"""Phone discovery, enrollment and user-authorized signing workflows."""

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from . import discovery
from . import pairing
from . import phone as transfers
from . import process
from . import protocol
from .config import PhoneConfig
from .console import print, terminal_text
from .errors import ExtkitError, TransferError, RequestRejected, BatchSigningError
from .errors import transfer_fail as fail
from .trust import enrolled_certificates
from .models import SigningOutcome, FinalizeArtifact


def command_discover(config: PhoneConfig):
    phones, errors = discovery.find_phones(config)
    for phone in phones:
        trust = "Secure Boot db" if phone.enrolled else "not enrolled"
        print(f"{terminal_text(phone.service.name)}\t{terminal_text(phone.service.address)}:{phone.service.port}\t{trust}\t{phone.extension_fingerprint}")
    for error in errors:
        print(f"ignored: {terminal_text(error)}", file=sys.stderr, color="yellow")
    return 0 if phones else 1


def has_enrolled_user_key(config: PhoneConfig):
    return bool(enrolled_certificates(config.db_glob, config.extension_owner))


def enrollment_instructions(config: PhoneConfig):
    image = config.boot_directory / "boot.img"
    return (
        "No ExtKit user signing key is enrolled in the live Secure Boot db.\n"
        "On your phone, open ExtSigner's 'Connect your Raspberry Pi' page.\n"
        "From 'Trusted signing': Settings gear → Connection setup.\n"
        "On 'Connect your Raspberry Pi', tap 'Start secure receiver'.\n"
        "Connect both devices to the same local network, then run as root:\n"
        f"  extkit-phone send {image} --kind boot\n"
        "Scan the pairing QR displayed here with ExtSigner to allow this sending session, then review and approve signing.\n"
        "Then reboot the Pi and run: extkit-phone check-enrollment\n"
        "If you already personalized boot.img, reboot to load its key.\n"
        "This procedure does not write OTP or change EEPROM configuration."
    )


def command_check_enrollment(config: PhoneConfig, quiet=False):
    if has_enrolled_user_key(config):
        if not quiet:
            print("ExtKit user signing key is enrolled in the live Secure Boot db.", color="green")
        return 0
    if not quiet:
        print(enrollment_instructions(config), file=sys.stderr, color="yellow")
    return 1


def record_pending_enrollment(phone):
    directory = protocol.PENDING_ENROLLMENT.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_uid != os.geteuid():
        fail("unsafe pending-enrollment directory")
    if directory.stat().st_mode & 0o077:
        fail("pending-enrollment directory must be private")
    with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", dir=directory,
                                     prefix=".pending-", delete=False) as temporary:
        temporary.write(phone.extension_fingerprint + "\n")
        temporary_path = Path(temporary.name)
    try:
        temporary_path.replace(protocol.PENDING_ENROLLMENT)
    finally:
        temporary_path.unlink(missing_ok=True)


def pending_key_needs_reboot(config: PhoneConfig):
    try:
        fingerprint = protocol.PENDING_ENROLLMENT.read_text("ascii").strip()
    except (OSError, UnicodeError):
        return False
    if len(fingerprint) != 64 or any(char not in "0123456789abcdef" for char in fingerprint):
        return False
    live = {hashlib.sha256(cert).hexdigest() for cert in
            enrolled_certificates(config.db_glob, config.extension_owner)}
    return fingerprint not in live


def command_setup(config: PhoneConfig):
    if pending_key_needs_reboot(config):
        print("Signed boot files were installed during this boot, but the phone's key "
              "is not in the live Secure Boot db yet. Reboot to activate the key. "
              "Pairing does not need to be repeated.", color="yellow")
        return 0
    if has_enrolled_user_key(config):
        print("Phone signing is already provisioned: an ExtKit user key is active "
              "in the live Secure Boot db. Skipping pairing.", color="green")
        return 0
    print("\nSet up your phone as an extension signer\n")
    print("On your phone, open ExtSigner's 'Connect your Raspberry Pi' page.\n"
          "From 'Trusted signing': Settings gear → Connection setup.\n"
          "On 'Connect your Raspberry Pi', tap 'Start secure receiver'.\n"
          "Connect both devices to the same local network. This wizard will find\n"
          "your phone, send boot.img for review, and install the signed files.\n"
          "Scan the pairing QR displayed here with ExtSigner to allow this sending session, then review and approve signing.\n"
          "Reboot after firstboot finishes to activate the phone's signing key.\n"
          "This procedure does not write OTP or change EEPROM configuration.")
    while True:
        answer = input("\nSet up phone signing now? [Y/n] ").strip().lower()
        if answer not in {"", "y", "yes"}:
            print("Skipped. Extensions signed by this phone will not be trusted at boot "
                  "until enrollment and reboot.", color="yellow")
            return 0
        try:
            process.run(["systemctl", "start", "avahi-daemon.service"], check=True)
            outcomes = send(config, [config.boot_directory / "boot.img"], kind="boot")
            retry_receipts(config, outcomes)
            if any(not outcome.artifact.complete for outcome in outcomes):
                print('Signed files were retained, but installation needs attention. Check the reported '
                      'error before rebooting. Do not repeat pairing.', file=sys.stderr, color='yellow')
                return 1
        except RequestRejected:
            print("Phone setup was dismissed. Run extkit-phone setup when you are ready to try again.", color="yellow")
            return 0
        except (ExtkitError, OSError, subprocess.SubprocessError) as error:
            print(f"Phone setup did not complete: {terminal_text(error)}", file=sys.stderr, color="red")
            continue
        print("\nSigned boot files installed. Reboot after firstboot finishes to load "
              "your signing key and allow its extensions to pass boot-time verification.", color="green")
        return 0


def send(config: PhoneConfig, inputs, *, kind="auto", output=None,
         finalize: FinalizeArtifact | None = None) -> list[SigningOutcome]:
    inputs = list(map(Path, inputs))
    if not inputs:
        fail("at least one signing request is required")
    if len(inputs) > 1:
        if output is not None or kind not in ('auto', 'extension') or any(path.suffix != '.extsign' for path in inputs):
            fail('batch sending accepts only .extsign extension requests and no --output')
        identities = [path.resolve() for path in inputs]
        if len(set(identities)) != len(inputs):
            fail('batch contains duplicate request paths')
        kind = 'extension'
    elif kind == 'auto':
        kind = 'addon' if inputs[0].suffix == '.addonsign' else 'extension' if inputs[0].suffix == '.extsign' else 'boot'
    for source in inputs:
        transfers.validate_request(source, kind, output, config)
    phones, errors = discovery.find_phones(config)
    enrolled = [phone for phone in phones if phone.enrolled]
    if enrolled:
        phone = discovery.choose_phone(enrolled, "Multiple phones have keys enrolled in Secure Boot:")
        authorized = pairing.session(phone, config)
        print(f"Authenticated {terminal_text(phone.service.name)} through the live Secure Boot db.", color="green")
    else:
        if has_enrolled_user_key(config):
            fail("No phone matching the live Secure Boot signing authority is available. "
                 "Start its receiver and check your network.")
        for error in errors:
            print(f"ignored: {terminal_text(error)}", file=sys.stderr, color="yellow")
        phone = discovery.choose_phone(phones, "No discovered phone is enrolled. Select one for initial pairing:", always_list=True)
        authorized = pairing.pair(phone, config)
    if len(inputs) > 1:
        print(f"Sending {len(inputs)} extension requests using one authenticated phone session.", flush=True)
        options = {'finalize': finalize} if finalize is not None else {}
        try:
            return transfers.send_batch(authorized, inputs, config, **options)
        except BatchSigningError as error:
            error.outcomes = tuple(retry_receipts(config, list(error.outcomes)))
            raise
    source = inputs[0]
    while True:
        try:
            options = {'finalize': finalize} if finalize is not None else {}
            outcome = transfers.send_request(authorized, source, kind, output, config, **options)
            break
        except RequestRejected as error:
            print(f"✗ The phone dismissed the request: {terminal_text(error)}", file=sys.stderr, color="red")
            if not sys.stdin.isatty() or input("Send the request again? [y/N] ").strip().lower() not in {"y", "yes"}:
                raise
    if kind == "boot" and outcome.artifact.installed:
        try:
            record_pending_enrollment(phone)
        except (OSError, TransferError) as error:
            print(f"Could not save the reboot reminder: {terminal_text(error)}. "
                  "Reboot to activate the installed signing key.", file=sys.stderr, color="yellow")
    return [outcome]


def retry_receipts(config: PhoneConfig, outcomes: list[SigningOutcome]) -> list[SigningOutcome]:
    """Interactive retry for phone receipts."""
    results = []
    for outcome in outcomes:
        while not outcome.receipt_delivered and sys.stdin.isatty():
            try:
                answer = input('Artifact published. Retry the phone receipt? [y/N] ').strip().lower()
            except EOFError:
                break
            if answer not in ('y', 'yes'):
                break
            outcome = transfers.retry_receipt(outcome, config)
        results.append(outcome)
    return results
