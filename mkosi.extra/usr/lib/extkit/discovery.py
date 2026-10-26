"""Discovery operations."""

import base64
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import process
from . import protocol
from . import transport as tls_transport
from .console import print, terminal_text
from .crypto import certificate_public_key, checked
from .errors import VerificationError
from .errors import transfer_fail as fail
from .phone_models import Service, Phone
from .trust import enrolled_certificates


def discover_services(service_type):
    command = ["avahi-browse", "--resolve", "--terminate", "--parsable", service_type]
    try:
        result = process.run(command, check=False, text=True, capture_output=True, timeout=15)
    except FileNotFoundError:
        fail("avahi-browse is missing. Install avahi-utils")
    except subprocess.TimeoutExpired:
        fail("local-network discovery timed out")
    if result.returncode != 0:
        fail((result.stderr or "avahi-browse failed").strip())
    found = {}
    for line in result.stdout.splitlines():
        fields = line.split(";")
        if len(fields) < 9 or fields[0] != "=":
            continue
        try:
            service = Service(unescape_avahi(fields[3]), unescape_avahi(fields[7]), int(fields[8]))
        except (ValueError, IndexError):
            continue
        found[(service.address, service.port)] = service
    return sorted(found.values(), key=lambda item: (item.name, item.address, item.port))


def unescape_avahi(value):
    output = bytearray()
    index = 0
    encoded = value.encode("utf-8")
    while index < len(encoded):
        if encoded[index:index + 1] == b"\\" and encoded[index + 1:index + 4].isdigit():
            output.append(int(encoded[index + 1:index + 4]))
            index += 4
        elif encoded[index:index + 2] == b"\\;":
            output.append(ord(";"))
            index += 2
        else:
            output.append(encoded[index])
            index += 1
    return output.decode("utf-8", errors="replace")


def binding_payload(transport_fingerprint):
    return protocol.BINDING_DOMAIN + transport_fingerprint.lower().encode("ascii") + b"\n"


def verify_rsa_signature(certificate, signature, payload):
    if not shutil.which("openssl"):
        fail("openssl is required to verify the phone identity")
    with tempfile.TemporaryDirectory(prefix="extkit-phone-") as directory:
        signature_file = Path(directory, 'signature.bin')
        payload_file = Path(directory, 'payload.bin')
        signature_file.write_bytes(signature)
        payload_file.write_bytes(payload)
        try:
            public_file = certificate_public_key(Path(directory), certificate)
            checked(['openssl', 'dgst', '-sha256', '-verify', str(public_file),
                     '-signature', str(signature_file), str(payload_file)], check=True, capture_output=True)
        except VerificationError as error:
            fail(f'the extension key did not authenticate the phone transport identity: {error}')


def inspect_phone(service, enrolled_fingerprints, timeout):
    response, _, peer = tls_transport.exchange(service, {"op": "info"}, timeout=timeout)
    info = protocol.object_field(response, "info")
    transport = base64.b64decode(protocol.text_field(info, "transportCertificate"), validate=True)
    extension = base64.b64decode(protocol.text_field(info, "extensionCertificate"), validate=True)
    signature = base64.b64decode(protocol.text_field(info, "bindingSignature"), validate=True)
    if transport != peer:
        fail(f"{service.name}: TLS certificate differs from the advertised binding")
    transport_fingerprint = hashlib.sha256(transport).hexdigest()
    if transport_fingerprint != info["transportFingerprint"].lower():
        fail(f"{service.name}: transport certificate fingerprint mismatch")
    verify_rsa_signature(extension, signature, binding_payload(transport_fingerprint))
    extension_fingerprint = hashlib.sha256(extension).hexdigest()
    return Phone(service, transport, extension, base64.b64decode(protocol.text_field(info, "bootCertificate"), validate=True),
                 extension_fingerprint, extension_fingerprint in enrolled_fingerprints)


def find_phones(config):
    enrolled = {hashlib.sha256(item).hexdigest() for item in enrolled_certificates(config.db_glob, config.extension_owner)}
    phones = []
    errors = []
    for service in discover_services(config.service_type):
        try:
            phones.append(inspect_phone(service, enrolled, config.connect_timeout))
        except Exception as error:
            errors.append(f"{service.name}: {error}")
    return phones, errors


def choose_phone(phones, heading, always_list=False):
    if not phones:
        fail("no compatible ExtKit signer is visible on the local network")
    if len(phones) == 1 and not always_list:
        return phones[0]
    print(heading)
    for index, phone in enumerate(phones, 1):
        print(f"  {index}. {terminal_text(phone.service.name)} ({terminal_text(phone.service.address)}) {phone.extension_fingerprint[:16]}…")
    while True:
        try:
            selected = int(input(f"Enter the phone number (1–{len(phones)}): "))
            if not 1 <= selected <= len(phones):
                raise ValueError
            return phones[selected - 1]
        except (ValueError, IndexError):
            print("Enter one of the listed numbers.", file=sys.stderr, color="yellow")
