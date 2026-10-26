"""Addon commands operations"""

import os
import re
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path

from . import addons
from . import addon_state
from . import filesystem
from . import phone_client
from . import signing
from . import validation
from .config import ExtkitConfig
from .console import print
from .errors import PublicationError, fail
from .models import ArtifactResult, Activation
from .trust import enrolled_certificates


def addon_versions(config: ExtkitConfig, name):
    validation.checked_name(name)
    directory = config.state / "store/addon"
    pattern = re.compile(re.escape(name) + r"_([1-9][0-9]*)\.addon\.efi\Z")
    return {int(match[1]): path for path in directory.glob(f"{name}_*.addon.efi")
            if (match := pattern.fullmatch(path.name))}


def selected_addon(config: ExtkitConfig, args):
    versions = addon_versions(config, args.name)
    version = int(args.version) if getattr(args, "version", None) else max(versions, default=0)
    if version not in versions:
        fail("addon version not found")
    return versions[version]


def addon_boot_directory(config: ExtkitConfig):
    directory = config.addon_settings.boot_directory
    if not directory.is_absolute():
        fail("addon BootDirectory must be absolute")
    directory.stat()  # Trigger the ESP automount.
    if not os.path.ismount(directory):
        fail(f"ESP is not mounted at {directory}")
    return directory / "loader/addons"


def addon_certificates(config: ExtkitConfig):
    return enrolled_certificates(config.addon_settings.db_glob)


def sign_addon(config: ExtkitConfig, image, enable=True):
    """Per-artifact signing plus short, conditional per-name activation."""
    with filesystem.artifact_locks(config, [image]):
        name, version = image.name.removesuffix('.addon.efi').rsplit('_', 1)
        destination = addon_boot_directory(config) if enable else None
        expected = addon_state.capture(config, name, destination) if destination is not None else None

        def activate():
            if not addons.verify(image, addon_certificates(config)):
                print('WARNING: Signed addon retained, but its key is not trusted by the live Secure Boot db. '
                      'Enroll the phone key and reboot, then run extkit addon enable ' + name, color='yellow')
                return Activation.DEFERRED if enable else Activation.NONE
            if destination is None:
                return Activation.NONE
            changed = addon_state.apply(config, name, destination,
                lambda: addons.install(image, destination, name, addon_certificates(config)), expected=expected)
            if changed:
                print(f'Enabled addon for next boot: {destination / (name + ".addon.efi")}', color='green')
                return Activation.ENABLED
            print('WARNING: Addon activation changed while signing. Keeping the current selection. '
                  'The signed version is stored but was not auto-enabled.', color='yellow')
            return Activation.DEFERRED

        if addons.inspect(image.read_bytes())[2]:
            activate()
            return []
        work = config.state / 'work'
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='addon-sign-', dir=work) as directory:
            original = filesystem.file_sha256(image)
            snapshot = Path(directory) / image.name
            filesystem.atomic_copy(image, snapshot)
            payload = snapshot.with_suffix('.addonsign')
            addons.request(snapshot, payload, name, version)
            signed = Path(directory) / 'signed.addon.efi'

            def finalize(result: ArtifactResult) -> ArtifactResult:
                if filesystem.file_sha256(image) != original:
                    fail('addon changed while awaiting phone review')
                if filesystem.file_sha256(result.image) != result.image_sha256:
                    fail('verified addon changed before final publication')
                try:
                    filesystem.publish_file(result.image, image)
                except PublicationError as error:
                    return replace(result, image=image, installed=True, durability_error=str(error))
                result = replace(result, image=image, installed=True, durability_error=None)
                try:
                    activation = activate()
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    return replace(result, activation=Activation.FAILED, activation_error=str(error))
                return replace(result, activation=activation)

            return phone_client.send(config, [payload], kind='addon', output=signed, finalize=finalize)


def build_addon(config: ExtkitConfig, args):
    validation.checked_name(args.name)
    if len(args.name) > 128:
        fail('addon name must not exceed 128 characters')
    command_line = args.cmdline
    if args.machine_id is not None:
        identity = ((config.root / 'etc/machine-id').read_text().strip()
                    if args.machine_id == 'current' else args.machine_id)
        if not re.fullmatch(r'[0-9a-f]{32}', identity) or identity == '0' * 32:
            fail('machine ID must be 32 lowercase hexadecimal digits and nonzero')
        command_line = 'systemd.machine_id=' + identity
    architecture = args.architecture or config.addon_settings.architecture
    if architecture is None:
        architecture = {'aarch64': 'arm64', 'x86_64': 'x86-64'}.get(os.uname().machine)
    data = addons.build(command_line, architecture)
    with filesystem.locked_state(config.state):
        version = max(addon_versions(config, args.name), default=0) + 1
        directory = config.state / 'store/addon'
        directory.mkdir(parents=True, exist_ok=True)
        image = directory / f'{args.name}_{version}.addon.efi'
        with filesystem.atomic_output(image) as stream:
            stream.write(data)
    addons.request(image, image.with_name(f'{args.name}_{version}.addonsign'), args.name, version)
    print(f'Built unsigned addon: {image}\nCommand line: {command_line}', color='green')
    if args.no_sign:
        print(f'WARNING: Not usable until signed. Run extkit addon sign {args.name} {version}.', color='yellow')
    elif input('Sign on the phone and install for next boot now? [Y/n] ').strip().lower() in ('', 'y', 'yes'):
        signing.warn_if_signing_key_unenrolled(config)
        sign_addon(config, image)


def sign_selected_addon(config: ExtkitConfig, args):
    signing.warn_if_signing_key_unenrolled(config)
    sign_addon(config, selected_addon(config, args), enable=not args.no_enable)


def enable_addon(config: ExtkitConfig, args):
    image = selected_addon(config, args)
    with filesystem.artifact_locks(config, [image]):
        directory = addon_boot_directory(config)
        addon_state.apply(config, args.name, directory,
            lambda: addons.install(image, directory, args.name, addon_certificates(config)))
    print(f'Enabled addon for next boot: {directory / (args.name + ".addon.efi")}', color='green')


def disable_addon(config: ExtkitConfig, args):
    validation.checked_name(args.name)
    directory = addon_boot_directory(config)
    def remove():
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f'{args.name}.addon.efi'
        path.unlink(missing_ok=True)
        filesystem.fsync_directory(path.parent)
    addon_state.apply(config, args.name, directory, remove)
    print(f'Disabled addon for next boot: {args.name}', color='green')


def inspect_addon(config: ExtkitConfig, args):
    image = selected_addon(config, args)
    command_line, architecture, signed = addons.inspect(image.read_bytes())
    print(f"{image.name}: {architecture}. Signature: {'signed' if signed else 'unsigned'}\n{command_line}")


def command_addon(config: ExtkitConfig, args):
    handlers = {'build': build_addon, 'sign': sign_selected_addon, 'enable': enable_addon,
                'disable': disable_addon, 'inspect': inspect_addon,
                'list': lambda config, args: print_addon_status(config)}
    return handlers[args.action](config, args)


def print_addon_status(config: ExtkitConfig, indent=""):
    images = sorted((config.state / "store/addon").glob("*.addon.efi"))
    if not images:
        print(f"{indent}none")
        return
    certificates = addon_certificates(config)
    for image in images:
        try:
            command_line, architecture, signed = addons.inspect(image.read_bytes())
            trusted = addons.verify(image, certificates) if signed else False
            name = image.name.removesuffix(".addon.efi").rsplit("_", 1)[0]
            active = config.addon_settings.boot_directory / "loader/addons" / f"{name}.addon.efi"
            enabled = active.is_file() and active.read_bytes() == image.read_bytes()
            print(f"{indent}{image.name}: {architecture}. Signature: {'signed' if signed else 'unsigned'}. "
                  f"trust: {'trusted' if trusted else 'not trusted'}. "
                  f"{'enabled for boot' if enabled else 'disabled'}\n{indent}  {command_line}")
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            print(f"{indent}{image.name}: cannot inspect: {error}", color="yellow")
