"""Inspect sysupdate boot downloads and prepare authenticated phone requests."""

import configparser
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from . import metadata
from . import phone_client
from . import process
from . import validation
from .config import ExtkitConfig
from .config import load_phone_config
from .console import print
from .errors import ArtifactFormatError
from .errors import fail


VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*\Z")
MAX_MANIFEST = 8 * 1024 * 1024


def version_key(value):
    if not VERSION.fullmatch(value):
        raise ArtifactFormatError(f"unsupported OBS boot version: {value!r}")
    return tuple(int(part) for part in value.split("."))


def image_metadata(image):
    result = process.run(["mtype", "-i", str(image), "::/EXTKIT.VER"],
                            check=True, capture_output=True, text=True)
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def staged_images(directory, image_id):
    pattern = re.compile(re.escape(image_id) + r"_([0-9]+(?:\.[0-9]+)*)_([A-Za-z0-9-]+)\.boot\.img\Z")
    images = []
    for path in directory.glob("*.boot.img"):
        match = pattern.fullmatch(path.name)
        if match and path.is_file() and not path.is_symlink():
            images.append((match[1], path))
    return sorted(images, key=lambda item: version_key(item[0]), reverse=True)


def current_version(directory):
    image = directory / "boot.img"
    if not image.is_file():
        return None
    try:
        value = image_metadata(image).get("IMAGE_VERSION", "")
        return value if VERSION.fullmatch(value) else None
    except subprocess.CalledProcessError:
        return None


def show(directory, boot_directory, image_id, output=print):
    current = current_version(boot_directory)
    output(f"Boot image: active version {current or 'unknown'}")
    candidates = staged_images(directory, image_id)
    for version, path in candidates:
        if current is None or version_key(version) > version_key(current):
            output(f"  Update {version} staged by systemd-sysupdate. Awaiting phone authorization: {path.name}")
    if not candidates:
        output("  No factory boot images staged. Run systemd-sysupdate update to download an update set.")
    elif current is not None and not any(version_key(v) > version_key(current) for v, _ in candidates):
        output("  No newer staged boot image.")
    return candidates


def repository():
    result = process.run(["systemd-analyze", "cat-config", "sysupdate.d/80-boot.transfer"],
                            check=True, capture_output=True, text=True)
    config = configparser.ConfigParser(interpolation=None, strict=False)
    config.read_string(result.stdout)
    url = config.get("Source", "Path").strip().strip('"')
    if not url.startswith("https://") or any(c.isspace() for c in url) or "%" in url:
        raise ArtifactFormatError("80-boot.transfer requires a literal HTTPS repository URL")
    return url.rstrip("/") + "/"


def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        if not response.url.startswith("https://"):
            raise ArtifactFormatError("publisher proof redirected to an insecure URL")
        data = response.read(MAX_MANIFEST + 1)
    if len(data) > MAX_MANIFEST:
        raise ArtifactFormatError("publisher proof exceeds size limit")
    return data


def manifest_hash(manifest, filename):
    matches = []
    for line in manifest.decode("utf-8").splitlines():
        match = re.fullmatch(r"([a-fA-F0-9]{64}) [ *](.+)", line)
        if match and match[2].removeprefix("./") == filename:
            matches.append(match[1].lower())
    if len(matches) != 1:
        raise ArtifactFormatError("signed manifest must contain exactly one matching boot image")
    return matches[0]


def verify_manifest(manifest, signature, directory, keyrings=None):
    manifest_path = directory / "SHA256SUMS"
    signature_path = directory / "SHA256SUMS.gpg"
    manifest_path.write_bytes(manifest)
    signature_path.write_bytes(signature)
    if keyrings is None:
        keyrings = [path for path in (Path("/etc/systemd/import-pubring.gpg"),
                                     Path("/etc/systemd/import-pubring.pgp"),
                                     Path("/usr/lib/systemd/import-pubring.gpg"),
                                     Path("/usr/lib/systemd/import-pubring.pgp")) if path.is_file()]
    if not keyrings:
        raise ArtifactFormatError("no trusted systemd import GPG keyring found")
    arguments = ["gpg", "--batch", "--homedir", str(directory), "--no-default-keyring"]
    for keyring in keyrings:
        arguments.extend(["--keyring", str(keyring)])
    process.run([*arguments, "--verify", str(signature_path), str(manifest_path)], check=True)


def prepare(image, directory, url=None):
    """Carry signed checksum proof with the exact factory bytes for phone verification."""
    url = url or repository()
    manifest, signature = fetch(url + "SHA256SUMS"), fetch(url + "SHA256SUMS.gpg")
    verify_manifest(manifest, signature, directory)
    expected = manifest_hash(manifest, image.name)
    request = directory / (image.name + ".bootsign")
    # Hash the same bytes written to the request, so changes on writable STATE
    # cannot occur between verification and packaging.
    digest = hashlib.sha256()
    with zipfile.ZipFile(request, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("SHA256SUMS", manifest)
        archive.writestr("SHA256SUMS.gpg", signature)
        archive.writestr("request.json", json.dumps({"format": 1, "fileName": image.name, "repository": url}))
        with image.open("rb") as source, archive.open("boot.img", "w", force_zip64=True) as target:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                target.write(chunk)
    if digest.hexdigest() != expected:
        raise ArtifactFormatError("factory boot image does not match its OBS-signed checksum. Re-download with systemd-sysupdate")
    return request


def sign(directory, boot_directory, image_id, sender, version=None,
         output=print, confirm=None):
    if os.geteuid() != 0:
        raise ArtifactFormatError("boot-update requires root")
    candidates = show(directory, boot_directory, image_id, output)
    if version is not None:
        version_key(version)
        candidates = [item for item in candidates if item[0] == version]
    else:
        current = current_version(boot_directory)
        candidates = [item for item in candidates if current is None or version_key(item[0]) > version_key(current)]
    if not candidates:
        raise ArtifactFormatError("no matching staged boot update. Run systemd-sysupdate update first (or specify a staged version)")
    version, image = candidates[0]
    metadata = image_metadata(image)
    if metadata.get("IMAGE_VERSION") != version or metadata.get("IMAGE_ID") != image_id:
        raise ArtifactFormatError("staged image version/identity does not match its filename")
    if confirm is None or not confirm(f"Send factory boot version {version} to the phone for review and signing? [Y/n] "):
        output("Boot update left staged. Run extkit boot-update when ready to sign.")
        return
    # The payload is stored on STATE
    with tempfile.TemporaryDirectory(prefix="sign-", dir=directory) as work:
        output("Checking OBS publisher proof before sending…")
        request = prepare(image, Path(work))
        output("Sending authenticated factory image for phone review…")
        sender([request], kind="boot")
        output("✓ Signed boot files installed with versioned recovery copies. Reboot to activate the update.", color="green")


"""Boot updates operations."""


def boot_update_paths(config: ExtkitConfig):
    if config.boot_settings is None:
        fail("configure [BootUpdates] in extkit.conf")
    directory = config.boot_settings.staging_directory
    boot = load_phone_config(config.phone_configuration).boot_directory
    if not directory.is_absolute() or not boot.is_absolute():
        fail("boot update paths must be absolute")
    image_id = metadata.os_release(config).get("IMAGE_ID", "")
    if not validation.NAME_RE.fullmatch(image_id):
        fail("IMAGE_ID missing or invalid in /usr/lib/os-release")
    return directory, boot, image_id


def command_boot_update_check(config: ExtkitConfig, args):
    directory, boot, image_id = boot_update_paths(config)
    show(directory, boot, image_id, print)


def command_boot_update(config: ExtkitConfig, args):
    directory, boot, image_id = boot_update_paths(config)
    def confirm(prompt):
        if not sys.stdin.isatty():
            return False
        return input(prompt).strip().lower() in ("", "y", "yes")
    sign(directory, boot, image_id,
                               lambda inputs, **options: phone_client.send(config, inputs, **options),
         args.version, print, confirm)
