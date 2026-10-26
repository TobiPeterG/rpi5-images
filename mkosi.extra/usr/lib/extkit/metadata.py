"""Generate and inspect systemd extension compatibility metadata."""

import tempfile
from pathlib import Path

from . import images
from . import process
from . import store
from .config import ExtkitConfig
from .errors import fail


UPDATE_POLICIES = ("persistent", "current", "any")


def os_release(config: ExtkitConfig):
    return parse_release_text((config.root / 'usr/lib/os-release').read_text())


def release_metadata(config: ExtkitConfig, tree, name, kind, version, updates):
    release = os_release(config)
    level = "SYSEXT_LEVEL" if kind == "sysext" else "CONFEXT_LEVEL"
    if updates == "any":
        metadata = ["ID=_any"]
    elif updates == "persistent":
        if not release.get(level):
            fail(f"{level} is required for persistent {kind} images")
        metadata = [f"ID={release['ID']}", f"{level}={release[level]}"]
    else:
        if not release.get("VERSION_ID"):
            fail(f"VERSION_ID is required for current-system {kind} images")
        metadata = [f"ID={release['ID']}", f"VERSION_ID={release['VERSION_ID']}"]
    metadata += [
        f"IMAGE_ID={name}",
        f"IMAGE_VERSION={version}",
    ]
    location = "usr/lib" if kind == "sysext" else "etc"
    destination = tree / location / "extension-release.d" / f"extension-release.{name}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(metadata) + "\n")


def parse_release_text(text):
    values = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values


def embedded_update_policy(config: ExtkitConfig, kind, image):
    parsed = store.split_image_name(image)
    if parsed is None:
        fail(f"invalid extension image name: {image}")
    name, _ = parsed
    location = "usr/lib" if kind == "sysext" else "etc"
    metadata = parse_release_text(read_image_metadata(config,
        image, f"{location}/extension-release.d/extension-release.{name}"))
    level = "SYSEXT_LEVEL" if kind == "sysext" else "CONFEXT_LEVEL"
    if metadata.get("ID") == "_any":
        updates = "any"
    elif level in metadata:
        updates = "persistent"
    elif "VERSION_ID" in metadata:
        updates = "current"
    else:
        fail(f"extension has no systemd compatibility policy: {image}")
    return updates, metadata.get("VERSION_ID")


def read_image_metadata(config: ExtkitConfig, image, relative):
    """Extract release metadata"""
    partitions = images.gpt_partitions(image)
    if not partitions or "extkit-root" not in partitions:
        fail("expected an ExtKit GPT extension image")
    work = config.state / "work"
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="extkit-metadata-", dir=work) as directory:
        metadata = Path(directory) / "release"
        process.run([
            config.erofs_fsck_tool, f"--offset={partitions['extkit-root']['offset']}",
            f"--path=/{relative}", f"--extract={metadata}", "--no-preserve", str(image),
        ], check=True, capture_output=True, text=True)
        if metadata.is_symlink() or not metadata.is_file():
            fail("extension release metadata must be a regular file")
        with metadata.open("rb") as stream:
            data = stream.read(64 * 1024 + 1)
        if len(data) > 64 * 1024:
            fail("extension release metadata exceeds 64 KiB")
        return data.decode("utf-8")


def policy_description(updates, version_id=None):
    if updates == "persistent":
        return "persistent (systemd level compatibility)"
    if updates == "any":
        return "any system (ID=_any)"
    return f"current VERSION_ID {version_id or 'unknown'}"
