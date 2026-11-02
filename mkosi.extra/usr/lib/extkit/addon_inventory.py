"""Filename parser and inventory for add-ons."""

from dataclasses import dataclass
from pathlib import Path

from . import validation
from .errors import fail


@dataclass(frozen=True)
class AddonEntry:
    path: Path
    name: str | None
    version: int | None
    error: str | None = None


def parse_filename(path):
    filename = Path(path).name
    if not filename.endswith('.addon.efi'):
        fail(f'invalid addon filename: {filename}')
    stem = filename.removesuffix('.addon.efi')
    if '_' not in stem:
        fail(f'invalid addon filename: {filename}')
    name, version = stem.rsplit('_', 1)
    validation.checked_name(name)
    return name, validation.positive_version(version)


def inventory(config):
    entries, seen = [], set()
    for path in sorted((config.state / 'store/addon').glob('*.addon.efi')):
        try:
            name, version = parse_filename(path)
            if not path.is_file():
                fail(f'addon is not a regular file: {path}')
            if (name, version) in seen:
                fail(f'ambiguous addon version {name} {version}: {path}')
            seen.add((name, version))
            entries.append(AddonEntry(path, name, version))
        except (OSError, ValueError) as error:
            entries.append(AddonEntry(path, None, None, str(error)))
    return entries


def versions(config, name):
    validation.checked_name(name)
    result = {}
    for entry in inventory(config):
        if entry.error and entry.path.name.startswith(name + '_'):
            fail(entry.error)
        if entry.name == name:
            result[entry.version] = entry.path
    return result


def selected(config, name, version=None):
    number = validation.positive_version(version) if version is not None else None
    available = versions(config, name)
    if number is None:
        number = max(available, default=None)
    if number not in available:
        fail('addon version not found')
    return available[number]
