"""Versioned artifact inventory, activation links and the atomic staging index."""

import json
import os
import re
import uuid
from datetime import datetime, timezone

from . import overlay
from . import validation
from .config import ExtkitConfig
from .errors import fail
from .filesystem import atomic_json
from .filesystem import locked_state


def selection_file(config: ExtkitConfig):
    return config.runtime_directory / 'extkit' / 'index.json'


def load_index(config: ExtkitConfig):
    path = selection_file(config)
    if not path.exists():
        return {'selected': [], 'deleted': [], 'generation': 0}
    try:
        value = json.loads(path.read_text())
    except (ValueError, UnicodeError) as error:
        fail(f'invalid staging index JSON: {error}')
    if (not isinstance(value, dict) or set(value) != {'selected', 'deleted', 'generation'}
            or type(value['generation']) is not int or value['generation'] < 0):
        fail('invalid staging index')
    for entries in (value['selected'], value['deleted']):
        if not isinstance(entries,list) or any(not isinstance(item,str) for item in entries):
            fail('invalid staging index paths')
    if set(value['selected']) & set(value['deleted']):
        fail('staging index contains conflicting operations')
    return {'selected': sorted(set(value['selected'])), 'deleted': sorted(set(value['deleted'])), 'generation': value['generation']}


def save_index(config: ExtkitConfig, selected, deleted):
    selected, deleted = set(selected), set(deleted)
    if selected & deleted:
        fail('cannot select and delete the same path')
    with locked_state(config.state):
        generation = load_index(config)['generation'] + 1
        atomic_json(selection_file(config), {'selected': sorted(selected), 'deleted': sorted(deleted), 'generation': generation})


def reserve_version(config: ExtkitConfig, name):
    """Caller holds the state lock."""
    directory = config.runtime_directory / 'extkit' / 'reservations'
    directory.mkdir(parents=True, exist_ok=True)
    versions = [number for kind in config.kinds for number in image_versions(config, kind, name)]
    for path in directory.glob(f'{name}_*.json'):
        match = re.fullmatch(re.escape(name) + r'_([0-9]+)_[0-9a-f]+\.json', path.name)
        if match:
            versions.append(int(match[1]))
    version = max(versions, default=0) + 1
    reservation = directory / f'{name}_{version}_{uuid.uuid4().hex}.json'
    atomic_json(reservation, {'name': name, 'version': version, 'pid': os.getpid()})
    return reservation, version


def release_reservation(config: ExtkitConfig, reservation):
    with locked_state(config.state):
        reservation.unlink(missing_ok=True)


def load_selection(config: ExtkitConfig):
    return load_index(config)['selected']


def load_deletions(config: ExtkitConfig):
    return load_index(config)['deleted']


def staged_paths(config: ExtkitConfig, kind=None):
    index = load_index(config)
    paths = set(index['selected']) | set(index['deleted'])
    return sorted(path for path in paths if kind is None or overlay.kind_for(config, overlay.relative_path(config, path)) == kind)


def save_selection(config: ExtkitConfig, paths):
    with locked_state(config.state):
        save_index(config, paths, load_deletions(config))


def save_deletions(config: ExtkitConfig, paths):
    with locked_state(config.state):
        save_index(config, load_selection(config), paths)


def activation_stamp(config: ExtkitConfig, kind, name):
    link = enabled_dir(config, kind) / (name + '.raw')
    if not link.is_symlink():
        return None
    info = link.lstat()
    return (info.st_ino, info.st_mtime_ns, os.readlink(link))


def store_dir(config: ExtkitConfig, kind):
    return config.state / "store" / kind


def enabled_dir(config: ExtkitConfig, kind):
    return config.enabled_dirs[kind]


def runtime_dir(config: ExtkitConfig, kind):
    return config.runtime_dirs[kind]


def image_versions(config: ExtkitConfig, kind, name):
    versions = {}
    directory = store_dir(config, kind)
    for image in directory.glob(f"{name}_*.raw") if directory.exists() else []:
        parsed = split_image_name(image)
        if parsed is None or parsed[0] != name:
            continue
        version = parsed[1]
        if not version.isdecimal() or int(version) < 1:
            fail(f"automatic versioning requires positive integer versions: {image}")
        versions[int(version)] = image
    return versions


def latest_image(config: ExtkitConfig, kind, name):
    versions = image_versions(config, kind, name)
    return versions[max(versions)] if versions else None


def requested_images(config: ExtkitConfig, name, version=None, kind=None):
    validation.checked_name(name)
    if version is not None:
        validation.checked_name(version)
    found = []
    for candidate_kind in (kind,) if kind else config.kinds:
        image = (store_dir(config, candidate_kind) / f"{name}_{version}.raw"
                 if version is not None else latest_image(config, candidate_kind, name))
        if image is not None and image.is_file():
            found.append((candidate_kind, image))
    if not found:
        suffix = f" version {version}" if version is not None else ""
        fail(f"no built images found for {name}{suffix}")
    return found


def stored_extension_states(config: ExtkitConfig, kind):
    states = []
    directory = store_dir(config, kind)
    for image in sorted(directory.glob("*.raw")) if directory.exists() else []:
        parsed = split_image_name(image)
        if parsed is None:
            continue
        name, _ = parsed
        link = enabled_dir(config, kind) / f"{name}.raw"
        selected = link.is_symlink() and link.resolve() == image.resolve()
        states.append((image, selected, link if selected else None))
    return states


def enabled_since(link):
    timestamp = link.lstat().st_mtime
    return datetime.fromtimestamp(timestamp, timezone.utc).astimezone().isoformat(timespec="seconds")


def split_image_name(image):
    stem = image.name.removesuffix(".raw")
    if "_" not in stem:
        return None
    return stem.split("_", 1)


def version_key(value):
    return tuple((0, int(part)) if part.isdigit() else (1, part.casefold())
                 for part in re.split(r"([0-9]+)", value))


def enable_image(config: ExtkitConfig, kind, name, image):
    link = enabled_dir(config, kind) / f"{name}.raw"
    link.parent.mkdir(parents=True, exist_ok=True)
    temporary = link.with_name(f".{link.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(image)
    temporary.replace(link)
    return link
