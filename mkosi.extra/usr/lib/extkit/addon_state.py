"""Per-name add-on activation intent."""
from dataclasses import dataclass
import json
from pathlib import Path
from . import filesystem, validation
from .errors import fail


@dataclass(frozen=True)
class ActivationSnapshot:
    generation: int
    active: tuple[int, int, int] | None


def _record(config, name):
    validation.checked_name(name)
    return config.state / 'addon-activation' / f'{name}.json'


def _snapshot(config, name, directory):
    record = _record(config, name)
    generation = 0
    if record.exists():
        try:
            generation = json.loads(record.read_text())['generation']
        except (ValueError, KeyError, TypeError) as error:
            fail(f'invalid addon activation record: {error}')
        if type(generation) is not int or generation < 0:
            fail('invalid addon activation generation')
    active = directory / f'{name}.addon.efi'
    try:
        info = active.lstat()
    except FileNotFoundError:
        stamp = None
    else:
        stamp = (info.st_ino, info.st_mtime_ns, info.st_size)
    return ActivationSnapshot(generation, stamp)


def capture(config, name, directory: Path) -> ActivationSnapshot:
    with filesystem.artifact_locks(config, [_record(config, name)]):
        return _snapshot(config, name, directory)


def apply(config, name, directory: Path, operation, *, expected=None) -> bool:
    with filesystem.artifact_locks(config, [_record(config, name)]):
        current = _snapshot(config, name, directory)
        if expected is not None and current != expected:
            return False
        filesystem.atomic_json(_record(config, name), {'generation': current.generation + 1})
        operation()
        return True
