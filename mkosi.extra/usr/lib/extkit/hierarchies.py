"""Read the hierarchy assignments shared with systemd and interactive shells."""

import os
from pathlib import Path
import shlex

from .errors import ConfigurationError


KINDS = ('sysext', 'confext')


def load(path):
    values = {}
    for number, line in enumerate(Path(path).read_text().splitlines(), 1):
        fields = shlex.split(line, comments=True)
        if not fields:
            continue
        if len(fields) != 1 or '=' not in fields[0]:
            raise ConfigurationError(f'{path}:{number}: expected a literal KEY=VALUE assignment')
        key, value = fields[0].split('=', 1)
        if key in values:
            raise ConfigurationError(f'{path}:{number}: duplicate assignment: {key}')
        values[key] = value
    kinds, assigned = {}, set()
    for kind in KINDS:
        key = f'SYSTEMD_{kind.upper()}_HIERARCHIES'
        if not values.get(key):
            raise ConfigurationError(f'{path}: {key} must specify at least one hierarchy')
        prefixes = []
        for value in values[key].split(':'):
            prefix = Path(value)
            if not prefix.is_absolute() or '..' in prefix.parts or len(prefix.parts) != 2:
                raise ConfigurationError(f'{key}: hierarchies must be absolute top-level paths: {value!r}')
            name = prefix.parts[1]
            if name in assigned:
                raise ConfigurationError(f'hierarchy is assigned more than once: {value!r}')
            assigned.add(name)
            prefixes.append(name)
        kinds[kind] = tuple(prefixes)
    return kinds


def environment(config, source=None):
    result = dict(os.environ if source is None else source)
    for kind, prefixes in config.kinds.items():
        result[f'SYSTEMD_{kind.upper()}_HIERARCHIES'] = ':'.join('/' + prefix for prefix in prefixes)
    return result
