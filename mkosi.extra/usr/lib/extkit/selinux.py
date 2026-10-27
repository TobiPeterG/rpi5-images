"""Label image entries using their final system paths."""

import os
import re
import shlex
import subprocess
from pathlib import Path

from . import process
from .errors import fail


def label_paths(tree, paths):
    """Use the active policy to label paths as though the image tree were /."""
    if not Path('/sys/fs/selinux/enforce').exists():
        return
    try:
        lines = Path('/etc/selinux/config').read_text().splitlines()
        settings = [line.split('=', 1)[1].strip() for line in lines
                    if line.strip().startswith('SELINUXTYPE=')]
        values = shlex.split(settings[-1]) if settings else []
        if len(values) != 1 or not re.fullmatch(r'[A-Za-z0-9_-]+', values[0]):
            fail('invalid or missing SELINUXTYPE in /etc/selinux/config')
        contexts = Path('/etc/selinux') / values[0] / 'contexts/files/file_contexts'
        tree = Path(tree).resolve()
        entries = [Path(path).absolute() for path in paths]
        if not entries:
            return
        if any(not path.is_relative_to(tree) for path in entries):
            fail('SELinux label path outside image tree')
        data = b''.join(os.fsencode(path) + b'\0' for path in entries)
        process.run(['setfiles', '-F', '-E', '-r', str(tree), '-0', '-s', str(contexts)],
                    input=data, check=True, capture_output=True)
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode(errors='replace').strip() if error.stderr else str(error)
        fail(f'cannot label extension image: {detail}')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        fail(f'cannot label extension image: {error}')
