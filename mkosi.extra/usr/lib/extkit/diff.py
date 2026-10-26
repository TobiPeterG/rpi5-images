"""Structured filesystem comparison."""

import difflib
import hashlib
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from . import overlay
from .config import ExtkitConfig
from .console import print


TEXT_LIMIT = 1024 * 1024


@dataclass(frozen=True)
class FileSnapshot:
    kind: str
    mode: int
    uid: int
    gid: int
    target: str | None
    xattrs: tuple[tuple[str, bytes], ...]
    size: int
    digest: str | None


@dataclass(frozen=True)
class FileChange:
    path: str
    before: FileSnapshot | None
    after: FileSnapshot | None


def snapshot(path):
    if path is None:
        return None
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode):
        kind = 'link'
    elif stat.S_ISREG(info.st_mode):
        kind = 'file'
    elif stat.S_ISDIR(info.st_mode):
        kind = 'directory'
    elif stat.S_ISCHR(info.st_mode) and info.st_rdev == 0:
        kind = 'whiteout'
    else:
        kind = 'special'
    attrs = tuple(sorted((name, os.getxattr(path, name, follow_symlinks=False))
                         for name in os.listxattr(path, follow_symlinks=False)))
    digest = None
    if kind == 'file':
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return FileSnapshot(kind, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid,
                        os.readlink(path) if kind == 'link' else None, attrs,
                        info.st_size if kind == 'file' else 0, digest)


def compare_file(relative, before, after):
    left, right = snapshot(before), snapshot(after)
    return None if left == right else FileChange(relative, left, right)


def image_entries(tree):
    """Include directories and leaves without traversing symlinks."""
    result = {}
    for root, names, files in os.walk(tree, followlinks=False):
        for name in names + files:
            path = Path(root) / name
            result[str(path.relative_to(tree))] = path
    return result


def content_lines(path):
    # Hex streaming preserves every byte when a unified text diff would exceed
    # the bounded text budget or require replacement decoding.
    with Path(path).open('rb') as stream:
        offset = 0
        while chunk := stream.read(32):
            yield f'{offset:016x}  {chunk.hex(" ")}\n'
            offset += len(chunk)


def show_content(path, output=None):
    output = sys.stdout if output is None else output
    output.writelines(content_lines(path))


def render(change, old, new, old_label, new_label, content_command="extkit diff --content"):
    path, left, right = change.path, change.before, change.after
    if left is None:
        print(f'ADDED /{path}')
    elif right is None:
        print(f'REMOVED /{path}')
    elif left.kind != right.kind:
        print(f'TYPE CHANGED /{path}: {left.kind} -> {right.kind}')
    for field in ('mode', 'uid', 'gid', 'target', 'xattrs'):
        a, b = getattr(left, field, None), getattr(right, field, None)
        if a != b:
            if field == 'mode':
                a, b = (oct(value) if value is not None else None for value in (a, b))
            print(f'{field.upper()} /{path}: {old_label}={a!r} -> {new_label}={b!r}')
    left_file = left is not None and left.kind == 'file'
    right_file = right is not None and right.kind == 'file'
    if not left_file and not right_file:
        return
    if left_file and right_file and left.digest == right.digest:
        return
    sizes = (left.size if left_file else 0, right.size if right_file else 0)
    hashes = (left.digest if left_file else None, right.digest if right_file else None)
    if max(sizes) > TEXT_LIMIT:
        print(f'CONTENT CHANGED /{path}: {sizes[0]} -> {sizes[1]} bytes')
        print(f'  SHA256: {hashes[0]} -> {hashes[1]}')
        print(f'  Full bytes: {content_command}.')
        return
    a = Path(old).read_bytes() if left_file else b''
    b = Path(new).read_bytes() if right_file else b''
    try:
        if b"\0" in a or b"\0" in b:
            raise UnicodeError()
        before = a.decode('utf-8').splitlines(keepends=True)
        after = b.decode('utf-8').splitlines(keepends=True)
    except UnicodeError:
        print(f'BINARY CHANGED /{path}: {sizes[0]} -> {sizes[1]} bytes')
        print(f'  SHA256: {hashes[0]} -> {hashes[1]}')
        print(f'  Full bytes: {content_command}.')
    else:
        sys.stdout.writelines(difflib.unified_diff(
            before, after, fromfile=f'{old_label}/{path}', tofile=f'{new_label}/{path}'))


def show_diff(config: ExtkitConfig, base, relative, content=False):
    old = base / relative
    try:
        new = overlay.live_file(config, relative)
    except ValueError:
        if overlay.is_whiteout(config, relative) and (old.exists() or old.is_symlink()):
            print(f'DELETED /{relative}')
            new = config.root / relative
            if new.exists() or new.is_symlink():
                raise
        else:
            raise
    if content:
        for label, path in (('base', old), ('live', new)):
            if path.is_file() and not path.is_symlink():
                print(f'{label}/{relative}: complete hexadecimal content')
                show_content(path)
        return
    change = compare_file(str(relative), old, new)
    if change is None:
        print(f'UNCHANGED /{relative}')
    else:
        render(change, old, new, 'base', 'live', f'extkit diff --content /{relative}')


def show_image_difference(old_tree, new_tree, old_label, new_label, content=False, content_command=None):
    old, new = image_entries(old_tree), image_entries(new_tree)
    for relative in sorted(set(old) | set(new)):
        # A missing inventory entry is absent, not a path to probe through a
        # parent which the other image may have replaced with a symlink.
        a, b = old.get(relative), new.get(relative)
        change = compare_file(relative, a, b)
        if change is None:
            continue
        render(change, a, b, old_label, new_label,
               content_command or 'extkit compare NAME OLD_VERSION NEW_VERSION --content')
        if content:
            for label, path, entry in ((old_label, a, change.before), (new_label, b, change.after)):
                if entry is not None and entry.kind == 'file':
                    print(f'{label}/{relative}: complete hexadecimal content')
                    show_content(path)
