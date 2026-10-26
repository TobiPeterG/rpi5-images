"""Discovery paths and quarantine storage."""

import json
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import filesystem, store
from .console import print
from .errors import fail


def extension_search_directories(config):
    paths = {
        "sysext": ("etc/extensions", "run/extensions", "var/lib/extensions"),
        "confext": ("run/confexts", "var/lib/confexts", "usr/local/lib/confexts", "usr/lib/confexts"),
    }
    return {kind: {config.root / relative for relative in paths[kind]} |
            {store.enabled_dir(config, kind), store.runtime_dir(config, kind)} for kind in config.kinds}


def quarantine_extension(config, path, kind, reason):
    """Move discovery entries out of service search paths."""
    path = Path(path)
    target = path.resolve()
    candidates = {path: kind}
    # Disable all aliases of this image, not just the name returned by discovery.
    for other_kind, directories in extension_search_directories(config).items():
        for directory in directories:
            if directory.is_dir():
                for entry in directory.iterdir():
                    if entry.is_symlink() and entry.resolve() == target:
                        candidates[entry] = other_kind
    root = config.state / "quarantine"
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink() or not root.resolve().is_relative_to(config.state.resolve()):
        fail("quarantine must be inside StateDirectory, not a symlink")
    for entry, entry_kind in sorted(candidates.items()):
        if not entry.exists() and not entry.is_symlink():
            continue
        slot = root / uuid.uuid4().hex
        slot.mkdir(mode=0o700)
        record = {"kind": entry_kind, "name": entry.name, "original": str(entry),
                  "target": str(target), "reason": str(reason)[:4096],
                  "time": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        (slot / "record.json").write_bytes(filesystem.json_bytes(record))
        try:
            # shutil.move preserves symlinks instead of following them.
            shutil.move(str(entry), str(slot / "entry"))
        except OSError as error:
            fail(f"cannot quarantine {entry}. Refusing extension merge: {error}")
        print(f"WARNING: Quarantined {entry}: {reason}", file=sys.stderr, color="yellow")


def print_quarantine(config, kind=None):
    root = config.state / "quarantine"
    records = []
    for slot in sorted(root.iterdir()) if root.is_dir() and not root.is_symlink() else []:
        if not slot.is_dir() or slot.is_symlink():
            continue
        try:
            record = json.loads((slot / "record.json").read_text())
            if kind is None or record.get("kind") == kind:
                records.append((slot, record))
        except (OSError, ValueError):
            print(f"  quarantine: unreadable record at {slot}", color="yellow")
    print("  quarantine:" if records else "  quarantine: none")
    for slot, record in records:
        print(f"    {record['kind']}/{record['name']}: {record['reason']}\n"
              f"      since {record['time']}. original: {record['original']}. saved: {slot / 'entry'}")
