"""Synchronize enabled artifact links with systemd runtime discovery."""

from . import quarantine
from . import store
from .config import ExtkitConfig
from .errors import fail
from .filesystem import state_transaction


@state_transaction
def command_sync(config: ExtkitConfig, args):
    """Synchronize enabled images into systemd's runtime discovery directory."""
    kind = args.kind
    destination = store.runtime_dir(config, kind)
    if destination.is_symlink():
        destination.unlink()
    destination.mkdir(parents=True, exist_ok=True)
    for entry in destination.iterdir():
        if getattr(args, "boot", False) and entry.is_dir():
            quarantine.quarantine_extension(config, entry, kind, "unmanaged directory extension")
            continue
        if getattr(args, "boot", False) and entry.is_file() and not entry.is_symlink():
            # Leave raw runtime images available for the boot checker
            continue
        if entry.is_symlink() or entry.is_file():
            entry.unlink()
        elif entry.is_dir():
            fail(f"runtime extension directory contains unmanaged directory: {entry}")
    source = store.enabled_dir(config, kind)
    if getattr(args, "boot", False) and source.is_dir():
        for entry in source.iterdir():
            if entry.is_dir():
                quarantine.quarantine_extension(config, entry, kind, "directory/subvolume extension")
    for link in sorted(source.glob("*.raw")) if source.exists() else []:
        if not link.is_symlink() or not link.resolve().is_relative_to(store.store_dir(config, kind)):
            continue
        image = link.resolve()
        if not image.is_file():
            if getattr(args, "boot", False):
                quarantine.quarantine_extension(config, link, kind, "missing or non-regular image target")
            continue
        runtime = destination / link.name
        if not runtime.exists() and not runtime.is_symlink():
            runtime.symlink_to(link)
