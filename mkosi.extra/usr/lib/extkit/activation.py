"""Expose enabled extension directories through systemd's runtime discovery paths."""

from . import store
from .config import ExtkitConfig
from .errors import fail
from .filesystem import state_transaction


@state_transaction
def command_sync(config: ExtkitConfig, args):
    """Link runtime discovery to the persistent enabled directory."""
    source = store.enabled_dir(config, args.kind)
    destination = store.runtime_dir(config, args.kind)
    if source == destination or source.is_relative_to(destination) or destination.is_relative_to(source):
        fail("enabled and runtime extension directories must not contain each other")
    source.mkdir(parents=True, exist_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        if destination.readlink() == source:
            return
        destination.unlink()
    elif destination.exists():
        if not destination.is_dir() or any(destination.iterdir()):
            fail(f"runtime discovery path must be an empty directory or a symlink: {destination}")
        destination.rmdir()
    destination.symlink_to(source, target_is_directory=True)
