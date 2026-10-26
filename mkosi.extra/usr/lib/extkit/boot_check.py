"""Boot prerequisite: quarantine invalid candidates and require kernel-authenticated images."""

import fcntl
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

from . import activation
from . import images
from . import process
from . import quarantine
from . import verification
from .config import ExtkitConfig
from .errors import fail
from .filesystem import state_transaction
from .trust import verification_environment


def authenticate_extension_or_quarantine(config: ExtkitConfig, path, kind, environment):
    try:
        if not path.is_file() or images.gpt_partitions(path) is None:
            raise ValueError("boot requires a regular GPT extension image")
    except (ValueError, OSError) as error:
        quarantine.quarantine_extension(config, path, kind, error)
        return False
    try:
        result = verification.verify_kernel_image(path, environment)
        if result.returncode:
            raise ValueError(result.stderr or 'kernel rejected the extension signature')
    except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        quarantine.quarantine_extension(config, path, kind, getattr(error, "stderr", None) or str(error))
        return False
    return True


@state_transaction
def command_boot_check(config: ExtkitConfig, args):
    # Both services scan shared discovery paths. Serialize quarantine and sync
    # so they cannot race while moving the same malicious entry.
    config.runtime_directory.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(config.runtime_directory / "extkit-boot-check.lock",
                         os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        boot_check_locked(config, args)


def boot_check_locked(config: ExtkitConfig, args):
    """Boot prerequisite: no directory images, kernel-authenticated DDIs."""
    loader = "systemd-sysext" if args.kind == "sysext" else "systemd-confext"
    environment = verification_environment()
    if args.kind == "sysext":
        environment["SYSTEMD_SYSEXT_HIERARCHIES"] = ":".join(
            "/" + hierarchy for hierarchy in config.kinds["sysext"])
    # Discovery collapses duplicate names. Inspect every search directory as
    # well, so a shadowed directory cannot escape the boot prerequisite.
    for kind, directories in quarantine.extension_search_directories(config).items():
        for directory in sorted(directories):
            if directory.is_dir():
                for entry in list(directory.iterdir()):
                    if entry.is_dir():
                        quarantine.quarantine_extension(config, entry, kind, "directory/subvolume extensions are not authenticated images")
    activation.command_sync(config, SimpleNamespace(kind=args.kind, boot=True))
    # Verify individual candidates before asking systemd to read release metadata:
    authenticated = set()
    for directory in sorted(quarantine.extension_search_directories(config)[args.kind]):
        for path in sorted(directory.glob("*.raw")) if directory.is_dir() else []:
            if not path.exists() and not path.is_symlink():
                continue
            resolved = path.resolve()
            if resolved not in authenticated and authenticate_extension_or_quarantine(config, path, args.kind, environment):
                authenticated.add(resolved)
    # image policy is not consulted for directory images.
    # Examine ALL of systemd's discovery locations
    discovered = process.run(
        [loader, *([f"--root={config.root}"] if config.root != Path("/") else []), "--json=short", "list"], check=True, capture_output=True,
        text=True, env=environment,
    )
    images = json.loads(discovered.stdout or "[]")
    if not isinstance(images, list):
        fail("unexpected extension discovery response")
    for image in images:
        if image.get("type") != "raw":
            quarantine.quarantine_extension(config, Path(image["path"]), args.kind, "non-image extension")
            continue
        path = Path(image["path"])
        if path.resolve() not in authenticated:
            authenticate_extension_or_quarantine(config, path, args.kind, environment)
    mutable = config.root / "var/lib/extensions.mutable"
    if (mutable.resolve() != (config.runtime_directory / "extensions.mutable").resolve()
            or not mutable.resolve().is_relative_to(config.runtime_directory.resolve())):
        fail("mutable extension data must be backed by /run, not persistent storage")
