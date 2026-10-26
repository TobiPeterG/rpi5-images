"""Boot install operations."""

import fcntl
import hashlib
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from . import filesystem
from .console import print
from .errors import InstallationError
from .errors import installation_fail as fail
from .models import VerifiedBootPair


def boot_recovery_pairs(directory):
    return sorted((path for path in directory.glob("boot_*.img")
                   if path.is_file() and not path.is_symlink()
                   and re.fullmatch(r"boot_[A-Za-z0-9][A-Za-z0-9.+-]{0,127}_[0-9a-f]{12}\.img", path.name)
                   and path.with_suffix(".sig").is_file()
                   and not path.with_suffix(".sig").is_symlink()),
                  key=lambda path: path.stat().st_mtime_ns)


def make_boot_update_space(image, signature, directory, versioned):
    """Reserve peak staging space, reclaiming only old generated recovery pairs."""
    block = os.statvfs(directory).f_frsize or 4096
    def allocated(path):
        return ((path.stat().st_size + block - 1) // block) * block

    # Two new copies: the versioned pair and the pending active pair.
    required = 2 * (allocated(image) + allocated(signature)) + 1024 * 1024
    active = [directory / name for name in ("boot.img", "boot.sig")]
    for path in active:
        if path.is_symlink() or (path.exists() and not path.is_file()):
            fail(f"boot destination must be a regular file: {path}")
    active_digest = None
    if active[0].exists():
        with active[0].open("rb") as stream:
            active_digest = hashlib.file_digest(stream, "sha256").hexdigest()[:12]
    sources = {image.resolve(), signature.resolve()}
    pairs = boot_recovery_pairs(directory)
    matching_active = [path for path in pairs
                       if active_digest and path.stem.endswith("_" + active_digest)]
    protected = matching_active[-1] if matching_active else None
    candidates = [path for path in pairs
                  if path.stem != versioned
                  and path != protected
                  and path.resolve() not in sources
                  and path.with_suffix(".sig").resolve() not in sources]
    if shutil.disk_usage(directory).free >= required:
        return
    reclaimable = sum(allocated(path) + allocated(path.with_suffix(".sig")) for path in candidates)
    if shutil.disk_usage(directory).free + reclaimable < required:
        fail("Not enough ESP space for the boot update, even after pruning old recovery versions. Active boot files and recovery versions were left unchanged")
    for old in candidates:
        if shutil.disk_usage(directory).free >= required:
            return
        old.with_suffix(".sig").unlink()
        old.unlink()
        os.sync()
        print(f"Removed oldest boot recovery pair to free ESP space: {old.name} / {old.with_suffix('.sig').name}. Recovery requires another copy or download.", color="yellow")
    if shutil.disk_usage(directory).free < required:
        fail("ESP still lacks staging space after pruning. Active boot files were left unchanged")


def install_boot_files(pair: VerifiedBootPair, directory: Path, version: str | None = None):
    """Install a downloaded pair."""
    directory = Path(directory)
    image, signature = pair.image, pair.signature
    if filesystem.file_sha256(image) != pair.image_sha256 or filesystem.file_sha256(signature) != pair.signature_sha256:
        raise InstallationError('verified boot pair changed before installation')
    with image.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    lines = signature.read_text("ascii").splitlines()
    if not lines or lines[0].lower() != digest:
        fail("returned boot.sig does not match the downloaded boot.img")
    if not any(line.startswith("rsa2048:") and len(line[8:].strip()) == 512
               and all(char in "0123456789abcdefABCDEF" for char in line[8:].strip())
               for line in lines[1:]):
        fail("returned boot.sig has no valid RSA-2048 signature")
    if not version:
        fail("boot image version metadata is required")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,127}", version):
        fail("invalid boot image version")
    versioned = f"boot_{version}_{digest[:12]}"
    with open(directory / ".extkit-boot.lock", "a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        names = ("boot.img", "boot.sig")
        pending = [directory / (name + ".pending") for name in names]
        for path in pending + [directory / f"{versioned}.{suffix}" for suffix in ("img", "sig")]:
            if path.is_symlink() or (path.exists() and not path.is_file()):
                fail(f"boot destination must be a regular file: {path}")
        for path in pending:
            if path.resolve() in {image.resolve(), signature.resolve()}:
                fail("boot update input must not be a pending destination")
        for path in pending:
            if path.exists():
                path.unlink()
                print(f"Removed stale pending boot file: {path.name}. Complete versioned pairs remain available for recovery.", color="yellow")
        make_boot_update_space(image, signature, directory, versioned)
        with tempfile.TemporaryDirectory(prefix=".extkit-boot-", dir=directory) as temporary:
            staging = Path(temporary)
            for suffix, source in (("img", image), ("sig", signature)):
                staged = staging / f"{versioned}.{suffix}"
                target = directory / staged.name
                if target.is_symlink():
                    fail(f"versioned boot destination must not be a symlink: {target}")
                shutil.copyfile(source, staged)
                with staged.open("rb") as stream:
                    os.fsync(stream.fileno())
                os.replace(staged, target)
            os.sync()
            try:
                # Copy only from the fully written versioned pair. Neither
                # active file is replaced until both pending files are flushed.
                for suffix, path in zip(("img", "sig"), pending):
                    shutil.copyfile(directory / f"{versioned}.{suffix}", path)
                    with path.open("rb") as stream:
                        os.fsync(stream.fileno())
                os.sync()
                for path, name in zip(pending, names):
                    os.replace(path, directory / name)
                os.sync()
            except OSError:
                print("ERROR: Boot installation failed. If active files are mismatched, restore a matching versioned .img/.sig pair to boot.img/boot.sig before rebooting.", file=sys.stderr, color="red")
                os.sync()
                raise
            finally:
                for path in pending:
                    path.unlink(missing_ok=True)
            # Keep the current pair plus five previous pairs.
            pairs = list(reversed(boot_recovery_pairs(directory)))
            previous = [path for path in pairs if path.stem != versioned]
            for old in previous[5:]:
                try:
                    old.unlink()
                    old.with_suffix(".sig").unlink()
                except OSError as error:
                    print(f"WARNING: Boot update is installed, but could not prune {old}: {error}", file=sys.stderr, color="yellow")
            os.sync()
            print(f"✓ Saved recovery pair: {versioned}.img / {versioned}.sig", color="green")
