"""shared helpers for ExtKit's command-line tools."""
import builtins
import glob
import struct
import uuid
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import threading

_locks = threading.local()
EFI_CERT_X509_GUID = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")


def efi_x509_certificates(data, owner_guid=None):
    """Return DER certificates from an EFI signature-list payload."""
    certificates = []
    position = 0
    while position + 28 <= len(data):
        signature_type = uuid.UUID(bytes_le=data[position:position + 16])
        list_size, header_size, signature_size = struct.unpack_from("<III", data, position + 16)
        if list_size < 28 or position + list_size > len(data) or signature_size < 16:
            break
        entries = position + 28 + header_size
        end = position + list_size
        if entries > end or (end - entries) % signature_size:
            break
        if signature_type == EFI_CERT_X509_GUID:
            while entries + signature_size <= end:
                owner = uuid.UUID(bytes_le=data[entries:entries + 16])
                if owner_guid is None or owner == owner_guid:
                    certificates.append(data[entries + 16:entries + signature_size])
                entries += signature_size
        position = end
    return certificates


def enrolled_certificates(pattern, owner_guid=None):
    certificates = []
    for name in glob.glob(pattern):
        try:
            data = Path(name).read_bytes()
        except OSError:
            continue
        # efivarfs prefixes variable data with the four-byte EFI attributes.
        certificates.extend(efi_x509_certificates(data[4:], owner_guid))
    return certificates


def print(*values, color=None, **options):
    colors = {"red": "31", "yellow": "33", "green": "32"}
    if color is not None and color not in colors:
        raise ValueError(f"unsupported output color: {color}")
    stream = options.get("file", sys.stdout)
    if stream is None:
        stream = sys.stdout
    if color and stream.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb":
        separator = options.get("sep")
        text = (" " if separator is None else separator).join(str(value) for value in values)
        options.pop("sep", None)
        builtins.print(f"\033[{colors[color]}m{text}\033[0m", **options)
    else:
        builtins.print(*values, **options)


def load_path_list(path):
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    if not isinstance(data, list) or any(not isinstance(item, str) for item in data):
        raise ValueError(f"invalid selection: {path}")
    return sorted(set(data))


def save_path_list(path, paths):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix=f".{path.name}.", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(sorted(set(paths)), stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def locked_state(directory):
    key = str(directory.resolve())
    held = getattr(_locks, "held", None)
    if held is None:
        held = _locks.held = set()
    if key in held:
        yield
        return
    directory.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(directory / ".extkit.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        held.add(key)
        try:
            yield
        finally:
            held.remove(key)


def verification_environment(source=None):
    environment = dict(os.environ if source is None else source)
    environment.update(SYSTEMD_ALLOW_USERSPACE_VERITY="0",
                       SYSTEMD_DISSECT_VERITY_SIGNATURE="1",
                       SYSTEMD_DISSECT_VERITY_SIDECAR="0")
    return environment
