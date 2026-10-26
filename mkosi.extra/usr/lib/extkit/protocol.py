"""Wire protocol."""

from pathlib import Path

from .errors import TransferError


PROTOCOL = "org.extkit.signing-network.v1"
BINDING_DOMAIN = b"org.extkit.transport-binding.v1\n"
PAIRING_DOMAIN = b"org.extkit.pairing.v1\0"
MAX_HEADER = 64 * 1024
PENDING_ENROLLMENT = Path("/run/extkit-phone/pending-enrollment")


def object_field(value, key):
    if not isinstance(value, dict) or not isinstance(value.get(key), dict):
        raise TransferError(f'phone response field {key!r} must be an object')
    return value[key]


def text_field(value, key):
    if not isinstance(value, dict) or not isinstance(value.get(key), str) or not value[key]:
        raise TransferError(f'phone response field {key!r} must be a non-empty string')
    return value[key]
