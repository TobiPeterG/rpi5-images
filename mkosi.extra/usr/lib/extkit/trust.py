"""Live EFI authority and kernel verification policy."""

import glob
import os
import struct
import uuid
from pathlib import Path


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


def verification_environment(source=None):
    environment = dict(os.environ if source is None else source)
    environment.update(SYSTEMD_ALLOW_USERSPACE_VERITY="0",
                       SYSTEMD_DISSECT_VERITY_SIGNATURE="1",
                       SYSTEMD_DISSECT_VERITY_SIDECAR="0")
    return environment
