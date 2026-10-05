"""command-line UKI addons"""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zipfile

FORMAT = "org.extkit.addon-request.v1"
MAX_SIZE = 64 * 1024
SBAT = b"sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\nextkit-addon,1,ExtKit,extkit-addon,1,https://systemd.io/\n\0"
MACHINES = {"arm64": 0xaa64, "x86-64": 0x8664}
# Return EFI_UNSUPPORTED, without touching firmware or memory.
CODE = {"arm64": bytes.fromhex("600080d20000f0f2c0035fd6"),
        "x86-64": bytes.fromhex("48b80300000000000080c3")}


def build(command_line, architecture):
    if architecture not in MACHINES:
        raise ValueError("addon architecture must be arm64 or x86-64")
    if not command_line or len(command_line.encode()) > 8192 or any(ord(c) < 32 or ord(c) > 126 for c in command_line):
        raise ValueError("addon command line must contain 1–8192 printable ASCII bytes")
    sections = [(b".text", CODE[architecture], 0x60000020),
                (b".cmdline", command_line.encode() + b"\0", 0x40000040),
                (b".sbat", SBAT, 0x40000040)]
    header = bytearray(512)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 60, 64)
    header[64:68] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, 68, MACHINES[architecture], 3, 0, 0, 0, 240, 0x22)
    opt = 88
    struct.pack_into("<H", header, opt, 0x20b)
    struct.pack_into("<III", header, opt + 4, 512, sum((len(s[1]) + 511) // 512 * 512 for s in sections[1:]), 0)
    struct.pack_into("<IIQII", header, opt + 16, 4096, 4096, 0, 4096, 512)
    struct.pack_into("<HH", header, opt + 40, 1, 0)
    struct.pack_into("<HH", header, opt + 48, 1, 0)
    image_size = 4096
    result = bytearray(header)
    for index, (name, data, flags) in enumerate(sections):
        raw_size = (len(data) + 511) // 512 * 512
        position = 328 + index * 40
        result[position:position + 8] = name.ljust(8, b"\0")
        struct.pack_into("<IIIIIIHHI", result, position + 8,
                         len(data), image_size, raw_size, len(result), 0, 0, 0, 0, flags)
        result.extend(data + bytes(raw_size - len(data)))
        image_size += (len(data) + 4095) // 4096 * 4096
    struct.pack_into("<II", result, opt + 56, image_size, 512)
    struct.pack_into("<HH", result, opt + 68, 10, 0x140)
    struct.pack_into("<QQQQII", result, opt + 72, 1024 * 1024, 4096, 1024 * 1024, 4096, 0, 16)
    return bytes(result)


def inspect(data):
    if not 512 <= len(data) <= MAX_SIZE or data[:2] != b"MZ" or data[64:68] != b"PE\0\0":
        raise ValueError("invalid addon PE image")
    architecture = next((key for key, value in MACHINES.items() if struct.unpack_from("<H", data, 68)[0] == value), None)
    if architecture is None:
        raise ValueError("unsupported addon architecture")
    size, _, raw_size, offset = struct.unpack_from("<IIII", data, 368 + 8)
    if not 1 < size <= 8193 or raw_size < size or offset < 512 or offset + raw_size > len(data):
        raise ValueError("invalid addon command-line section")
    payload = data[offset:offset + size]
    if payload[-1:] != b"\0":
        raise ValueError("unterminated addon command line")
    command_line = payload[:-1].decode("ascii")
    canonical = build(command_line, architecture)
    normalized = bytearray(data[:len(canonical)])
    normalized[152:156] = bytes(4)  # PE checksum, not part of Authenticode.
    normalized[232:240] = bytes(8)  # Certificate table.
    if bytes(normalized) != canonical:
        raise ValueError("addon contains unexpected headers, sections or executable code")
    cert_offset, cert_size = struct.unpack_from("<II", data, 232)
    if cert_size:
        if cert_offset != len(canonical) or cert_offset + cert_size != len(data) or cert_size < 8:
            raise ValueError("invalid addon certificate table")
        length, revision, kind = struct.unpack_from("<IHH", data, cert_offset)
        if revision != 0x200 or kind != 2 or not 8 < length <= cert_size or any(data[cert_offset + length:]):
            raise ValueError("invalid addon WIN_CERTIFICATE")
    elif len(data) != len(canonical) or cert_offset:
        raise ValueError("unsigned addon contains trailing data")
    return command_line, architecture, bool(cert_size)


def request(image, destination, name, version):
    data = image.read_bytes()
    command_line, architecture, signed = inspect(data)
    if signed:
        raise ValueError("addon is already signed")
    metadata = {"format": FORMAT, "name": name, "version": str(version),
                "architecture": architecture, "imageSha256": hashlib.sha256(data).hexdigest()}
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("request.json", json.dumps(metadata))
        archive.writestr("addon.efi", data)


def verify(image, certificates):
    """Check Authenticode"""
    _, _, signed = inspect(image.read_bytes())
    if not signed:
        return False
    with tempfile.TemporaryDirectory(prefix="extkit-addon-verify-") as work:
        der, pem = Path(work) / "certificate.der", Path(work) / "certificate.pem"
        for certificate in certificates:
            der.write_bytes(certificate)
            subprocess.run(["openssl", "x509", "-inform", "DER", "-in", str(der), "-out", str(pem)],
                           check=True, capture_output=True)
            result = subprocess.run(["sbverify", "--cert", str(pem), str(image)], capture_output=True)
            if result.returncode == 0:
                return True
    return False


def install(image, directory, name, certificates):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", name):
        raise ValueError("invalid addon name")
    if not verify(image, certificates):
        raise ValueError("addon signature is not trusted by the live Secure Boot db; enroll its key and reboot")
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{name}.addon.efi"
    with tempfile.NamedTemporaryFile(dir=directory, prefix=".addon-", delete=False) as stream:
        pending = Path(stream.name)
        try:
            stream.write(image.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
            pending.replace(destination)
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            pending.unlink(missing_ok=True)
    return destination
