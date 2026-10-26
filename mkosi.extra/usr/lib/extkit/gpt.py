"""Parsing of the GPT format used by our images."""

import struct
import uuid
import zlib
from pathlib import Path

from .errors import fail


def gpt_partitions(image):
    """Read our 512-byte-sector GPT, checking bounds and CRCs before extraction."""
    with Path(image).open("rb") as stream:
        stream.seek(512)
        header = bytearray(stream.read(512))
        if header[:8] != b"EFI PART":
            return None
        if len(header) < 92:
            fail("truncated GPT header")
        header_size = struct.unpack_from("<I", header, 12)[0]
        if not 92 <= header_size <= 512:
            fail("invalid GPT header size")
        expected = struct.unpack_from("<I", header, 16)[0]
        struct.pack_into("<I", header, 16, 0)
        if zlib.crc32(header[:header_size]) != expected:
            fail("invalid GPT header checksum")
        entry_lba, count, size, checksum = struct.unpack_from("<QIII", header, 72)
        image_size = Path(image).stat().st_size
        if not 1 <= count <= 128 or size != 128 or entry_lba < 2:
            fail("unsupported GPT entry table")
        if entry_lba * 512 + count * size > image_size:
            fail("GPT entry table outside image")
        stream.seek(entry_lba * 512)
        entries = stream.read(count * size)
        if zlib.crc32(entries) != checksum:
            fail("invalid GPT partition table checksum")
        partitions = {}
        extents: list[tuple[int, int]] = []
        for index in range(count):
            entry = entries[index * size:(index + 1) * size]
            if entry[:16] == bytes(16):
                continue
            start, end = struct.unpack_from("<QQ", entry, 32)
            if start < 34 or end < start or (end + 1) * 512 > image_size:
                fail("GPT partition outside image")
            if any(start <= other_end and end >= other_start
                   for other_start, other_end in extents):
                fail("overlapping GPT partitions")
            extents.append((start, end))
            label = entry[56:128].decode("utf-16-le").rstrip("\0")
            if label in partitions:
                fail("duplicate GPT partition label")
            partitions[label] = {
                "offset": start * 512, "size": (end - start + 1) * 512,
                "uuid": uuid.UUID(bytes_le=entry[16:32]).hex,
            }
        return partitions
