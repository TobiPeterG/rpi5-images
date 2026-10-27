"""Construct extension DDIs and immutable signing-request packages."""

import hashlib
import os
import struct
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path

from . import filesystem as fs
from . import process
from .config import ExtkitConfig
from .errors import ArtifactFormatError
from .errors import fail
from .gpt import gpt_partitions


BLOCK_SIZE = 4096
DIGEST_SIZE = 32
HASHES_PER_BLOCK = 128
SIGNATURE_BYTES = 16384


@contextmanager
def image_tree(config: ExtkitConfig, image):
    """Extract an image into a private temporary tree for inspection or inheritance."""
    work = config.state / "work"
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="extkit-image-", dir=work) as directory:
        tree = Path(directory) / "tree"
        tree.mkdir()
        partitions = gpt_partitions(image)
        if not partitions or "extkit-root" not in partitions:
            fail("expected an ExtKit GPT extension image")
        process.run([
            config.erofs_fsck_tool, f"--offset={partitions['extkit-root']['offset']}",
            f"--extract={tree}", "--overwrite", "--preserve", "--xattrs", str(image),
        ], check=True)
        yield tree


def copy_image_tree(config: ExtkitConfig, image, destination):
    with image_tree(config, image) as source:
        process.run(["cp", "-a", f"{source}/.", str(destination)], check=True)


def hash_block(block, salt):
    return hashlib.sha256(salt + block).digest()


def verity_root_hash(image, data_blocks, salt, temporary_directory):
    """Compute the cryptsetup-compatible dm-verity v1/SHA-256 root hash."""
    image = Path(image)
    if image.stat().st_size != data_blocks * BLOCK_SIZE:
        raise ArtifactFormatError("image size does not equal data_blocks * 4096")
    source, source_blocks, generated = image, data_blocks, []
    try:
        while source_blocks > 1:
            output_blocks = (source_blocks + HASHES_PER_BLOCK - 1) // HASHES_PER_BLOCK
            descriptor, filename = tempfile.mkstemp(prefix="verity-level-", dir=temporary_directory)
            os.close(descriptor)
            output = Path(filename)
            generated.append(output)
            with source.open("rb") as src, output.open("wb") as dst:
                remaining = source_blocks
                for _ in range(output_blocks):
                    hashes = bytearray(BLOCK_SIZE)
                    for index in range(HASHES_PER_BLOCK):
                        if not remaining:
                            break
                        block = src.read(BLOCK_SIZE)
                        if len(block) != BLOCK_SIZE:
                            raise ArtifactFormatError("truncated image while calculating dm-verity")
                        start = index * DIGEST_SIZE
                        hashes[start:start + DIGEST_SIZE] = hash_block(block, salt)
                        remaining -= 1
                    dst.write(hashes)
                if remaining or src.read(1):
                    raise ArtifactFormatError("image size changed while calculating dm-verity")
            source, source_blocks = output, output_blocks
        with source.open("rb") as src:
            block = src.read(BLOCK_SIZE)
            if len(block) != BLOCK_SIZE or src.read(1):
                raise ArtifactFormatError("invalid final dm-verity level")
        return hash_block(block, salt).hex()
    finally:
        for path in generated:
            path.unlink(missing_ok=True)


def copy_partition(image, partition, output):
    with Path(image).open("rb") as source, Path(output).open("wb") as target:
        source.seek(partition["offset"])
        remaining = partition["size"]
        while remaining:
            chunk = source.read(min(remaining, 1024 * 1024))
            if not chunk:
                fail("truncated partition")
            target.write(chunk)
            remaining -= len(chunk)


def ddi_request(config: ExtkitConfig, image, request, name, version, kind):
    """Request a signature over the pre-built DDI filesystem and hash."""
    partitions = gpt_partitions(image)
    if partitions is None or not all(label in partitions for label in
                                     ("extkit-root", "extkit-verity", "extkit-signature")):
        fail("expected an ExtKit GPT image with filesystem, verity and signature partitions")
    with Path(image).open("rb") as source:
        source.seek(partitions["extkit-verity"]["offset"])
        header = source.read(512)
    fields = struct.unpack_from("<8sII16s32sIIQH6x256s", header)
    magic, version_format, hash_type, _, algorithm, data_size, hash_size, blocks, salt_size, salt = fields
    if (magic != b"verity\0\0" or version_format != 1 or hash_type != 1 or
            algorithm.rstrip(b"\0") != b"sha256" or data_size != 4096 or
            hash_size != 4096 or not 1 <= salt_size <= 256):
        fail("unsupported verity superblock")
    if blocks * 4096 != partitions["extkit-root"]["size"]:
        fail("verity data size differs from filesystem partition size")
    with tempfile.TemporaryDirectory(prefix="extkit-request-") as work:
        filesystem = Path(work) / "extension.erofs"
        copy_partition(image, partitions["extkit-root"], filesystem)
        root_hash = verity_root_hash(filesystem, blocks, salt[:salt_size], work)
    expected = partitions["extkit-root"]["uuid"] + partitions["extkit-verity"]["uuid"]
    if root_hash != expected:
        fail("pre-built DDI root hash differs from signing request")
    metadata = fs.json_bytes({
        "format": "org.extkit.signing-request.v1", "name": name,
        "version": str(version), "kind": kind, "imageEntry": "extension.raw",
        "imageSha256": fs.file_sha256(image), "rootHash": root_hash,
    })
    request = Path(request)
    request.parent.mkdir(parents=True, exist_ok=True)
    with fs.atomic_output(request) as stream:
        with zipfile.ZipFile(stream, "w", allowZip64=True) as archive:
            archive.writestr("request.json", metadata, compress_type=zipfile.ZIP_DEFLATED)
            archive.write(image, "extension.raw", compress_type=zipfile.ZIP_STORED)
    return root_hash


def prepare_ddi(config: ExtkitConfig, filesystem, output, request, name, version, kind):
    """Let systemd-repart build GPT and verity. Reserve space for offline signing."""
    filesystem = Path(filesystem).resolve()
    data_size = filesystem.stat().st_size
    if not data_size or data_size % 4096:
        fail("EROFS size must be a non-zero multiple of 4096")
    with tempfile.TemporaryDirectory(prefix="extkit-repart-") as work:
        definitions = Path(work)
        # CopyBlocks takes a literal absolute path
        if any(character in str(filesystem) for character in ('%', '\\', '\n', '\r')):
            fail("unsupported characters in filesystem image path")
        (definitions / "10-root.conf").write_text(
            '[Partition]\nType=root\nLabel=extkit-root\n'
            f'CopyBlocks={filesystem}\nSizeMinBytes={data_size}\nSizeMaxBytes={data_size}\n'
            'ReadOnly=yes\nVerity=data\nVerityMatchKey=root\n'
        )
        (definitions / "20-verity.conf").write_text(
            '[Partition]\nType=root-verity\nLabel=extkit-verity\n'
            'ReadOnly=yes\nVerity=hash\nVerityMatchKey=root\n'
            'VerityDataBlockSizeBytes=4096\nVerityHashBlockSizeBytes=4096\n'
        )
        (definitions / "30-signature.conf").write_text(
            '[Partition]\nType=root-verity-sig\nLabel=extkit-signature\n'
            f'SizeMinBytes={SIGNATURE_BYTES}\nSizeMaxBytes={SIGNATURE_BYTES}\nReadOnly=yes\n'
        )
        process.run([
            config.repart_tool, "--empty=create", "--size=auto", "--offline=yes",
            "--dry-run=no", "--sector-size=512", "--definitions", str(definitions),
            str(output),
        ], check=True)
    return ddi_request(config, output, request, name, version, kind)
