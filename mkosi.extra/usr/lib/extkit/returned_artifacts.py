"""Validation of phone-returned artifacts before installation."""

import base64
import hashlib
import json
import re
import tempfile
import zipfile
from pathlib import Path
from typing import NoReturn

from .crypto import checked, certificate_files
from .errors import VerificationError
from .filesystem import file_sha256
from .images import gpt_partitions
from .models import VerifiedBootPair, VerifiedExtension


def fail(message) -> NoReturn:
    raise VerificationError(message)


def verify_response(response, source, kind, artifact):
    if (not isinstance(response, dict) or response.get("kind") != kind or
            response.get("artifact") != Path(artifact).name or
            response.get("requestSha256") != file_sha256(source) or
            response.get("artifactSha256") != file_sha256(artifact)):
        fail("returned artifact is not bound to this request, kind and content")


def verify_boot(image: Path, signature: Path, certificate: bytes) -> VerifiedBootPair:
    text = Path(signature).read_text("ascii")
    match = re.fullmatch(r"([a-f0-9]{64})\nts: ([0-9]+)\nrsa2048: ([a-f0-9]{512})\n", text)
    if not match or match[1] != file_sha256(image):
        fail("returned boot.sig does not match boot.img")
    with tempfile.TemporaryDirectory(prefix="extkit-boot-verify-") as work:
        _, public = certificate_files(work, certificate)
        sig = Path(work) / "signature"
        sig.write_bytes(bytes.fromhex(match[3]))
        checked(["openssl", "dgst", "-sha256", "-verify", str(public),
                        "-signature", str(sig), str(image)], check=True, capture_output=True)
    return VerifiedBootPair(Path(image), Path(signature), file_sha256(image), file_sha256(signature))


def _verify_extension_layout(request, returned):
    partitions = gpt_partitions(returned)
    if not partitions or set(partitions) != {"extkit-root", "extkit-verity", "extkit-signature"}:
        fail("unexpected returned extension partitions")
    slot = partitions["extkit-signature"]
    if slot["size"] != 16384:
        fail("unexpected returned signature slot")
    with zipfile.ZipFile(request) as archive:
        if archive.getinfo("request.json").file_size > 65536:
            fail("oversized extension request metadata")
        metadata = json.loads(archive.read("request.json"))
        if metadata.get("format") != "org.extkit.signing-request.v1":
            fail("unsupported extension request")
        info = archive.getinfo(metadata["imageEntry"])
        if info.file_size != Path(returned).stat().st_size:
            fail("returned extension size changed")
        digest = hashlib.sha256()
        position = 0
        with archive.open(info) as original, Path(returned).open("rb") as result:
            while chunk := original.read(1024 * 1024):
                other = result.read(len(chunk))
                digest.update(chunk)
                # Only the reserved signature bytes may differ from the request.
                left = max(0, min(len(chunk), slot["offset"] - position))
                right = max(0, min(len(chunk), slot["offset"] + slot["size"] - position))
                if chunk[:left] != other[:left] or chunk[right:] != other[right:]:
                    fail("phone changed extension bytes outside the signature slot")
                position += len(chunk)
        if digest.hexdigest() != metadata["imageSha256"]:
            fail("original extension request digest mismatch")
    root_hash = metadata["rootHash"]
    if (not re.fullmatch("[a-f0-9]{64}", root_hash) or
            root_hash != partitions["extkit-root"]["uuid"] + partitions["extkit-verity"]["uuid"]):
        fail("returned root hash differs from request")
    with Path(returned).open("rb") as stream:
        stream.seek(slot["offset"])
        payload = json.loads(stream.read(slot["size"]).rstrip(b"\0"))
    if payload.get("rootHash") != root_hash:
        fail("signature refers to another root hash")
    cms = base64.b64decode(payload["signature"], validate=True)
    return root_hash, cms


def verify_extension(request: Path, returned: Path, certificate: bytes) -> VerifiedExtension:
    root_hash, cms = verify_extension_layout(request, returned)
    with tempfile.TemporaryDirectory(prefix="extkit-cms-verify-") as work:
        pem, _ = certificate_files(work, certificate)
        content, signature = Path(work) / "hash", Path(work) / "signature.der"
        content.write_bytes(root_hash.encode("ascii"))
        signature.write_bytes(cms)
        # nointern forces the exact authenticated phone certificate.
        # noverify skips CA-chain validation because this certificate is already pinned.
        checked(["openssl", "cms", "-verify", "-binary", "-inform", "DER",
                        "-in", str(signature), "-content", str(content),
                        "-certfile", str(pem), "-nointern", "-noverify", "-out", "/dev/null"],
                       check=True, capture_output=True)
    return VerifiedExtension(Path(returned), file_sha256(returned), root_hash)


def verify_extension_layout(request: Path, returned: Path):
    try:
        return _verify_extension_layout(request, returned)
    except (KeyError, TypeError, ValueError, zipfile.BadZipFile) as error:
        if isinstance(error, VerificationError):
            raise
        raise VerificationError(f'invalid returned extension: {error}') from error
