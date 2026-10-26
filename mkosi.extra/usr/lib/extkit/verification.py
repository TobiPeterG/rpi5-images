"""Verification operations."""

import base64
import json
import os
import subprocess
from pathlib import Path

from . import images
from . import process
from .config import ExtkitConfig
from .models import SignatureStatus, SignaturePresence, Trust
from .trust import verification_environment


SIGNED_POLICY = "root=signed:usr=absent"


def verify_kernel_image(image: Path, environment=None):
    """Kernel verification operation."""
    return process.run(
        ['systemd-dissect', '--read-only', f'--image-policy={SIGNED_POLICY}',
         '--with', str(image), '/usr/bin/true'], capture_output=True, text=True,
        env=verification_environment() if environment is None else environment, timeout=60,
    )


def signature_status(config: ExtkitConfig, image, verify=True):
    """Presence is distinct from acceptance by this boot's kernel keyrings."""
    try:
        partitions = images.gpt_partitions(image)
        if not partitions or "extkit-signature" not in partitions:
            return SignatureStatus(SignaturePresence.UNSIGNED, Trust.UNTRUSTED, "no embedded signature partition")
        partition = partitions["extkit-signature"]
        if partition["size"] > images.SIGNATURE_BYTES:
            return SignatureStatus(SignaturePresence.INVALID, Trust.UNTRUSTED, "oversized signature partition")
        with Path(image).open("rb") as stream:
            stream.seek(partition["offset"])
            payload = stream.read(partition["size"]).rstrip(b"\0")
        if not payload:
            return SignatureStatus(SignaturePresence.UNSIGNED, Trust.UNTRUSTED, "empty signature partition")
        value = json.loads(payload)
        cms = base64.b64decode(value["signature"], validate=True)
        if not cms:
            return SignatureStatus(SignaturePresence.UNSIGNED, Trust.UNTRUSTED, "empty CMS signature")
        if value.get("rootHash") != partitions["extkit-root"]["uuid"] + partitions["extkit-verity"]["uuid"]:
            return SignatureStatus(SignaturePresence.INVALID, Trust.UNTRUSTED, "signature root hash does not match GPT")
    except (OSError, ValueError, KeyError, TypeError) as error:
        return SignatureStatus(SignaturePresence.INVALID, Trust.UNTRUSTED, str(error))
    if not verify:
        return SignatureStatus(SignaturePresence.SIGNED, Trust.UNCHECKED, "signature present")
    if os.geteuid() != 0:
        return SignatureStatus(SignaturePresence.SIGNED, Trust.UNKNOWN, "kernel verification requires root")
    environment = verification_environment()
    try:
        result = verify_kernel_image(image, environment)
    except (OSError, subprocess.TimeoutExpired) as error:
        return SignatureStatus(SignaturePresence.SIGNED, Trust.UNKNOWN, str(error))
    if result.returncode == 0:
        return SignatureStatus(SignaturePresence.SIGNED, Trust.TRUSTED, "accepted by kernel signed-image verification")
    return SignatureStatus(SignaturePresence.SIGNED, Trust.UNTRUSTED, (result.stderr or "kernel verification failed").strip())
