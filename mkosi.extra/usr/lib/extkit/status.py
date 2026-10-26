"""Read-only extension status collection."""

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import metadata, process, store, verification
from .config import ExtkitConfig
from .models import SignatureStatus


@dataclass(frozen=True)
class ExtensionStatus:
    kind: str
    image: Path
    name: str
    version: str
    enabled: bool
    enabled_since: str | None
    policy: str | None
    signature: SignatureStatus
    mounted: bool | None
    name_mounted: bool | None


def collect(config: ExtkitConfig, kind, *, mounted=None, include_policy=True):
    result = []
    for image, selected, link in store.stored_extension_states(config, kind):
        name, version = store.split_image_name(image)
        policy = None
        if include_policy:
            try:
                updates, version_id = metadata.embedded_update_policy(config, kind, image)
                policy = metadata.policy_description(updates, version_id)
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                policy = f'unknown (metadata unreadable: {error})'
        result.append(ExtensionStatus(
            kind, image, name, version, selected, store.enabled_since(link) if selected else None,
            policy, verification.signature_status(config, image),
            # systemd's status identifies names
            None if mounted is None or name in mounted else False,
            None if mounted is None else name in mounted,
        ))
    return result


def mounted_extensions(config: ExtkitConfig, kind):
    environment = os.environ.copy()
    environment[f"SYSTEMD_{kind.upper()}_HIERARCHIES"] = ":".join(
        f"/{prefix}" for prefix in config.kinds[kind]
    )
    try:
        result = process.run(
            [f"systemd-{kind}", "status", "--json=short", "--no-pager"],
            text=True, capture_output=True, env=environment,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        return None
    mounted = set()
    for row in rows:
        values = row.get("extensions", [])
        if isinstance(values, str):
            values = re.split(r"[\s,]+", values)
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            return None
        for value in values:
            if value and value != "none":
                mounted.add(value)
    return mounted
