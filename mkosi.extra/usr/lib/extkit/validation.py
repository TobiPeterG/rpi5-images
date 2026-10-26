"""Validation operations."""

import re

from .errors import fail


NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*\Z")


def checked_name(value):
    if not NAME_RE.fullmatch(value) or value in (".", ".."):
        fail(f"invalid name/version: {value!r}")
    return value
