"""Explicit domain results."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable
from .phone_models import PhoneSession


class SignaturePresence(str, Enum):
    UNSIGNED = 'unsigned'
    SIGNED = 'signed'
    INVALID = 'invalid'


class Trust(str, Enum):
    TRUSTED = 'trusted'
    UNTRUSTED = 'not trusted'
    UNKNOWN = 'unknown'
    UNCHECKED = 'unchecked'


@dataclass(frozen=True)
class SignatureStatus:
    presence: SignaturePresence
    trust: Trust
    detail: str

    @property
    def trusted(self):
        return self.trust is Trust.TRUSTED


@dataclass(frozen=True)
class VerifiedBootPair:
    image: Path
    signature: Path
    image_sha256: str
    signature_sha256: str


@dataclass(frozen=True)
class VerifiedExtension:
    image: Path
    image_sha256: str
    root_hash: str


class Activation(str, Enum):
    NONE = 'not requested'
    ENABLED = 'enabled for next boot'
    DEFERRED = 'deferred. Current selection preserved'
    FAILED = 'activation failed. Signed image retained'


@dataclass(frozen=True)
class ArtifactResult:
    """Verified publication result."""
    request_sha256: str
    kind: str
    image: Path
    image_sha256: str
    installed: bool = False
    activation: Activation = Activation.NONE
    extra_files: tuple[Path, ...] = ()
    durability_error: str | None = None
    activation_error: str | None = None

    @property
    def complete(self) -> bool:
        return self.durability_error is None and self.activation_error is None


FinalizeArtifact = Callable[[ArtifactResult], ArtifactResult]


@dataclass(frozen=True)
class SigningOutcome:
    artifact: ArtifactResult
    job_id: str
    session: PhoneSession = field(repr=False)
    receipt_delivered: bool = False
    receipt_error: str | None = None
