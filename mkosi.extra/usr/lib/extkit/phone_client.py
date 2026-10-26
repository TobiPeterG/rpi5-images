"""Shared in-process interface"""

from pathlib import Path
from typing import Sequence

from . import phone_service
from .config import ExtkitConfig, load_phone_config
from .models import SigningOutcome, FinalizeArtifact
from .errors import BatchSigningError


def send(config: ExtkitConfig, inputs: Sequence[Path], *, kind: str, output: Path | None = None,
         finalize: FinalizeArtifact | None = None) -> list[SigningOutcome]:
    phone = load_phone_config(config.phone_configuration)
    options = {'finalize': finalize} if finalize is not None else {}
    outcomes = phone_service.send(phone, inputs, kind=kind, output=output, **options)
    outcomes = phone_service.retry_receipts(phone, outcomes)
    if any(not outcome.artifact.complete for outcome in outcomes):
        raise BatchSigningError('Signed files were retained, but durability or activation needs attention.', outcomes)
    return outcomes


def check_enrollment(config: ExtkitConfig) -> bool:
    return phone_service.has_enrolled_user_key(load_phone_config(config.phone_configuration))
