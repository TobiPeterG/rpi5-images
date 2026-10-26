"""Certificate conversion primitives."""

import subprocess
from pathlib import Path

from . import process
from .errors import VerificationError


def checked(command, **options):
    try:
        return process.run(command, **options)
    except subprocess.CalledProcessError as error:
        raise VerificationError('signature/certificate verification failed') from error


def certificate_pem(directory: Path, certificate: bytes) -> Path:
    der, pem = Path(directory) / 'certificate.der', Path(directory) / 'certificate.pem'
    der.write_bytes(certificate)
    checked(['openssl', 'x509', '-inform', 'DER', '-in', str(der), '-out', str(pem)],
            check=True, capture_output=True)
    return pem


def certificate_public_key(directory: Path, certificate: bytes) -> Path:
    der, public = Path(directory) / 'certificate.der', Path(directory) / 'public.pem'
    der.write_bytes(certificate)
    checked(['openssl', 'x509', '-inform', 'DER', '-in', str(der), '-pubkey', '-noout', '-out', str(public)],
            check=True, capture_output=True)
    return public


def certificate_files(directory: Path | str, certificate: bytes) -> tuple[Path, Path]:
    return certificate_pem(Path(directory), certificate), certificate_public_key(Path(directory), certificate)
