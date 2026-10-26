"""Verify returned artifacts, then publish or invoke the artifact-specific installer."""

import tempfile
import zipfile
from dataclasses import replace
from pathlib import Path

from . import addons, boot_install, filesystem
from .config import PhoneConfig
from .console import print
from .errors import PublicationError, transfer_fail as fail
from .phone_models import PhoneSession
from .models import ArtifactResult, Activation
from .returned_artifacts import verify_response, verify_boot, verify_extension


def install_result(session: PhoneSession, job_id, source, kind, output, config: PhoneConfig, download) -> ArtifactResult:
    phone = session.phone
    request_sha256 = filesystem.file_sha256(source)
    if kind not in ("addon", "extension", "boot"):
        fail(f"unsupported returned artifact kind: {kind}")
    if kind == "addon":
        if output is None:
            fail("addon requests require --output.")
        destination = Path(output)
        with tempfile.TemporaryDirectory(prefix="extkit-addon-result-") as temporary:
            image = Path(temporary) / "addon.efi"
            response = download(session, job_id, "addon.efi", image, config)
            verify_response(response, source, kind, image)
            if not addons.verify(image, [phone.extension_certificate]):
                fail("returned addon signature is not from the authenticated phone")
            with zipfile.ZipFile(source) as archive:
                original = archive.read("addon.efi")
            if addons.inspect(original)[:2] != addons.inspect(image.read_bytes())[:2]:
                fail("returned addon content differs from the submitted request")
            result = ArtifactResult(request_sha256, kind, destination, filesystem.file_sha256(image))
            try:
                filesystem.atomic_copy(image, destination)
            except PublicationError as error:
                result = replace(result, durability_error=str(error))
        print(f"Stored signed addon: {destination}", color="green")
        return result
    elif kind == "extension":
        destination = Path(output) if output else source.with_suffix(".signed.raw")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".extkit-result-", dir=destination.parent) as temporary:
            image = Path(temporary) / "extension.raw"
            response = download(session, job_id, "extension.raw", image, config)
            verify_response(response, source, kind, image)
            verified = verify_extension(source, image, phone.extension_certificate)
            result = ArtifactResult(request_sha256, kind, destination, verified.image_sha256)
            try:
                filesystem.publish_file(verified.image, destination)
            except PublicationError as error:
                result = replace(result, durability_error=str(error))
        print(f"Saved {destination}", color="green")
        return result
    else:
        with tempfile.TemporaryDirectory(prefix="extkit-phone-result-") as temporary:
            directory = Path(temporary)
            boot_response = download(session, job_id, "boot.img", directory / "boot.img", config)
            sig_response = download(session, job_id, "boot.sig", directory / "boot.sig", config)
            verify_response(boot_response, source, kind, directory / "boot.img")
            verify_response(sig_response, source, kind, directory / "boot.sig")
            pair = verify_boot(directory / "boot.img", directory / "boot.sig",
                        phone.boot_certificate)
            if output is not None:
                destination = Path(output)
                destination.mkdir(parents=True, exist_ok=True)
                filesystem.atomic_copy(directory / "boot.img", destination / "personalized-boot.img")
                filesystem.atomic_copy(directory / "boot.sig", destination / "boot.sig")
                print(f"Saved verified boot files in {destination}", color="green")
                return ArtifactResult(request_sha256, kind, destination / 'personalized-boot.img',
                                      pair.image_sha256, extra_files=(destination / 'boot.sig',))
            else:
                boot_install.install_boot_files(pair, config.boot_directory,
                                   version=(boot_response or {}).get("bootVersion"))
                print(f"Installed boot.img and boot.sig in {config.boot_directory}. Versioned recovery copies retained.", color="green")
                return ArtifactResult(request_sha256, kind, config.boot_directory / 'boot.img',
                                      pair.image_sha256, installed=True, activation=Activation.ENABLED,
                                      extra_files=(config.boot_directory / 'boot.sig',))
