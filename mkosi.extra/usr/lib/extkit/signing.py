"""Phone review and publication of private extension signing snapshots."""

import json
import os
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import replace
from pathlib import Path

from . import filesystem
from . import images
from . import phone_client
from . import store
from . import verification
from .config import ExtkitConfig
from .console import print
from .errors import PublicationError, fail
from .filesystem import locked_state
from .models import SignaturePresence, ArtifactResult, Activation


def install_returned_extension(config: ExtkitConfig, image, request, returned):
    from .returned_artifacts import verify_extension_layout
    image, returned = Path(image), Path(returned)
    with zipfile.ZipFile(request) as archive:
        metadata = json.loads(archive.read('request.json'))
    if filesystem.file_sha256(image) != metadata['imageSha256']:
        fail('original image changed after preparing the request')
    verify_extension_layout(request, returned)
    filesystem.publish_file(returned, image)


def phone_sign_images(config: ExtkitConfig, outputs, enabled):
    sign_image_batch(config, [(kind, output, enabled[kind]) for kind, output in outputs.items()])


def _sign_image_batch(config: ExtkitConfig, targets):
    """Own immutable request snapshots until every returned result is checked."""
    work = config.state / 'work'
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sign-', dir=work) as directory:
        prepared = []
        for kind, image, activation in targets:
            private = Path(directory) / kind / image.name
            filesystem.atomic_copy(image, private)
            name, version = store.split_image_name(image)
            request = private.with_suffix('.extsign')
            images.ddi_request(config, private, request, name, version, kind)
            prepared.append((kind, image, activation, request, private.with_suffix('.signed.raw')))
        by_request = {filesystem.file_sha256(request): (kind, image, activation, request)
                      for kind, image, activation, request, _ in prepared}

        def finalize(result: ArtifactResult) -> ArtifactResult:
            kind, image, expected_activation, request = by_request[result.request_sha256]
            name, _ = store.split_image_name(image)
            if filesystem.file_sha256(result.image) != result.image_sha256:
                fail('verified extension changed before final publication')
            try:
                install_returned_extension(config, image, request, result.image)
            except PublicationError as error:
                if error.destination != image:
                    raise
                return replace(result, image=image, installed=True, durability_error=str(error))
            result = replace(result, image=image, installed=True, durability_error=None)
            activation = Activation.NONE
            try:
                with locked_state(config.state):
                    if expected_activation is not None:
                        if store.activation_stamp(config, kind, name) == expected_activation:
                            store.enable_image(config, kind, name, image)
                            activation = Activation.ENABLED
                        else:
                            activation = Activation.DEFERRED
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                return replace(result, activation=Activation.FAILED, activation_error=str(error))
            print(f'Stored signed {kind} image: {image}', color='green')
            return replace(result, activation=activation)
        try:
            return phone_client.send(config, [item[3] for item in prepared],
                                     kind='extension', finalize=finalize)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            print(f'Signing did not fully complete: {error}. Successfully published images remain stored. '
                  'Retry only the remaining images with extkit sign.', file=sys.stderr, color='red')
            raise


def prepare_signing(config: ExtkitConfig, args):
    """Snapshot inventory."""
    if getattr(args, 'untrusted', False) and os.geteuid() != 0:
        fail('sign --untrusted requires root to test kernel trust')
    with locked_state(config.state):
        candidates = ([(kind, image) for kind in config.kinds if args.kind is None or kind == args.kind
                       for image, _, _ in store.stored_extension_states(config, kind)]
                      if args.name is None else list(store.requested_images(config, args.name, args.version, args.kind)))
        targets = []
        for kind, image in candidates:
            name, _ = store.split_image_name(image)
            link = store.enabled_dir(config, kind) / f'{name}.raw'
            activation = (store.activation_stamp(config, kind, name)
                          if link.is_symlink() and link.resolve() == image.resolve() else None)
            targets.append((kind, image, activation))
    if args.name is None:
        targets = [target for target in targets
                   if (not verification.signature_status(config, target[1]).trusted if args.untrusted else
                       verification.signature_status(config, target[1], verify=False).presence is not SignaturePresence.SIGNED)]
    if not targets:
        print('No extensions need signing.')
    return targets


def warn_if_signing_key_unenrolled(config: ExtkitConfig):
    try:
        if not phone_client.check_enrollment(config):
            fail("no user signing key is enrolled in the live Secure Boot db")
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print("WARNING: User signing key enrollment could not be confirmed. "
             "Continuing extension creation, but boot-time verification will reject "
             "images signed by an untrusted key. Run 'extkit-phone setup' and reboot. "
             "If boot.img is already personalized, reboot to load its key. "
             f"({error})", file=sys.stderr, color="yellow")


def offer_build_signing(config: ExtkitConfig, outputs, name, version, enabled, no_sign=False):
    print("WARNING: These images cannot be loaded under the signed-image policy until "
          "they are signed by a trusted key. Their contents take effect only after "
          "the extensions are enabled and merged (mounted).", file=sys.stderr, color="yellow")
    sign_now = False
    if not no_sign:
        while True:
            try:
                answer = input("Sign the built extension image(s) now? [y/N] ").strip().lower()
            except (EOFError, OSError):
                # No interactive input: keep the prepared images for later signing.
                break
            if answer in ("", "n", "no", "later"):
                break
            if answer in ("y", "yes", "now"):
                sign_now = True
                break
            print("Enter y to sign now, or n to sign later.", color="yellow")
    if sign_now:
        phone_sign_images(config, outputs, enabled)
    else:
        print("Signing deferred. Images and signing requests have been retained.")
        for kind in outputs:
            print(f"Sign later: extkit sign {name} {version} --type {kind}")


def command_sign(config: ExtkitConfig, args):
    targets = prepare_signing(config, args)
    if targets:
        sign_image_batch(config, targets)


def sign_image_batch(config: ExtkitConfig, targets):
    with filesystem.artifact_locks(config, [output for _,output,_ in targets]):
        return _sign_image_batch(config, targets)
