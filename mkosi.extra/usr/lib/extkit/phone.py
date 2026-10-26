"""Queue requests, stream artifacts and acknowledge completed phone sessions."""

import os
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

from . import filesystem
from . import protocol
from . import result_install
from . import transport
from .config import PhoneConfig
from .console import human_size
from .console import print, terminal_text
from .errors import TransferError, RequestRejected, BatchSigningError
from .errors import transfer_fail as fail
from .phone_models import PhoneSession
from .models import ArtifactResult, SigningOutcome, FinalizeArtifact


def save_artifact(session: PhoneSession, job_id, artifact, destination, config: PhoneConfig):
    phone, token = session.phone, session.token
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.receive-', delete=False) as stream:
        temporary = Path(stream.name)
    print(f"Receiving {artifact} from the phone…", flush=True)
    try:
        response, _, _ = transport.exchange(
            phone.service,
            {"op": "result", "token": token, "jobId": job_id, "artifact": artifact},
            output=temporary,
            timeout=config.signing_timeout,
            expected_peer=phone.transport_certificate,
            max_response=(16 * 1024 * 1024 * 1024 if artifact == "extension.raw" else
                          256 * 1024 * 1024 if artifact == "boot.img" else 8 * 1024 * 1024),
        )
        filesystem.publish_file(temporary, destination)
        print(f"Received {artifact} ({human_size(destination.stat().st_size)}).", flush=True, color="green")
        return response
    finally:
        temporary.unlink(missing_ok=True)


def send_request(session: PhoneSession, source, kind, output, config: PhoneConfig, finalize: FinalizeArtifact | None = None) -> SigningOutcome:
    job_id = submit_request(session, source, kind, output, config)
    options = {"finalize": finalize} if finalize is not None else {}
    return finish_request(session, job_id, Path(source), kind, output, config, **options)


def submit_request(session: PhoneSession, source, kind, output, config: PhoneConfig, wait=True):
    phone, token = session.phone, session.token
    source = Path(source)
    validate_request(source, kind, output, config)
    deadline = time.monotonic() + config.signing_timeout
    while True:
        reservation, _, _ = transport.exchange(phone.service,
            {"op": "reserve", "token": token, "kind": kind, "payloadLength": source.stat().st_size},
            expected_peer=phone.transport_certificate, timeout=config.connect_timeout)
        if reservation.get("state") == "accepted":
            break
        if reservation.get("state") != "waiting":
            fail("phone returned an invalid queue reservation")
        if not wait:
            return None
        if time.monotonic() >= deadline:
            fail("timed out waiting for space in the phone's signing queue")
        print(f"Waiting for phone queue space: {source.name}", flush=True)
        time.sleep(config.poll_interval)
    print(f"Sending {kind} signing request ({human_size(source.stat().st_size)}) to {terminal_text(phone.service.name)}…", flush=True)
    response, _, _ = transport.exchange(
        phone.service,
        {"op": "submit", "token": token, "kind": kind, "payloadLength": source.stat().st_size,
         "reservationId": protocol.text_field(reservation, "reservationId")},
        payload=source,
        timeout=config.signing_timeout,
        expected_peer=phone.transport_certificate,
    )
    job_id = protocol.text_field(response, "jobId")
    print("Request transfer finished.", flush=True, color="green")
    print(f"Request {job_id} is awaiting review and authorization on the phone.")
    return job_id


def validate_request(source: Path, kind, output, config: PhoneConfig):
    """Local preflight, also repeated at submission after interactive approval."""
    if kind not in ('boot', 'addon', 'extension'):
        fail(f'unsupported signing request kind: {kind}')
    if not source.is_file():
        fail(f"input file does not exist: {source}")
    if kind == "addon" and output is None:
        fail("addon requests require --output. Use extkit addon sign to install them")
    if kind == "boot" and output is None:
        boot_directory = config.boot_directory
        # Trigger a systemd automount before checking the actual mount.
        boot_directory.stat()
        if not os.path.ismount(boot_directory):
            fail(f"boot partition is not mounted at {boot_directory}")
        if os.geteuid() != 0:
            fail("automatic boot installation requires root. Use --output to save files elsewhere")


def finish_request(session: PhoneSession, job_id, source, kind, output, config: PhoneConfig, ready=False,
                   finalize: FinalizeArtifact | None = None) -> SigningOutcome:
    phone, token = session.phone, session.token
    deadline = time.monotonic() + config.signing_timeout
    while time.monotonic() < deadline:
        if ready:
            break
        time.sleep(config.poll_interval)
        status, _, _ = transport.exchange(phone.service, {"op": "status", "token": token, "jobId": job_id}, expected_peer=phone.transport_certificate, timeout=config.connect_timeout)
        if request_complete(status):
            break
    else:
        fail("timed out waiting for phone authorization")
    try:
        artifact = result_install.install_result(session, job_id, source, kind, output, config, save_artifact)
        if finalize is not None:
            artifact = finalize(artifact)
        if not isinstance(artifact, ArtifactResult):
            fail("artifact finalization did not return a verified publication result")
    except (OSError, TransferError, ValueError) as error:
        try:
            transport.exchange(phone.service, {"op": "received", "token": token, "jobId": job_id,
                                    "success": False, "error": str(error)[:512]},
                     expected_peer=phone.transport_certificate, timeout=config.connect_timeout)
        except (OSError, TransferError, ValueError):
            pass
        raise
    outcome = retry_receipt(SigningOutcome(artifact, job_id, session), config)
    if not artifact.complete:
        print(f'WARNING: Signed file retained at {artifact.image}. '
              f'durability: {artifact.durability_error or "confirmed"}. '
              f'activation: {artifact.activation_error or artifact.activation.value}. '
              'Do not repeat signing. Check the stored file and retry activation.', color='yellow')
    elif outcome.receipt_delivered:
        print('✓ Signing, publication and return transfer completed.', flush=True, color='green')
    return outcome


def request_complete(status):
    """Interpret terminal request states identically for single and batch sends."""
    state = protocol.text_field(status, 'state')
    if state == 'rejected':
        raise RequestRejected(status.get('error') or 'Request dismissed on the phone')
    if state == 'failed':
        fail(status.get('error') or 'Phone signing failed')
    return state == 'complete'


def retry_receipt(outcome: SigningOutcome, config: PhoneConfig) -> SigningOutcome:
    """Retry acknowledgement."""
    if outcome.receipt_delivered:
        return outcome
    session = outcome.session
    try:
        message = {'op': 'received', 'token': session.token, 'jobId': outcome.job_id,
                   'success': outcome.artifact.complete}
        if not outcome.artifact.complete:
            message['error'] = (f'Signed file retained at {outcome.artifact.image}. '
                                f'durability error: {outcome.artifact.durability_error}. '
                                f'activation error: {outcome.artifact.activation_error}')[:512]
        transport.exchange(session.phone.service, message,
            expected_peer=session.phone.transport_certificate, timeout=config.connect_timeout)
    except (OSError, ValueError) as error:
        print('WARNING: The signed artifact was retained, but its phone receipt '
              f'was not delivered: {terminal_text(error)}. Do not repeat signing or installation.', color='yellow')
        return replace(outcome, receipt_error=str(error))
    return replace(outcome, receipt_delivered=True, receipt_error=None)


def send_batch(session: PhoneSession, inputs, config: PhoneConfig, finalize: FinalizeArtifact | None = None) -> list[SigningOutcome]:
    """Upload while capacity permits, then drain results to free queue bytes."""
    phone, token = session.phone, session.token
    outcomes: list[SigningOutcome] = []
    remaining = list(inputs)
    pending: dict[str, Path] = {}
    failures = []
    deadline = time.monotonic() + config.signing_timeout
    waiting_notice = False
    while remaining or pending:
        if time.monotonic() >= deadline:
            raise BatchSigningError('batch signing timed out. Published images were retained', outcomes)
        if waiting_notice:
            # A lost receipt may leave the phone's byte budget occupied. Retry
            # just those receipts before reserving more queue space.
            outcomes = [retry_receipt(item, config) if not item.receipt_delivered else item for item in outcomes]
        while remaining:
            path = remaining[0]
            try:
                job_id = submit_request(session, path, "extension", None, config, wait=False)
            except (OSError, TransferError, ValueError) as error:
                print(f"✗ {path}: {terminal_text(error)}", file=sys.stderr, color="red")
                failures.append(remaining.pop(0))
                continue
            if job_id is None:
                if not waiting_notice:
                    print("Waiting for the phone's 2 GB queue budget to become available…", flush=True)
                    waiting_notice = True
                break
            remaining.pop(0)
            pending[job_id] = path
            waiting_notice = False
        for job_id, path in list(pending.items()):
            try:
                status, _, _ = transport.exchange(phone.service, {"op": "status", "token": token, "jobId": job_id},
                                        expected_peer=phone.transport_certificate, timeout=config.connect_timeout)
                if not request_complete(status):
                    continue
                options = {'finalize': finalize} if finalize is not None else {}
                outcome = finish_request(session, job_id, Path(path), 'extension', None, config, ready=True, **options)
                outcomes.append(outcome)
                if not outcome.artifact.complete:
                    failures.append(path)
            except RequestRejected as error:
                print(f"✗ {path}: {terminal_text(error)}", file=sys.stderr, color="red")
                if sys.stdin.isatty() and input(f"Send {terminal_text(Path(path).name)} again? [y/N] ").strip().lower() in {"y", "yes"}:
                    remaining.append(path)
                else:
                    failures.append(path)
            except (OSError, TransferError, ValueError) as error:
                print(f"✗ {path}: {terminal_text(error)}", file=sys.stderr, color="red")
                failures.append(path)
            del pending[job_id]
        if remaining or pending:
            time.sleep(config.poll_interval)
    if failures:
        raise BatchSigningError(f"{len(failures)} signing request(s) did not complete. Successfully published images were retained", outcomes)
    return outcomes
