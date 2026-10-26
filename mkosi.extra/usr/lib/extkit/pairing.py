"""Pairing operations."""

import base64
import hashlib
import hmac
import secrets
import shutil
import time
import uuid

from . import protocol
from . import transport
from . import process
from .config import PhoneConfig
from .console import print
from .errors import transfer_fail as fail
from .phone_models import PhoneSession


def pairing_context(phone):
    # The authenticated TLS endpoint supplies the signing certificates.
    return hashlib.sha256(phone.transport_certificate).digest()


def pairing_identifier(pairing_id):
    try:
        identifier = uuid.UUID(pairing_id)
    except ValueError:
        fail('invalid pairing session UUID')
    if str(identifier) != pairing_id:
        fail('pairing ID must be a canonical UUID')
    return identifier


def pairing_qr(pairing_id, qr_secret):
    if len(qr_secret) != 32:
        fail('invalid QR secret')
    encoded = base64.urlsafe_b64encode(qr_secret).decode('ascii').rstrip('=')
    return f'extkit-pair:v1:{pairing_identifier(pairing_id).hex}:{encoded}'


def pairing_proof(context, pairing_id, qr_secret):
    if len(context) != 32 or len(qr_secret) != 32:
        fail('invalid QR proof fields')
    return hmac.digest(qr_secret, protocol.PAIRING_DOMAIN + b'phone-scanned-qr\0'
                       + pairing_identifier(pairing_id).bytes + context, 'sha256').hex()


def pair(phone, config: PhoneConfig):
    if not shutil.which('qrencode'):
        fail('qrencode is required to display the pairing QR code')
    pairing_id = str(uuid.uuid4())
    qr_secret = secrets.token_bytes(32)
    context = pairing_context(phone)
    response, _, _ = transport.exchange(phone.service, {"op": "pairStart", "pairingId": pairing_id},
                                       timeout=config.connect_timeout, expected_peer=phone.transport_certificate)
    if protocol.text_field(response, 'pairingId') != pairing_id or response.get('state') != 'waiting':
        fail('phone returned an unexpected pairing session')
    print('\nOn ExtSigner, tap "Scan QR and allow connection" and scan this display.\n'
          'Scanning allows this sending session.\n'
          'Keep this QR private until pairing completes. It expires after two minutes.\n', flush=True)
    # stdin keeps the one-time secret out of process command-line listings.
    process.run(['qrencode', '-t', 'UTF8', '-l', 'L'], input=pairing_qr(pairing_id, qr_secret),
                text=True, check=True)
    return await_authorization(phone, config, pairing_id, {'state': 'waiting'},
                               expected_proof=pairing_proof(context, pairing_id, qr_secret))


def await_authorization(phone, config: PhoneConfig, pairing_id, response, expected_proof=None):
    deadline = time.monotonic() + config.pairing_timeout
    while response.get("state") == "waiting" and time.monotonic() < deadline:
        time.sleep(config.poll_interval)
        response, _, _ = transport.exchange(phone.service, {"op": "pairStatus", "pairingId": pairing_id}, expected_peer=phone.transport_certificate, timeout=config.connect_timeout)
    if response.get("state") != "accepted":
        fail("connection authorization was rejected on the phone or timed out")
    if expected_proof is not None:
        proof = protocol.text_field(response, 'qrProof')
        if len(proof) != 64 or any(char not in '0123456789abcdef' for char in proof) or not hmac.compare_digest(proof, expected_proof):
            fail('phone did not prove scanning this QR code. Enrollment aborted')
    return PhoneSession(phone, protocol.text_field(response, "token"))


def session(phone, config: PhoneConfig):
    response, _, _ = transport.exchange(
        phone.service,
        {"op": "session", "extensionFingerprint": phone.extension_fingerprint},
        timeout=config.connect_timeout,
        expected_peer=phone.transport_certificate,
    )
    print("Waiting for you to allow this local-network connection on the phone. ", flush=True)
    return await_authorization(phone, config, protocol.text_field(response, "pairingId"), response)
