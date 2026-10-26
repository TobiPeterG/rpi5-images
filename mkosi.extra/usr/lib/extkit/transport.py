"""Transport operations."""

import json
import secrets
import socket
import ssl
import struct
from pathlib import Path

from . import protocol
from .console import TransferProgress
from .errors import transfer_fail as fail


def recv_exact(stream, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = stream.recv(min(1024 * 1024, remaining))
        if not chunk:
            fail("phone closed the connection early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def exchange(service, request, payload=None, output=None, timeout=10, expected_peer=None, max_response=1024 * 1024):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((service.address, service.port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=None) as stream:
            peer = stream.getpeercert(binary_form=True)
            if expected_peer is not None and not secrets.compare_digest(peer, expected_peer):
                fail("phone TLS identity changed during the operation")
            header = json.dumps(request, separators=(",", ":")).encode()
            if len(header) > protocol.MAX_HEADER:
                fail("request header is too large")
            stream.sendall(struct.pack(">I", len(header)) + header)
            if payload:
                progress = TransferProgress("Sending", Path(payload).stat().st_size)
                completed = 0
                try:
                    with open(payload, "rb") as source:
                        while chunk := source.read(1024 * 1024):
                            stream.sendall(chunk)
                            completed += len(chunk)
                            progress.update(completed)
                finally:
                    progress.finish()
            size = struct.unpack(">I", recv_exact(stream, 4))[0]
            if not 2 <= size <= protocol.MAX_HEADER:
                fail("phone returned an invalid response header")
            try:
                response = json.loads(recv_exact(stream, size))
            except (ValueError, UnicodeError) as error:
                fail(f'phone returned malformed JSON: {error}')
            if not isinstance(response, dict) or type(response.get('ok')) is not bool:
                fail('phone response must be an object with a boolean ok field')
            if not response.get("ok"):
                fail(response.get("error", "phone rejected the request"))
            if response.get("protocol") != protocol.PROTOCOL:
                fail("phone returned an unexpected signing protocol")
            payload_length = response.get("payloadLength", 0)
            if type(payload_length) is not int or not 0 <= payload_length <= max_response:
                fail("phone response exceeds the size limit")
            if output is None:
                body = recv_exact(stream, payload_length)
            else:
                remaining = payload_length
                progress = TransferProgress("Receiving", payload_length)
                try:
                    with open(output, "wb") as destination:
                        while remaining:
                            chunk = stream.recv(min(1024 * 1024, remaining))
                            if not chunk:
                                fail("phone closed the result transfer early")
                            destination.write(chunk)
                            remaining -= len(chunk)
                            progress.update(payload_length - remaining)
                finally:
                    progress.finish()
                body = None
            return response, body, peer
