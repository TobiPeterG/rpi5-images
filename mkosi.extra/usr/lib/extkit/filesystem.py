"""Filesystem transactions and bounded streaming primitives."""

import fcntl
import hashlib
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

from .errors import PublicationError


_locks = threading.local()


@contextmanager
def locked_state(directory):
    key = str(directory.resolve())
    held = getattr(_locks, "held", None)
    if held is None:
        held = _locks.held = set()
    if key in held:
        yield
        return
    directory.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(directory / ".extkit.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        held.add(key)
        try:
            yield
        finally:
            held.remove(key)


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def state_transaction(function):
    @wraps(function)
    def transaction(config, *args, **kwargs):
        with locked_state(config.state):
            return function(config, *args, **kwargs)
    return transaction


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally: os.close(descriptor)


@contextmanager
def atomic_output(destination):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.'+destination.name+'.', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            yield stream
            stream.flush()
            stream.close()
            publish_file(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)


def atomic_json(destination, value):
    with atomic_output(destination) as output:
        output.write(json_bytes(value))


def atomic_copy(source, destination):
    import shutil
    with open(source, 'rb') as input, atomic_output(destination) as output:
        shutil.copyfileobj(input, output, 1024*1024)


@contextmanager
def staged_copy(source, destination):
    """Prepare a durable copy beside its destination without publishing it."""
    import shutil
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.publish-', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            with Path(source).open('rb') as source_stream:
                shutil.copyfileobj(source_stream, stream, 1024 * 1024)
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
            yield temporary
        finally:
            temporary.unlink(missing_ok=True)


def publish_file(source, destination):
    """Publish an already-written same-filesystem artifact, with durable rename."""
    source, destination = Path(source), Path(destination)
    with source.open('rb') as stream:
        os.fsync(stream.fileno())
    os.replace(source, destination)
    try:
        fsync_directory(destination.parent)
    except OSError as error:
        raise PublicationError(destination, error) from error


@contextmanager
def artifact_locks(config, paths):
    from contextlib import ExitStack
    directory = config.state / 'locks'
    directory.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        for name in sorted({hashlib.sha256(str(Path(path).resolve()).encode()).hexdigest() for path in paths}):
            descriptor = os.open(directory / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            stream = stack.enter_context(os.fdopen(descriptor, 'a'))
            fcntl.flock(stream, fcntl.LOCK_EX)
        yield
