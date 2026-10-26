"""Expected failures."""

from typing import NoReturn


class ExtkitError(ValueError):
    pass


class ConfigurationError(ExtkitError):
    pass


class ArtifactFormatError(ExtkitError):
    pass


class VerificationError(ExtkitError):
    pass


class TransferError(ExtkitError):
    pass


class RequestRejected(TransferError):
    pass


class BatchSigningError(TransferError):
    def __init__(self, message, outcomes):
        self.outcomes = tuple(outcomes)
        super().__init__(message)


class InstallationError(ExtkitError):
    pass


class PublicationError(OSError):
    """Replacement happened, but its directory durability could not be confirmed."""

    def __init__(self, destination, error):
        self.destination = destination
        self.replaced = True
        super().__init__(f'{destination} was replaced, but directory synchronization failed: {error}')


def fail(message) -> NoReturn:
    raise ArtifactFormatError(message)


def transfer_fail(message) -> NoReturn:
    raise TransferError(message)


def verification_fail(message) -> NoReturn:
    raise VerificationError(message)


def installation_fail(message) -> NoReturn:
    raise InstallationError(message)
