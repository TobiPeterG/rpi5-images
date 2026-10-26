"""Authenticated authority information and session capability ownership."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Service:
    name: str
    address: str
    port: int


@dataclass(frozen=True)
class Phone:
    service: Service
    transport_certificate: bytes
    extension_certificate: bytes
    boot_certificate: bytes
    extension_fingerprint: str
    enrolled: bool


@dataclass(frozen=True)
class PhoneSession:
    phone: Phone
    token: str = field(repr=False)
