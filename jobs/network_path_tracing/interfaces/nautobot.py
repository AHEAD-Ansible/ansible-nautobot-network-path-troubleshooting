"""Abstractions over Nautobot lookups used by the path tracing logic."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol, Union


@dataclass
class IPAddressRecord:
    """Minimum data required from a Nautobot IPAddress record."""
    address: str
    prefix_length: int
    device_name: Optional[str] = None
    interface_name: Optional[str] = None


@dataclass
class PrefixRecord:
    """Minimal representation of a Nautobot Prefix object."""
    prefix: str
    status: Optional[str] = None
    id: Optional[str] = None


@dataclass
class DeviceRecord:
    """Minimal representation of a Nautobot Device object."""
    name: str
    primary_ip: Optional[str] = None
    platform_slug: Optional[str] = None
    platform_name: Optional[str] = None
    napalm_driver: Optional[str] = None


@dataclass(frozen=True)
class RedundancyMember:
    """Represent a member of an interface redundancy group."""
    device_name: Optional[str]
    interface_name: Optional[str]
    priority: Optional[int] = None
    is_preferred: bool = False


@dataclass(frozen=True)
class RedundancyResolution:
    """Preferred redundancy member alongside the full membership list."""
    preferred: IPAddressRecord
    members: tuple[RedundancyMember, ...] = field(default_factory=tuple)


class NautobotDataSource(Protocol):
    """Protocol for retrieving Nautobot data without binding to ORM internals."""
    def get_ip_address(self, address: str) -> Optional[IPAddressRecord]:
        """Return the IPAddress record for ``address`` if it exists."""
    def get_most_specific_prefix(self, address: str) -> Optional[PrefixRecord]:
        """Return the most specific prefix containing the supplied address."""
    def find_gateway_ip(self, prefix: PrefixRecord, custom_field: str) -> Optional[IPAddressRecord]:
        """Return the gateway IP within ``prefix`` tagged via ``custom_field`` if present."""
    def get_device(self, name: str) -> Optional[DeviceRecord]:
        """Return the Device record for ``name`` if it exists."""
    def get_interface_ip(self, device_name: str, interface_name: str) -> Optional[IPAddressRecord]:
        """Return IP information for ``device_name``/``interface_name`` if available."""
    def resolve_redundant_gateway(
        self, address: str
    ) -> Optional[Union[RedundancyResolution, IPAddressRecord]]:
        """Return gateway details derived from interface redundancy groups (HSRP/VRRP)."""
