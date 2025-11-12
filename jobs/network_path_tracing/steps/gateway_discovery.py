"""Step 2: default gateway discovery within the source prefix."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Optional, Tuple

from ..exceptions import GatewayDiscoveryError
from ..interfaces.nautobot import (
    IPAddressRecord,
    NautobotDataSource,
    RedundancyMember,
    RedundancyResolution,
)
from .input_validation import InputValidationResult


@dataclass(frozen=True)
class GatewayDiscoveryResult:
    """Outcome of the gateway discovery workflow."""
    found: bool
    method: str
    gateway: Optional[IPAddressRecord]
    details: Optional[str] = None
    redundant_members: tuple[RedundancyMember, ...] = ()


class GatewayDiscoveryStep:
    """Locate the default gateway for the validated source prefix."""
    def __init__(self, data_source: NautobotDataSource, custom_field: str) -> None:
        self._data_source = data_source
        self._custom_field = custom_field

    def run(self, validation: InputValidationResult) -> GatewayDiscoveryResult:
        """Locate the gateway IP, falling back to the lowest usable host."""
        if validation.is_host_ip:
            return GatewayDiscoveryResult(
                found=True,
                method="direct_host",
                gateway=validation.source_record,
                details="Source IP is a /32; using it as the entry point.",
            )

        gateway_record = self._data_source.find_gateway_ip(
            validation.source_prefix, self._custom_field
        )
        if gateway_record:
            adjusted_record, method, details, members = self._resolve_gateway_via_redundancy(gateway_record)
            return GatewayDiscoveryResult(
                found=True,
                method=method,
                gateway=adjusted_record,
                details=details,
                redundant_members=members,
            )

        fallback_record, from_nautobot = self._fallback_to_lowest_host(validation)
        if fallback_record:
            original_device = fallback_record.device_name
            adjusted_record, _, _, members = self._resolve_gateway_via_redundancy(fallback_record)
            detail_parts = ["Used lowest usable IP address as the gateway fallback."]
            if not from_nautobot:
                detail_parts.append("Address not present in Nautobot.")
            if members or (not original_device and adjusted_record.device_name):
                detail_parts.append("Resolved gateway interface via interface redundancy groups.")
            elif adjusted_record.device_name and adjusted_record.interface_name:
                detail_parts.append(
                    f"Resolved to device '{adjusted_record.device_name}' interface '{adjusted_record.interface_name}'."
                )
            details = " ".join(detail_parts)
            return GatewayDiscoveryResult(
                found=True,
                method="lowest_host",
                gateway=adjusted_record,
                details=details,
                redundant_members=members,
            )

        raise GatewayDiscoveryError(
            "No default gateway found. Ensure a gateway IP is tagged or present in Nautobot."
        )

    def _fallback_to_lowest_host(
        self, validation: InputValidationResult
    ) -> tuple[Optional[IPAddressRecord], bool]:
        """Fall back to the lowest usable host IP in the prefix."""
        network = ipaddress.ip_network(validation.source_prefix.prefix)
        if network.version == 4 and network.prefixlen >= 30:
            return None, False
        try:
            first_host = next(network.hosts())
        except StopIteration:
            return None, False
        ip_str = str(first_host)
        record = self._data_source.get_ip_address(ip_str)
        if record:
            return record, True
        return (
            IPAddressRecord(
                address=ip_str,
                prefix_length=network.prefixlen,
                device_name=None,
                interface_name=None,
            ),
            False,
        )

    def _resolve_gateway_via_redundancy(
        self, gateway_record: IPAddressRecord
    ) -> tuple[IPAddressRecord, str, str, tuple[RedundancyMember, ...]]:
        """Optionally enrich gateway details using interface redundancy (HSRP/VRRP)."""

        method = "custom_field"
        details = f"Gateway tagged via custom field '{self._custom_field}'."
        record = gateway_record
        members: tuple[RedundancyMember, ...] = ()

        if record.device_name and record.interface_name:
            return record, method, details, members

        redundancy_resolver = getattr(self._data_source, "resolve_redundant_gateway", None)
        if callable(redundancy_resolver) and record.address:
            try:
                redundant_record = redundancy_resolver(record.address)
            except Exception:  # pragma: no cover - data source specific errors
                redundant_record = None
            if isinstance(redundant_record, RedundancyResolution):
                preferred = redundant_record.preferred
                if not preferred.prefix_length and record.prefix_length:
                    preferred.prefix_length = record.prefix_length
                method = "hsrp"
                details = (
                    f"Gateway tagged via custom field and resolved to interface redundancy member "
                    f"with the highest configured priority for IP {record.address}."
                )
                record = preferred
                members = redundant_record.members
            elif isinstance(redundant_record, IPAddressRecord):
                if not redundant_record.prefix_length and record.prefix_length:
                    redundant_record.prefix_length = record.prefix_length
                method = "hsrp"
                details = (
                    f"Gateway tagged via custom field and resolved to interface redundancy member "
                    f"with the highest configured priority for IP {record.address}."
                )
                record = redundant_record

        return record, method, details, members
