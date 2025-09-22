"""Step 2: default gateway discovery within the source prefix."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Optional

from ..exceptions import GatewayDiscoveryError
from ..interfaces.nautobot import IPAddressRecord, NautobotDataSource
from .input_validation import InputValidationResult


@dataclass(frozen=True)
class GatewayDiscoveryResult:
    """Outcome of the gateway discovery workflow."""
    found: bool
    method: str
    gateway: Optional[IPAddressRecord]
    details: Optional[str] = None


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
            return GatewayDiscoveryResult(
                found=True,
                method="custom_field",
                gateway=gateway_record,
                details=f"Gateway tagged via custom field '{self._custom_field}'.",
            )

        fallback_record = self._fallback_to_lowest_host(validation)
        if fallback_record:
            return GatewayDiscoveryResult(
                found=True,
                method="lowest_host",
                gateway=fallback_record,
                details="Used lowest usable IP address as the gateway fallback.",
            )

        raise GatewayDiscoveryError(
            "No default gateway found. Ensure a gateway IP is tagged or present in Nautobot."
        )

    def _fallback_to_lowest_host(
        self, validation: InputValidationResult
    ) -> Optional[IPAddressRecord]:
        """Fall back to the lowest usable host IP in the prefix."""
        network = ipaddress.ip_network(validation.source_prefix.prefix)
        if network.version == 4 and network.prefixlen >= 30:
            return None
        try:
            first_host = next(network.hosts())
        except StopIteration:
            return None
        return self._data_source.get_ip_address(str(first_host))