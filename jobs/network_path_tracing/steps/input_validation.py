"""Implementation of Step 1 from the high-level design: input validation."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Optional

from ..config import NetworkPathSettings
from ..exceptions import InputValidationError
from ..interfaces.nautobot import IPAddressRecord, NautobotDataSource, PrefixRecord


@dataclass(frozen=True)
class InputValidationResult:
    """Normalized output of the input validation step."""
    source_ip: str
    destination_ip: str
    source_record: IPAddressRecord
    source_prefix: PrefixRecord
    is_host_ip: bool
    source_found: bool = True


class InputValidationStep:
    """Validate source/destination inputs and retrieve the source subnet."""
    def __init__(self, data_source: NautobotDataSource) -> None:
        self._data_source = data_source

    def run(self, settings: Optional[NetworkPathSettings] = None) -> InputValidationResult:
        """Execute the validation workflow using the provided settings."""
        settings = settings or NetworkPathSettings()
        source_ip = self._normalise_ip(settings.source_ip, "source")
        destination_ip = self._normalise_ip(settings.destination_ip, "destination")
        source_prefix = self._require_prefix(source_ip)
        source_record = self._data_source.get_ip_address(source_ip)
        source_found = source_record is not None
        if not source_found:
            prefix_length = ipaddress.ip_network(source_prefix.prefix).prefixlen
            source_record = IPAddressRecord(
                address=source_ip,
                prefix_length=prefix_length,
                device_name=None,
                interface_name=None,
            )
        is_host_ip = source_found and source_record.prefix_length == 32
        return InputValidationResult(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_record=source_record,
            source_prefix=source_prefix,
            is_host_ip=is_host_ip,
            source_found=source_found,
        )

    def _normalise_ip(self, candidate: str, role: str) -> str:
        """Normalize user input to a canonical IPv4/IPv6 string."""
        if not candidate:
            raise InputValidationError(f"Missing {role} IP address")
        try:
            return str(ipaddress.ip_address(candidate.split("/")[0]))
        except ValueError as exc:
            raise InputValidationError(f"Invalid {role} IP '{candidate}': {exc}") from exc

    def _require_prefix(self, address: str) -> PrefixRecord:
        """Ensure a prefix exists for the IP address."""
        prefix = self._data_source.get_most_specific_prefix(address)
        if prefix is None:
            raise InputValidationError(
                "No containing prefix found for source IP; update Nautobot prefixes."
            )
        return prefix
