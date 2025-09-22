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


class InputValidationStep:
    """Validate source/destination inputs and retrieve the source subnet."""

    def __init__(self, data_source: NautobotDataSource) -> None:
        self._data_source = data_source

    def run(self, settings: Optional[NetworkPathSettings] = None) -> InputValidationResult:
        """Execute the validation workflow using the provided settings."""

        settings = settings or NetworkPathSettings()

        source_ip = self._normalise_ip(settings.source_ip, "source")
        destination_ip = self._normalise_ip(settings.destination_ip, "destination")

        source_record = self._require_ip_record(source_ip)
        source_prefix = self._require_prefix(source_ip)

        is_host_ip = source_record.prefix_length == 32

        return InputValidationResult(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_record=source_record,
            source_prefix=source_prefix,
            is_host_ip=is_host_ip,
        )

    def _normalise_ip(self, candidate: str, role: str) -> str:
        """Normalise user input to a canonical IPv4/IPv6 string."""

        if not candidate:
            raise InputValidationError(f"Missing {role} IP address")

        try:
            # Preserve canonical host formatting (no netmask).
            return str(ipaddress.ip_address(candidate.split("/")[0]))
        except ValueError as exc:
            raise InputValidationError(f"Invalid {role} IP '{candidate}': {exc}") from exc

    def _require_ip_record(self, address: str) -> IPAddressRecord:
        record = self._data_source.get_ip_address(address)
        if record is None:
            raise InputValidationError(
                f"Source IP {address} not found in Nautobot; please register it in IPAM."
            )
        return record

    def _require_prefix(self, address: str) -> PrefixRecord:
        prefix = self._data_source.get_most_specific_prefix(address)
        if prefix is None:
            raise InputValidationError(
                "No containing prefix found for source IP; update Nautobot prefixes."
            )
        return prefix
