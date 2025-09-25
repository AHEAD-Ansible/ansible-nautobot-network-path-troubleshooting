"""Step 4: iterative path tracing with ECMP support."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import List, Optional, Set

from ..config import NetworkPathSettings
from ..exceptions import PathTracingError, NextHopDiscoveryError
from ..interfaces.nautobot import NautobotDataSource, IPAddressRecord, PrefixRecord
from .gateway_discovery import GatewayDiscoveryResult
from .input_validation import InputValidationResult
from .next_hop_discovery import NextHopDiscoveryResult, NextHopDiscoveryStep


@dataclass(frozen=True)
class PathHop:
    """Represents a single hop in the path."""
    device_name: Optional[str]
    interface_name: Optional[str]
    next_hop_ip: Optional[str]
    egress_interface: Optional[str]
    details: Optional[str]


@dataclass(frozen=True)
class Path:
    """Represents a single traced path."""
    hops: List[PathHop]
    reached_destination: bool
    issues: List[str]


@dataclass(frozen=True)
class PathTracingResult:
    """Outcome of the path tracing workflow."""
    paths: List[Path]
    issues: List[str]


class PathTracingStep:
    """Trace the full path from gateway to destination, handling ECMP."""
    def __init__(
        self,
        data_source: NautobotDataSource,
        settings: NetworkPathSettings,
        next_hop_step: NextHopDiscoveryStep,
        logger: Optional[logging.Logger] = None,
    ):
        self._data_source = data_source
        self._settings = settings
        self._max_hops = 10
        self._max_failed_hops = 3
        self._logger = logger
        self._next_hop_step = next_hop_step

    def run(self, validation: InputValidationResult, gateway: GatewayDiscoveryResult) -> PathTracingResult:
        """Execute the path tracing workflow."""
        if not gateway.found or not gateway.gateway:
            raise PathTracingError("No gateway available to start path tracing")
        paths = []
        issues = []
        seen_devices: Set[str] = set()
        self._trace_path(
            current_device=gateway.gateway.device_name,
            current_interface=gateway.gateway.interface_name,
            destination_ip=validation.destination_ip,
            current_hops=[],
            failed_hops=0,
            paths=paths,
            issues=issues,
            seen_devices=seen_devices
        )
        return PathTracingResult(paths=paths, issues=issues)

    def _trace_path(
        self,
        current_device: Optional[str],
        current_interface: Optional[str],
        destination_ip: str,
        current_hops: List[PathHop],
        failed_hops: int,
        paths: List[Path],
        issues: List[str],
        seen_devices: Set[str]
    ):
        """Recursively trace the path to the destination."""
        if not current_device:
            issues.append("No device found for hop; path terminated.")
            paths.append(Path(hops=current_hops, reached_destination=False, issues=issues[:]))
            return
        if len(current_hops) >= self._max_hops:
            issues.append(f"Maximum hop count ({self._max_hops}) exceeded.")
            paths.append(Path(hops=current_hops, reached_destination=False, issues=issues[:]))
            return
        if current_device in seen_devices:
            issues.append(f"Routing loop detected at device '{current_device}'.")
            paths.append(Path(hops=current_hops, reached_destination=False, issues=issues[:]))
            return
        seen_devices.add(current_device)
        if failed_hops >= self._max_failed_hops:
            issues.append(f"Too many failed hops ({failed_hops}); potential routing issue.")
            paths.append(Path(hops=current_hops, reached_destination=False, issues=issues[:]))
            return
        try:
            next_hop_result = self._next_hop_step.run(
                InputValidationResult(
                    source_ip=self._settings.source_ip,
                    destination_ip=destination_ip,
                    source_record=IPAddressRecord(address="", prefix_length=0, device_name=current_device, interface_name=current_interface),
                    source_prefix=PrefixRecord(prefix=""),
                    is_host_ip=False
                ),
                GatewayDiscoveryResult(found=True, method="path_tracing", gateway=IPAddressRecord(address="", prefix_length=0, device_name=current_device, interface_name=current_interface))
            )
        except NextHopDiscoveryError as exc:
            current_hops.append(PathHop(
                device_name=current_device,
                interface_name=current_interface,
                next_hop_ip=None,
                egress_interface=None,
                details=str(exc)
            ))
            issues.append(f"Next-hop lookup failed: {exc}")
            paths.append(Path(hops=current_hops, reached_destination=False, issues=issues[:]))
            return
        if not next_hop_result.found:
            current_hops.append(PathHop(
                device_name=current_device,
                interface_name=current_interface,
                next_hop_ip=None,
                egress_interface=None,
                details=next_hop_result.details
            ))
            issues.append("Routing blackhole detected: no next hop found.")
            paths.append(Path(hops=current_hops, reached_destination=False, issues=issues[:]))
            return
        for next_hop in next_hop_result.next_hops:
            next_hop_ip = next_hop["next_hop_ip"]
            egress_if = next_hop["egress_interface"]
            next_hop_record = self._data_source.get_ip_address(next_hop_ip) if next_hop_ip else None
            hop_entry = PathHop(
                device_name=current_device,
                interface_name=current_interface,
                next_hop_ip=next_hop_ip,
                egress_interface=egress_if,
                details=next_hop_result.details
            )
            current_hops.append(hop_entry)

            is_destination = False
            if next_hop_ip == destination_ip:
                is_destination = True
            elif self._is_destination_within_next_hop(next_hop_record, destination_ip):
                is_destination = True

            if is_destination:
                destination_hop = self._build_destination_hop(destination_ip)
                path_hops = current_hops[:]
                if destination_hop:
                    path_hops.append(destination_hop)
                paths.append(Path(hops=path_hops, reached_destination=True, issues=issues[:]))
                current_hops.pop()
                continue

            next_device = next_hop_record.device_name if next_hop_record else None
            next_interface = next_hop_record.interface_name if next_hop_record else egress_if
            self._trace_path(
                current_device=next_device,
                current_interface=next_interface,
                destination_ip=destination_ip,
                current_hops=current_hops[:],
                failed_hops=failed_hops + (1 if not next_device else 0),
                paths=paths,
                issues=issues,
                seen_devices=seen_devices.copy()
            )
            current_hops.pop()

    def _is_destination_within_next_hop(
        self,
        next_hop_record: Optional[IPAddressRecord],
        destination_ip: str,
    ) -> bool:
        """Return True if destination IP resides on the same subnet as the next hop."""

        if not next_hop_record or not next_hop_record.address or not next_hop_record.prefix_length:
            return False
        try:
            network = ipaddress.ip_network(
                f"{next_hop_record.address}/{next_hop_record.prefix_length}",
                strict=False,
            )
            return ipaddress.ip_address(destination_ip) in network
        except ValueError:
            return False

    def _build_destination_hop(self, destination_ip: str) -> Optional[PathHop]:
        """Construct the final hop describing the destination device."""

        dest_record = self._data_source.get_ip_address(destination_ip)
        if dest_record:
            details = "Destination device resolved via Nautobot"
            return PathHop(
                device_name=dest_record.device_name,
                interface_name=dest_record.interface_name,
                next_hop_ip=destination_ip,
                egress_interface=None,
                details=details,
            )

        return PathHop(
            device_name="device_info: Not Found",
            interface_name=None,
            next_hop_ip=destination_ip,
            egress_interface=None,
            details="Destination device info not found in Nautobot",
        )
