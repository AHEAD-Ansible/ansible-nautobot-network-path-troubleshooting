"""Step 4: iterative path tracing with ECMP support."""

from __future__ import annotations

import ipaddress
import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ..config import NetworkPathSettings
from ..exceptions import PathTracingError, NextHopDiscoveryError
from ..interfaces.nautobot import (
    NautobotDataSource,
    IPAddressRecord,
    PrefixRecord,
    RedundancyMember,
)
from .gateway_discovery import GatewayDiscoveryResult
from .input_validation import InputValidationResult
from .next_hop_discovery import NextHopDiscoveryStep
from ..graph import NetworkPathGraph


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
    graph: Optional[NetworkPathGraph] = None


@dataclass
class TraceState:
    """BFS traversal state for graph-based path tracing."""
    device_name: Optional[str]
    interface_name: Optional[str]
    path_hops: List[PathHop] = field(default_factory=list)
    path_issues: List[str] = field(default_factory=list)
    failed_hops: int = 0
    visited: Set[Tuple[str, str]] = field(default_factory=set)  # Changed to track (device, interface) for intra-device handling


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
        self._latest_graph: Optional[NetworkPathGraph] = None
        self._completed_paths: List[Path] = []
        self._path_signatures: Set[Tuple[Any, ...]] = set()

    def run(self, validation: InputValidationResult, gateway: GatewayDiscoveryResult) -> PathTracingResult:
        """Execute the path tracing workflow."""
        if not gateway.found or not gateway.gateway:
            raise PathTracingError("No gateway available to start path tracing")
        graph = NetworkPathGraph()
        self._latest_graph = graph

        start_device = gateway.gateway.device_name
        start_interface = gateway.gateway.interface_name
        start_node_id = self._node_id_for_device(start_device)
        graph.mark_start(
            graph.ensure_node(
                start_node_id,
                label=start_device or "start",
                device_name=start_device,
                interface=start_interface,
                ip_address=gateway.gateway.address,
            )
        )

        source_node_id = self._add_source_node(graph, validation, start_node_id, start_interface)
        self._integrate_redundant_gateways(graph, gateway, start_node_id, source_node_id)

        self._completed_paths = []
        self._path_signatures = set()

        queue: deque[TraceState] = deque(
            [
                TraceState(
                    device_name=start_device,
                    interface_name=start_interface,
                    path_hops=[],
                    path_issues=[],
                    failed_hops=0,
                    visited=set(),
                )
            ]
        )

        aggregate_issues: List[str] = []

        destination_ip = validation.destination_ip

        while queue:
            state = queue.popleft()
            self._process_state(
                state=state,
                destination_ip=destination_ip,
                graph=graph,
                aggregate_issues=aggregate_issues,
                queue=queue,
            )

        success_paths = [path for path in self._completed_paths if path.reached_destination]
        failure_paths = [path for path in self._completed_paths if not path.reached_destination]

        final_paths = success_paths + failure_paths

        return PathTracingResult(paths=final_paths, issues=aggregate_issues, graph=graph)

    @property
    def latest_graph(self) -> Optional[NetworkPathGraph]:
        """Return the last-built graph (for CLI visualisations)."""

        return self._latest_graph

    def _process_state(
        self,
        *,
        state: TraceState,
        destination_ip: str,
        graph: NetworkPathGraph,
        aggregate_issues: List[str],
        queue: deque[TraceState],
    ) -> None:
        device_name = state.device_name
        interface_name = state.interface_name

        current_hops = list(state.path_hops)
        path_issues = list(state.path_issues)

        if not device_name:
            self._record_issue(path_issues, aggregate_issues, "No device found for hop; path terminated.")
            self._finalize_path(current_hops, path_issues, reached=False)
            return

        if len(current_hops) >= self._max_hops:
            self._record_issue(
                path_issues,
                aggregate_issues,
                f"Maximum hop count ({self._max_hops}) exceeded.",
            )
            self._finalize_path(current_hops, path_issues, reached=False)
            return

        visited_key = (device_name, interface_name or "")
        if visited_key in state.visited:
            self._record_issue(
                path_issues,
                aggregate_issues,
                f"Routing loop detected at device '{device_name}' interface '{interface_name}'.",
            )
            self._finalize_path(current_hops, path_issues, reached=False)
            return

        if state.failed_hops >= self._max_failed_hops:
            self._record_issue(
                path_issues,
                aggregate_issues,
                f"Too many failed hops ({state.failed_hops}); potential routing issue.",
            )
            self._finalize_path(current_hops, path_issues, reached=False)
            return

        visited = set(state.visited)
        visited.add(visited_key)

        # Check if current device is the destination
        dest_record = self._data_source.get_ip_address(destination_ip)
        if dest_record and dest_record.device_name == device_name:
            hop_entry = PathHop(
                device_name=device_name,
                interface_name=interface_name,
                next_hop_ip=destination_ip,
                egress_interface=dest_record.interface_name,
                details="Reached destination on current device (local route)."
            )
            path_hops = current_hops + [hop_entry]
            self._finalize_path(path_hops, path_issues, reached=True)

            dest_node_id = self._node_id_for_destination(device_name, destination_ip)
            graph.mark_destination(
                graph.ensure_node(
                    dest_node_id,
                    label=device_name or destination_ip,
                    device_name=device_name,
                    ip_address=destination_ip,
                )
            )
            node_id = self._node_id_for_device(device_name)
            graph.add_edge(
                node_id,
                dest_node_id,
                local_route=True,
                details=hop_entry.details,
            )
            return

        node_id = self._node_id_for_device(device_name)
        label = device_name or node_id
        node_attrs: Dict[str, Any] = {
            "label": label,
            "device_name": device_name,
        }
        if interface_name:
            node_attrs.setdefault("interfaces", [])
        graph.ensure_node(node_id, **node_attrs)
        if interface_name:
            self._append_unique(graph.graph.nodes[node_id].setdefault("interfaces", []), interface_name)

        try:
            next_hop_result = self._next_hop_step.run(
                self._build_state_validation(destination_ip, device_name, interface_name),
                self._build_state_gateway(device_name, interface_name),
            )
        except NextHopDiscoveryError as exc:
            hop = PathHop(
                device_name=device_name,
                interface_name=interface_name,
                next_hop_ip=None,
                egress_interface=None,
                details=str(exc),
            )
            current_hops.append(hop)
            self._record_issue(path_issues, aggregate_issues, f"Next-hop lookup failed: {exc}")
            self._finalize_path(current_hops, path_issues, reached=False)
            graph.ensure_node(node_id, error=str(exc))
            return

        if not next_hop_result.found:
            hop = PathHop(
                device_name=device_name,
                interface_name=interface_name,
                next_hop_ip=None,
                egress_interface=None,
                details=next_hop_result.details,
            )
            current_hops.append(hop)
            self._record_issue(path_issues, aggregate_issues, "Routing blackhole detected: no next hop found.")
            self._finalize_path(current_hops, path_issues, reached=False)
            graph.ensure_node(node_id, blackhole=True)
            return

        for next_hop in next_hop_result.next_hops:
            next_hop_ip = next_hop.get("next_hop_ip")
            egress_interface = next_hop.get("egress_interface")

            # Handle local route if next_hop_ip is None or indicator of local
            if next_hop_ip in (None, '', 'local', '0.0.0.0'):
                if dest_record and dest_record.device_name == device_name:
                    hop_entry = PathHop(
                        device_name=device_name,
                        interface_name=interface_name,
                        next_hop_ip=destination_ip,
                        egress_interface=egress_interface,
                        details="Local route to destination."
                    )
                    path_hops = current_hops + [hop_entry]
                    self._finalize_path(path_hops, path_issues, reached=True)

                    dest_node_id = self._node_id_for_destination(device_name, destination_ip)
                    graph.mark_destination(
                        graph.ensure_node(
                            dest_node_id,
                            label=device_name or destination_ip,
                            device_name=device_name,
                            ip_address=destination_ip,
                        )
                    )
                    graph.add_edge(
                        node_id,
                        dest_node_id,
                        local_route=True,
                        details=hop_entry.details,
                    )
                    continue
                if self._is_destination_on_interface(device_name, egress_interface, destination_ip):
                    hop_entry = PathHop(
                        device_name=device_name,
                        interface_name=interface_name,
                        next_hop_ip=destination_ip,
                        egress_interface=egress_interface,
                        details=f"Destination within subnet of interface '{egress_interface}'.",
                    )
                    destination_hop = self._build_destination_hop(destination_ip)
                    dest_node_id = self._node_id_for_destination(
                        destination_hop.device_name if destination_hop else None,
                        destination_ip,
                    )
                    graph.mark_destination(
                        graph.ensure_node(
                            dest_node_id,
                            label=(destination_hop.device_name if destination_hop else destination_ip),
                            device_name=destination_hop.device_name if destination_hop else None,
                            ip_address=destination_ip,
                            destination_hop=destination_hop,
                        )
                    )
                    graph.add_edge(
                        node_id,
                        dest_node_id,
                        hop=hop_entry,
                        next_hop_ip=destination_ip,
                        egress_interface=egress_interface,
                        details=hop_entry.details,
                    )
                    path_hops = current_hops + [hop_entry]
                    if destination_hop:
                        path_hops.append(destination_hop)
                    self._finalize_path(path_hops, path_issues, reached=True)
                    continue
                else:
                    # Not local, treat as failure
                    hop = PathHop(
                        device_name=device_name,
                        interface_name=interface_name,
                        next_hop_ip=None,
                        egress_interface=egress_interface,
                        details="No next hop; possible blackhole."
                    )
                    current_hops.append(hop)
                    self._record_issue(path_issues, aggregate_issues, "Routing blackhole detected.")
                    self._finalize_path(current_hops, path_issues, reached=False)
                    continue

            next_hop_record = self._data_source.get_ip_address(next_hop_ip) if next_hop_ip else None

            hop_entry = PathHop(
                device_name=device_name,
                interface_name=interface_name,
                next_hop_ip=next_hop_ip,
                egress_interface=egress_interface,
                details=next_hop_result.details,
            )

            next_device_name = next_hop_record.device_name if next_hop_record else None
            next_interface = next_hop_record.interface_name if next_hop_record else egress_interface

            is_destination = False
            if next_hop_ip == destination_ip:
                is_destination = True
            elif self._is_destination_within_next_hop(next_hop_record, destination_ip):
                is_destination = True

            target_node_id: str
            if is_destination:
                destination_hop = self._build_destination_hop(destination_ip)
                dest_node_id = self._node_id_for_destination(destination_hop.device_name, destination_ip)
                graph.mark_destination(
                    graph.ensure_node(
                        dest_node_id,
                        label=destination_hop.device_name or destination_ip,
                        device_name=destination_hop.device_name,
                        ip_address=destination_ip,
                        destination_hop=destination_hop,
                    )
                )
                graph.add_edge(
                    node_id,
                    dest_node_id,
                    hop=hop_entry,
                    next_hop_ip=next_hop_ip,
                    egress_interface=egress_interface,
                    details=next_hop_result.details,
                )
                path_hops = current_hops + [hop_entry]
                if destination_hop:
                    path_hops.append(destination_hop)
                self._finalize_path(path_hops, path_issues, reached=True)
                continue

            target_node_id = self._node_id_for_next_hop(
                graph=graph,
                source_node_id=node_id,
                device_name=next_device_name,
                next_hop_ip=next_hop_ip,
                egress_interface=egress_interface,
            )

            graph.ensure_node(
                target_node_id,
                label=next_device_name or next_hop_ip or target_node_id,
                device_name=next_device_name,
                ip_address=next_hop_ip,
            )
            if next_interface:
                self._append_unique(
                    graph.graph.nodes[target_node_id].setdefault("interfaces", []),
                    next_interface,
                )

            graph.add_edge(
                node_id,
                target_node_id,
                hop=hop_entry,
                next_hop_ip=next_hop_ip,
                egress_interface=egress_interface,
                details=next_hop_result.details,
            )

            updated_failed_hops = state.failed_hops + (0 if next_device_name else 1)
            if updated_failed_hops > self._max_failed_hops:
                branch_issues = list(path_issues)
                self._record_issue(
                    branch_issues,
                    aggregate_issues,
                    f"Too many failed hops ({updated_failed_hops}); potential routing issue.",
                )
                self._finalize_path(
                    current_hops + [hop_entry],
                    branch_issues,
                    reached=False,
                )
                continue

            queue_state = TraceState(
                device_name=next_device_name,
                interface_name=next_interface,
                path_hops=current_hops + [hop_entry],
                path_issues=list(path_issues),
                failed_hops=updated_failed_hops,
                visited=visited,
            )
            queue.append(queue_state)

    def _add_source_node(
        self,
        graph: NetworkPathGraph,
        validation: InputValidationResult,
        start_node_id: str,
        start_interface: Optional[str],
    ) -> Optional[str]:
        """Ensure source device appears in the graph for visualization."""

        record = validation.source_record
        identifier = record.device_name or record.address or validation.source_ip
        if not identifier:
            return None

        node_id = f"source::{identifier}"
        label = record.device_name or identifier
        node_attrs: Dict[str, Any] = {
            "label": label,
            "device_name": record.device_name,
            "ip_address": record.address,
            "role": "source",
        }
        if record.interface_name:
            node_attrs["interfaces"] = [record.interface_name]
        graph.ensure_node(node_id, **node_attrs)

        if node_id != start_node_id:
            graph.add_edge(
                node_id,
                start_node_id,
                relation="source->gateway",
                source_interface=record.interface_name,
                target_interface=start_interface,
            )

        return node_id

    def _integrate_redundant_gateways(
        self,
        graph: NetworkPathGraph,
        gateway: GatewayDiscoveryResult,
        start_node_id: str,
        source_node_id: Optional[str],
    ) -> None:
        """Add redundancy members (e.g., HSRP peers) to the visualization graph."""

        members = getattr(gateway, "redundant_members", None) or ()
        if not members:
            return

        preferred_node_id = start_node_id
        member_nodes: list[tuple[RedundancyMember, str]] = []

        for member in members:
            if not member.device_name:
                continue
            node_id = self._node_id_for_device(member.device_name)
            node_attrs: Dict[str, Any] = {
                "label": member.device_name,
                "device_name": member.device_name,
                "redundancy_member": True,
            }
            graph.ensure_node(node_id, **node_attrs)
            if member.interface_name:
                self._append_unique(
                    graph.graph.nodes[node_id].setdefault("interfaces", []),
                    member.interface_name,
                )
            if member.priority is not None:
                graph.graph.nodes[node_id]["redundancy_priority"] = member.priority
            if member.is_preferred:
                preferred_node_id = node_id
            member_nodes.append((member, node_id))

        for member, node_id in member_nodes:
            if member.is_preferred:
                continue
            details = (
                f"Redundancy member (priority {member.priority})"
                if member.priority is not None
                else "Redundancy member"
            )
            edge_attrs = {
                "relation": "source->redundant_gateway",
                "redundancy": True,
                "redundancy_priority": member.priority,
                "redundancy_preferred": False,
                "dashed": True,
                "details": details,
                "egress_interface": (
                    f"prio {member.priority}"
                    if member.priority is not None
                    else "standby"
                ),
            }
            if source_node_id and source_node_id != node_id:
                graph.add_edge(source_node_id, node_id, **edge_attrs)
            if preferred_node_id and preferred_node_id != node_id:
                graph.add_edge(
                    node_id,
                    preferred_node_id,
                    relation="redundancy-link",
                    redundancy=True,
                    redundancy_priority=member.priority,
                    redundancy_preferred=False,
                    dashed=True,
                    details=details,
                )

    def _build_state_validation(
        self,
        destination_ip: str,
        device_name: Optional[str],
        interface_name: Optional[str],
    ) -> InputValidationResult:
        """Create a minimal validation object for iterative lookups."""

        return InputValidationResult(
            source_ip=self._settings.source_ip,
            destination_ip=destination_ip,
            source_record=IPAddressRecord(
                address="",
                prefix_length=0,
                device_name=device_name,
                interface_name=interface_name,
            ),
            source_prefix=PrefixRecord(prefix=""),
            is_host_ip=False,
        )

    @staticmethod
    def _build_state_gateway(
        device_name: Optional[str], interface_name: Optional[str]
    ) -> GatewayDiscoveryResult:
        """Reuse GatewayDiscoveryResult structure for iterative trace."""

        return GatewayDiscoveryResult(
            found=True,
            method="graph_tracing",
            gateway=IPAddressRecord(
                address="",
                prefix_length=0,
                device_name=device_name,
                interface_name=interface_name,
            ),
            details="graph traversal",
        )

    @staticmethod
    def _append_unique(container: List[str], value: Optional[str]) -> None:
        """Append value to list if present and not already stored."""

        if value and value not in container:
            container.append(value)

    @staticmethod
    def _record_issue(
        path_issues: List[str], aggregate: List[str], message: str
    ) -> None:
        """Track issues per-path and at the aggregate level."""

        if message not in path_issues:
            path_issues.append(message)
        if message not in aggregate:
            aggregate.append(message)

    def _finalize_path(
        self, hops: List[PathHop], issues: List[str], reached: bool
    ) -> None:
        """Append a finished path to the internal collection."""

        signature = tuple(
            (
                hop.device_name,
                hop.interface_name,
                hop.next_hop_ip,
                hop.egress_interface,
                hop.details,
            )
            for hop in hops
        ) + (reached,)
        if signature in self._path_signatures:
            return
        self._path_signatures.add(signature)
        self._completed_paths.append(
            Path(
                hops=list(hops),
                reached_destination=reached,
                issues=list(issues),
            )
        )

    @staticmethod
    def _node_id_for_device(device_name: Optional[str]) -> str:
        """Return a graph node identifier for a device."""

        return device_name or "unknown-device"

    @staticmethod
    def _node_id_for_destination(device_name: Optional[str], destination_ip: str) -> str:
        """Return an identifier for the destination node."""

        if device_name and device_name != "device_info: Not Found":
            return device_name
        return f"destination::{destination_ip}"

    def _node_id_for_next_hop(
        self,
        *,
        graph: NetworkPathGraph,
        source_node_id: str,
        device_name: Optional[str],
        next_hop_ip: Optional[str],
        egress_interface: Optional[str],
    ) -> str:
        """Determine the node id for the next hop candidate."""

        if device_name:
            return self._node_id_for_device(device_name)
        if next_hop_ip:
            return f"{source_node_id}::ip::{next_hop_ip}"
        if egress_interface:
            return f"{source_node_id}::if::{egress_interface}"
        return f"{source_node_id}::unknown::{graph.graph.number_of_nodes()}"

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

    def _is_destination_on_interface(
        self,
        device_name: Optional[str],
        interface_name: Optional[str],
        destination_ip: str,
    ) -> bool:
        """Return True if ``destination_ip`` lies within the interface's subnet."""

        if not device_name or not interface_name:
            return False

        interface_record = self._data_source.get_interface_ip(device_name, interface_name)
        if not interface_record or not interface_record.address or not interface_record.prefix_length:
            return False

        try:
            network = ipaddress.ip_network(
                f"{interface_record.address}/{interface_record.prefix_length}",
                strict=False,
            )
        except ValueError:
            return False

        try:
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
