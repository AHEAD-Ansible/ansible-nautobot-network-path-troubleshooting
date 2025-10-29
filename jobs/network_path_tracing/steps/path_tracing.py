"""Step 4: iterative path tracing with ECMP support."""

from __future__ import annotations

import ipaddress
import logging
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ..config import NetworkPathSettings
from ..exceptions import PathTracingError, NextHopDiscoveryError, GatewayDiscoveryError
from ..interfaces.nautobot import (
    NautobotDataSource,
    IPAddressRecord,
    PrefixRecord,
    RedundancyMember,
)
from .gateway_discovery import GatewayDiscoveryResult, GatewayDiscoveryStep
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
    extras: Dict[str, Any] = field(default_factory=dict)
    hop_type: Optional[str] = None


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
class DeviceNodeAssignment:
    """Track node usage within a single path for duplicate control."""
    node_id: str
    last_index: int


@dataclass
class TraceState:
    """BFS traversal state for graph-based path tracing."""
    device_name: Optional[str]
    interface_name: Optional[str]
    hop_ip: Optional[str]
    path_hops: List[PathHop] = field(default_factory=list)
    path_issues: List[str] = field(default_factory=list)
    failed_hops: int = 0
    visited: Set[Tuple[str, str]] = field(default_factory=set)  # Changed to track (device, interface) for intra-device handling
    graph_node_id: Optional[str] = None
    device_nodes: Dict[str, List[DeviceNodeAssignment]] = field(default_factory=dict)


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
        self._destination_gateway: Optional[GatewayDiscoveryResult] = None
        self._destination_gateway_step: Optional[GatewayDiscoveryStep] = None
        self._node_sequence = 0

    def run(self, validation: InputValidationResult, gateway: GatewayDiscoveryResult) -> PathTracingResult:
        """Execute the path tracing workflow."""
        if not gateway.found or not gateway.gateway:
            raise PathTracingError("No gateway available to start path tracing")
        graph = NetworkPathGraph()
        self._latest_graph = graph

        start_device = gateway.gateway.device_name
        start_interface = gateway.gateway.interface_name
        start_node_id = self._node_id_for_device(start_device, stable=True)
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
        self._destination_gateway = self._discover_destination_gateway(validation.destination_ip)

        queue: deque[TraceState] = deque(
            [
                TraceState(
                    device_name=start_device,
                    interface_name=start_interface,
                    hop_ip=gateway.gateway.address if gateway.gateway else None,
                    path_hops=[],
                    path_issues=[],
                    failed_hops=0,
                    visited=set(),
                    graph_node_id=start_node_id,
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
            hop_identifier = state.hop_ip or "unknown hop"
            message = f"No device found in Nautobot for {hop_identifier}; path terminated."
            self._record_issue(path_issues, aggregate_issues, message)
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

        device_nodes = state.device_nodes
        node_id = self._node_id_for_device(
            device_name,
            device_nodes=device_nodes,
            path_index=len(current_hops),
        )
        state.graph_node_id = node_id

        # Check if current device is the destination
        dest_record = self._data_source.get_ip_address(destination_ip)
        if dest_record and dest_record.device_name == device_name:
            hop_entry = PathHop(
                device_name=device_name,
                interface_name=interface_name,
                next_hop_ip=destination_ip,
                egress_interface=dest_record.interface_name,
                details="Reached destination on current device (local route).",
                extras={},
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
            return

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

        if self._destination_gateway and self._matches_destination_gateway_device(device_name):
            self._finalize_via_destination_gateway(
                state=state,
                graph=graph,
                destination_ip=destination_ip,
            )
            return

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
                extras={},
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
                extras={},
            )
            current_hops.append(hop)
            self._record_issue(path_issues, aggregate_issues, "Routing blackhole detected: no next hop found.")
            self._finalize_path(current_hops, path_issues, reached=False)
            graph.ensure_node(node_id, blackhole=True)
            return

        for next_hop in next_hop_result.next_hops:
            branch_hops = list(current_hops)
            branch_issues = list(path_issues)
            branch_failed_hops = state.failed_hops
            graph_source_node_id = node_id
            branch_device_nodes = self._clone_device_nodes(device_nodes)

            next_hop_ip = next_hop.get("next_hop_ip")
            egress_interface = next_hop.get("egress_interface")
            hop_type = next_hop.get("hop_type")
            extras = self._extract_hop_extras(next_hop)
            display_interface = extras.get("ingress_interface") or interface_name
            display_egress = extras.get("egress_interface") or egress_interface

            layer2_payloads = list(next_hop.get("layer2_hops") or [])

            if next_hop_ip in (None, "", "local", "0.0.0.0"):
                if dest_record and dest_record.device_name == device_name:
                    hop_entry = PathHop(
                        device_name=device_name,
                        interface_name=display_interface,
                        next_hop_ip=destination_ip,
                        egress_interface=display_egress,
                        details="Local route to destination.",
                        extras=extras,
                        hop_type=self._as_layer3_hop_type(hop_type),
                    )
                    branch_hops.append(hop_entry)
                    l2_payloads_for_branch = layer2_payloads
                    layer2_payloads = []
                    graph_source_node_id = self._append_layer2_hops(
                        branch_hops,
                        graph,
                        graph_source_node_id,
                        l2_payloads_for_branch,
                        branch_device_nodes,
                        display_egress,
                    )
                    graph_source_node_id = self._append_destination_layer2(
                        branch_hops,
                        graph,
                        graph_source_node_id,
                        device_name,
                        display_egress,
                        destination_ip,
                        branch_device_nodes,
                    )
                    destination_hop = self._build_destination_hop(destination_ip)
                    edge_egress = self._edge_egress_value(branch_hops, destination_hop, display_egress)

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
                        graph_source_node_id,
                        dest_node_id,
                        hop=destination_hop or hop_entry,
                        local_route=True,
                        details=hop_entry.details,
                        egress_interface=edge_egress,
                    )
                    if destination_hop:
                        branch_hops.append(destination_hop)
                    self._finalize_path(branch_hops, branch_issues, reached=True)
                    continue
                if self._is_destination_on_interface(device_name, display_egress, destination_ip):
                    hop_entry = PathHop(
                        device_name=device_name,
                        interface_name=display_interface,
                        next_hop_ip=destination_ip,
                        egress_interface=display_egress,
                        details=f"Destination within subnet of interface '{egress_interface}'.",
                        extras=extras,
                        hop_type=self._as_layer3_hop_type(hop_type),
                    )
                    branch_hops.append(hop_entry)
                    graph_source_node_id = self._append_layer2_hops(
                        branch_hops,
                        graph,
                        graph_source_node_id,
                        layer2_payloads,
                        branch_device_nodes,
                        display_egress,
                    )
                    layer2_payloads = []
                    graph_source_node_id = self._append_destination_layer2(
                        branch_hops,
                        graph,
                        graph_source_node_id,
                        device_name,
                        display_egress,
                        destination_ip,
                        branch_device_nodes,
                    )
                    destination_hop = self._build_destination_hop(destination_ip)
                    dest_node_id = self._node_id_for_destination(
                        destination_hop.device_name if destination_hop else None,
                        destination_ip,
                    )
                    edge_egress = self._edge_egress_value(branch_hops, destination_hop, display_egress)
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
                        graph_source_node_id,
                        dest_node_id,
                        hop=destination_hop or hop_entry,
                        next_hop_ip=destination_ip,
                        egress_interface=edge_egress,
                        details=hop_entry.details,
                    )
                    if destination_hop:
                        branch_hops.append(destination_hop)
                    self._finalize_path(branch_hops, branch_issues, reached=True)
                    continue

                hop = PathHop(
                    device_name=device_name,
                    interface_name=display_interface,
                    next_hop_ip=None,
                    egress_interface=display_egress,
                    details="No next hop; possible blackhole.",
                    extras=extras,
                    hop_type=self._as_layer3_hop_type(hop_type),
                )
                branch_hops.append(hop)
                graph_source_node_id = self._append_layer2_hops(
                    branch_hops,
                    graph,
                    graph_source_node_id,
                    layer2_payloads,
                    branch_device_nodes,
                    display_egress,
                )
                layer2_payloads = []
                self._record_issue(branch_issues, aggregate_issues, "Routing blackhole detected.")
                self._finalize_path(branch_hops, branch_issues, reached=False)
                continue

            next_hop_record = self._data_source.get_ip_address(next_hop_ip) if next_hop_ip else None

            hop_entry = PathHop(
                device_name=device_name,
                interface_name=display_interface,
                next_hop_ip=next_hop_ip,
                egress_interface=display_egress,
                details=next_hop_result.details,
                extras=extras,
                hop_type=self._as_layer3_hop_type(hop_type),
            )

            next_device_name = next_hop_record.device_name if next_hop_record else None
            next_interface = next_hop_record.interface_name if next_hop_record else egress_interface

            is_destination = False
            if next_hop_ip == destination_ip:
                is_destination = True
            elif self._is_destination_within_next_hop(next_hop_record, destination_ip):
                is_destination = True

            if is_destination:
                branch_hops.append(hop_entry)
                graph_source_node_id = self._append_layer2_hops(
                    branch_hops,
                    graph,
                    graph_source_node_id,
                    layer2_payloads,
                    branch_device_nodes,
                    display_egress,
                )
                layer2_payloads = []
                graph_source_node_id = self._append_destination_layer2(
                    branch_hops,
                    graph,
                    graph_source_node_id,
                    device_name,
                    display_egress,
                    destination_ip,
                    branch_device_nodes,
                )
                destination_hop = self._build_destination_hop(destination_ip)
                dest_node_id = self._node_id_for_destination(destination_hop.device_name, destination_ip)
                edge_egress = self._edge_egress_value(branch_hops, destination_hop, display_egress)
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
                    graph_source_node_id,
                    dest_node_id,
                    hop=destination_hop or hop_entry,
                    next_hop_ip=next_hop_ip,
                    egress_interface=edge_egress,
                    details=next_hop_result.details,
                )
                if destination_hop:
                    branch_hops.append(destination_hop)
                self._finalize_path(branch_hops, branch_issues, reached=True)
                continue

            target_node_id = self._node_id_for_next_hop(
                graph=graph,
                source_node_id=graph_source_node_id,
                device_name=next_device_name,
                next_hop_ip=next_hop_ip,
                egress_interface=display_egress,
                device_nodes=branch_device_nodes,
                path_index=len(branch_hops),
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

            branch_hops.append(hop_entry)
            graph_source_node_id = self._append_layer2_hops(
                branch_hops,
                graph,
                graph_source_node_id,
                layer2_payloads,
                branch_device_nodes,
                display_egress,
            )
            layer2_payloads = []

            graph.add_edge(
                graph_source_node_id,
                target_node_id,
                hop=hop_entry,
                next_hop_ip=next_hop_ip,
                egress_interface=display_egress,
                details=next_hop_result.details,
            )

            updated_failed_hops = branch_failed_hops + (0 if next_device_name else 1)
            if updated_failed_hops > self._max_failed_hops:
                self._record_issue(
                    branch_issues,
                    aggregate_issues,
                    f"Too many failed hops ({updated_failed_hops}); potential routing issue.",
                )
                self._finalize_path(
                    branch_hops,
                    branch_issues,
                    reached=False,
                )
                continue

            queue_state = TraceState(
                device_name=next_device_name,
                interface_name=next_interface,
                hop_ip=next_hop_ip,
                path_hops=branch_hops,
                path_issues=list(branch_issues),
                failed_hops=updated_failed_hops,
                visited=visited,
                graph_node_id=target_node_id,
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
            node_id = self._node_id_for_device(member.device_name, stable=True)
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
    def _edge_egress_value(
        branch_hops: List[PathHop],
        destination_hop: Optional[PathHop],
        fallback: Optional[str],
    ) -> Optional[str]:
        """Return the interface label to apply to the rendered edge."""

        for hop in reversed(branch_hops):
            if hop.hop_type == "layer2" and hop.egress_interface:
                return hop.egress_interface
        if fallback:
            return fallback
        if destination_hop and destination_hop.interface_name:
            return destination_hop.interface_name
        return None

    @staticmethod
    def _clone_device_nodes(
        mapping: Dict[str, List[DeviceNodeAssignment]]
    ) -> Dict[str, List[DeviceNodeAssignment]]:
        """Deep-copy the device node assignment map for branch exploration."""

        cloned: Dict[str, List[DeviceNodeAssignment]] = {}
        for device, assignments in mapping.items():
            cloned[device] = [
                DeviceNodeAssignment(node_id=entry.node_id, last_index=entry.last_index)
                for entry in assignments
            ]
        return cloned

    @staticmethod
    def _as_layer3_hop_type(hop_type: Optional[str]) -> str:
        """Ensure primary hops default to at least layer3."""

        if hop_type is None:
            return "layer3"
        if hop_type == "layer2":
            return "layer3"
        return hop_type

    def _append_destination_layer2(
        self,
        branch_hops: List[PathHop],
        graph: NetworkPathGraph,
        source_node_id: str,
        device_name: Optional[str],
        egress_interface: Optional[str],
        destination_ip: str,
        device_nodes: Dict[str, List[DeviceNodeAssignment]],
    ) -> str:
        """Append layer-2 hops between the last L3 hop and the destination."""

        discover = getattr(self._next_hop_step, "discover_layer2_path", None)
        if not callable(discover):
            return source_node_id

        start_device = device_name
        start_interface = egress_interface
        if branch_hops:
            last_hop = branch_hops[-1]
            if last_hop.hop_type == "layer2":
                start_device = last_hop.device_name or start_device
                start_interface = last_hop.egress_interface or start_interface

        if not start_device or not destination_ip:
            return source_node_id

        payloads = discover(
            device_name=start_device,
            egress_interface=start_interface,
            target_ip=destination_ip,
        ) or []

        if branch_hops and payloads:
            last_layer2 = branch_hops[-1]
            if last_layer2.hop_type == "layer2":
                payloads = [
                    p
                    for p in payloads
                    if not (
                        p.get("device_name") == last_layer2.device_name
                        and p.get("ingress_interface") == last_layer2.ingress_interface
                        and p.get("egress_interface") == last_layer2.egress_interface
                    )
                ]

        if not payloads:
            return source_node_id
        return self._append_layer2_hops(
            branch_hops,
            graph,
            source_node_id,
            payloads,
            device_nodes,
            start_interface,
        )

    def _matches_destination_gateway_device(self, device_name: Optional[str]) -> bool:
        """Return True if the current device matches the resolved destination gateway."""

        if not self._destination_gateway or not self._destination_gateway.gateway:
            return False
        gateway_device = self._destination_gateway.gateway.device_name
        if not gateway_device or not device_name:
            return False
        return gateway_device == device_name

    def _finalize_via_destination_gateway(
        self,
        *,
        state: TraceState,
        graph: NetworkPathGraph,
        destination_ip: str,
    ) -> None:
        """Construct the destination segment using the resolved gateway metadata."""

        dest_gateway = self._destination_gateway
        if not dest_gateway or not dest_gateway.gateway:
            return

        device_name = state.device_name
        if not device_name:
            return

        branch_hops = list(state.path_hops)
        branch_issues = list(state.path_issues)

        egress_interface = dest_gateway.gateway.interface_name
        ingress_interface = state.interface_name
        details = (
            f"Destination within subnet of interface '{egress_interface}'."
            if egress_interface
            else (dest_gateway.details or "Destination subnet resolved via gateway discovery.")
        )
        hop_entry = PathHop(
            device_name=device_name,
            interface_name=ingress_interface,
            next_hop_ip=destination_ip,
            egress_interface=egress_interface,
            details=details,
            extras={},
            hop_type="layer3",
        )
        branch_hops.append(hop_entry)

        source_node_id = state.graph_node_id
        if not source_node_id:
            source_node_id = self._node_id_for_device(
                device_name,
                device_nodes=state.device_nodes,
                path_index=len(branch_hops) - 1,
            )
            state.graph_node_id = source_node_id
        else:
            self._node_id_for_device(
                device_name,
                device_nodes=state.device_nodes,
                path_index=len(branch_hops) - 1,
            )
        graph.ensure_node(
            source_node_id,
            label=device_name,
            device_name=device_name,
        )
        if ingress_interface:
            self._append_unique(
                graph.graph.nodes[source_node_id].setdefault("interfaces", []),
                ingress_interface,
            )

        source_node_id = self._append_destination_layer2(
            branch_hops,
            graph,
            source_node_id,
            device_name,
            egress_interface,
            destination_ip,
            state.device_nodes,
        )
        state.graph_node_id = source_node_id

        destination_hop = self._build_destination_hop(destination_ip)
        dest_node_id = self._node_id_for_destination(
            destination_hop.device_name if destination_hop else None,
            destination_ip,
        )
        edge_egress = self._edge_egress_value(branch_hops, destination_hop, egress_interface)
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
            source_node_id,
            dest_node_id,
            hop=destination_hop or hop_entry,
            next_hop_ip=destination_ip,
            egress_interface=edge_egress,
            details=hop_entry.details,
        )
        if destination_hop:
            branch_hops.append(destination_hop)

        if self._logger:
            self._logger.info(
                "Finalized destination segment via gateway '%s' (%s)",
                dest_gateway.gateway.device_name or dest_gateway.gateway.address or "unknown",
                dest_gateway.method,
            )

        self._finalize_path(branch_hops, branch_issues, reached=True)

    def _discover_destination_gateway(self, destination_ip: str) -> Optional[GatewayDiscoveryResult]:
        """Reuse gateway discovery logic to resolve the final L3 hop toward the destination."""

        record = self._data_source.get_ip_address(destination_ip)
        if not record:
            return None

        prefix = self._data_source.get_most_specific_prefix(destination_ip)
        if prefix is None and record.prefix_length:
            try:
                network = ipaddress.ip_network(f"{record.address}/{record.prefix_length}", strict=False)
            except ValueError:
                network = None
            if network is not None:
                prefix = PrefixRecord(prefix=str(network))
        if prefix is None:
            return None

        validation = InputValidationResult(
            source_ip=destination_ip,
            destination_ip=destination_ip,
            source_record=record,
            source_prefix=prefix,
            is_host_ip=False,
        )

        if self._destination_gateway_step is None:
            self._destination_gateway_step = GatewayDiscoveryStep(
                self._data_source,
                self._settings.gateway_custom_field,
            )
        try:
            result = self._destination_gateway_step.run(validation)
            if result and self._logger and result.gateway:
                self._logger.info(
                    "Resolved destination-facing gateway '%s' via %s",
                    result.gateway.device_name or result.gateway.address or "unknown",
                    result.method,
                )
            return result
        except GatewayDiscoveryError:
            if self._logger:
                self._logger.debug(
                    "Destination gateway discovery failed; proceeding without destination shortcut",
                    extra={"grouping": "path-tracing"},
                )
            return None

    def _append_layer2_hops(
        self,
        branch_hops: List[PathHop],
        graph: NetworkPathGraph,
        source_node_id: str,
        layer2_payloads: List[Dict[str, Any]],
        device_nodes: Dict[str, List[DeviceNodeAssignment]],
        upstream_egress: Optional[str],
    ) -> str:
        """Append layer-2 hops to the path and graph, returning last node id."""

        current_source = source_node_id
        if not layer2_payloads:
            return current_source

        for index, payload in enumerate(layer2_payloads):
            details = payload.get("details") or "Layer 2 hop resolved via LLDP/MAC."
            extras = {
                "mac_address": payload.get("mac_address"),
                "ingress_interface": payload.get("ingress_interface"),
                "egress_interface": payload.get("egress_interface"),
            }
            layer2_hop = PathHop(
                device_name=payload.get("device_name"),
                interface_name=payload.get("ingress_interface"),
                next_hop_ip=None,
                egress_interface=payload.get("egress_interface"),
                details=details,
                extras=extras,
                hop_type="layer2",
            )
            branch_hops.append(layer2_hop)

            device_name = layer2_hop.device_name
            if device_name:
                node_id = self._node_id_for_device(
                    device_name,
                    device_nodes=device_nodes,
                    path_index=len(branch_hops) - 1,
                )
            else:
                node_id = self._new_node_id("layer2-hop")
            graph.ensure_node(
                node_id,
                label=device_name or node_id,
                device_name=device_name,
                role="layer2",
                mac_address=payload.get("mac_address"),
            )
            if layer2_hop.egress_interface:
                self._append_unique(
                    graph.graph.nodes[node_id].setdefault("interfaces", []),
                    layer2_hop.egress_interface,
                )
            edge_label = upstream_egress or payload.get("ingress_interface") or payload.get("egress_interface")
            graph.add_edge(
                current_source,
                node_id,
                hop=layer2_hop,
                egress_interface=edge_label,
                mac_address=payload.get("mac_address"),
                details=layer2_hop.details,
                dashed=True,
            )
            current_source = node_id
            upstream_egress = layer2_hop.egress_interface

        return current_source

    @staticmethod
    def _extract_hop_extras(next_hop: Dict[str, Any]) -> Dict[str, Any]:
        """Return hop metadata excluding standard keys."""

        if not isinstance(next_hop, dict):
            return {}
        return {
            key: value
            for key, value in next_hop.items()
            if key not in {"next_hop_ip", "egress_interface", "hop_type", "layer2_hops"}
        }

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
                json.dumps(hop.extras, sort_keys=True, default=str),
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

    def _new_node_id(self, base: str) -> str:
        """Return a unique node identifier based on ``base``."""

        self._node_sequence += 1
        token = (base or "node").replace(" ", "_")
        return f"{token}::{self._node_sequence}"

    def _node_id_for_device(
        self,
        device_name: Optional[str],
        *,
        stable: bool = False,
        device_nodes: Optional[Dict[str, List[DeviceNodeAssignment]]] = None,
        path_index: Optional[int] = None,
    ) -> str:
        """Return a graph node identifier, with path-aware duplication control."""

        if not device_name:
            return self._new_node_id("unknown-device")

        if stable or device_nodes is None:
            return device_name

        assignments = device_nodes.setdefault(device_name, [])
        if assignments:
            last_assignment = assignments[-1]
            if (
                path_index is None
                or last_assignment.last_index == -1
                or path_index - last_assignment.last_index <= 1
            ):
                if path_index is not None:
                    last_assignment.last_index = path_index
                return last_assignment.node_id

        if assignments:
            node_id = self._new_node_id(device_name)
        else:
            node_id = device_name

        assignments.append(
            DeviceNodeAssignment(
                node_id=node_id,
                last_index=path_index if path_index is not None else -1,
            )
        )
        return node_id

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
        device_nodes: Dict[str, List[DeviceNodeAssignment]],
        path_index: int,
    ) -> str:
        """Determine the node id for the next hop candidate."""

        if device_name:
            return self._node_id_for_device(
                device_name,
                device_nodes=device_nodes,
                path_index=path_index,
            )
        if next_hop_ip:
            base = f"{source_node_id}::ip::{next_hop_ip}"
        elif egress_interface:
            base = f"{source_node_id}::if::{egress_interface}"
        else:
            base = f"{source_node_id}::unknown"
        return self._new_node_id(base)

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
                extras={},
            )

        return PathHop(
            device_name="device_info: Not Found",
            interface_name=None,
            next_hop_ip=destination_ip,
            egress_interface=None,
            details="Destination device info not found in Nautobot",
            extras={},
        )
