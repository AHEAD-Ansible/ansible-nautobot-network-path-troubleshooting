"""NetworkX-based graph helpers for network path tracing."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Iterable, Optional

try:
    import networkx as nx
except ImportError as exc:  # pragma: no cover - dependency issue surfaces at runtime
    raise RuntimeError(
        "networkx must be installed to use the graph traversal features"
    ) from exc


class NetworkPathGraph:
    """Wrapper around a MultiDiGraph with convenience helpers."""

    def __init__(self) -> None:
        self._graph = nx.MultiDiGraph()
        self._start_node: Optional[str] = None
        self._destination_nodes: set[str] = set()

    @property
    def graph(self) -> nx.MultiDiGraph:
        """Return the underlying graph instance."""
        return self._graph

    @property
    def start_node(self) -> Optional[str]:
        """Return the identifier for the starting node."""
        return self._start_node

    @property
    def destination_nodes(self) -> set[str]:
        """Return identifiers for nodes marked as destinations."""
        return set(self._destination_nodes)

    def ensure_node(self, node_id: str, **attrs: Any) -> str:
        """Ensure a node exists and merge any supplied attributes."""
        if not node_id:
            raise ValueError("node_id must be a non-empty string")
        existing = self._graph.nodes.get(node_id, {})
        merged: Dict[str, Any] = {**existing, **attrs}
        self._graph.add_node(node_id, **merged)
        return node_id

    def mark_start(self, node_id: str) -> None:
        """Mark the logical start node for later reference."""
        self._start_node = node_id
        self.ensure_node(node_id)
        self._graph.nodes[node_id]["role"] = "start"

    def mark_destination(self, node_id: str) -> None:
        """Mark a node as a destination endpoint."""
        self.ensure_node(node_id)
        self._graph.nodes[node_id]["role"] = "destination"
        self._destination_nodes.add(node_id)

    def add_edge(
        self,
        source: str,
        target: str,
        *,
        key: Optional[str] = None,
        hop: Optional[Any] = None,
        **attrs: Any,
    ) -> None:
        """Add a directed edge with optional hop metadata."""
        self.ensure_node(source)
        self.ensure_node(target)
        if hop is not None:
            attrs.setdefault("hop", hop)
        source_role = self._graph.nodes[source].get("role")
        target_role = self._graph.nodes[target].get("role")
        if (
            (source_role == "layer2" or target_role == "layer2")
            and "dashed" not in attrs
        ):
            attrs["dashed"] = True
        edge_key = key or attrs.get("next_hop_ip") or attrs.get("egress_interface")
        self._graph.add_edge(source, target, key=edge_key, **attrs)

    def serialize(self) -> Dict[str, Any]:
        """Return a JSON-friendly view of the graph."""
        nodes = []
        for node_id, data in self._graph.nodes(data=True):
            node_payload: Dict[str, Any] = {"id": node_id}
            for attr, value in data.items():
                if is_dataclass(value):
                    node_payload[attr] = asdict(value)
                else:
                    node_payload[attr] = value
            nodes.append(node_payload)

        edges = []
        for source, target, key, data in self._graph.edges(keys=True, data=True):
            payload = {"source": source, "target": target, "key": key}
            for attr, value in data.items():
                if attr == "hop" and value is not None:
                    try:
                        payload[attr] = asdict(value)
                    except TypeError:
                        payload[attr] = value
                else:
                    payload[attr] = value
            edges.append(payload)

        return {
            "start": self._start_node,
            "destinations": list(self._destination_nodes),
            "nodes": nodes,
            "edges": edges,
        }

    def neighbors(self, node_id: str) -> Iterable[str]:
        """Yield neighbor node identifiers from the supplied node."""
        return self._graph.neighbors(node_id)

    def __len__(self) -> int:
        """Return number of nodes."""
        return self._graph.number_of_nodes()


__all__ = ["NetworkPathGraph"]
