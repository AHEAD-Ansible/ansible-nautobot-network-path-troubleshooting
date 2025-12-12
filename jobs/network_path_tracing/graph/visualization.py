"""PyVis helpers for interactive visualization (optional)."""

from __future__ import annotations

from typing import Iterable, Optional

from .network_graph import NetworkPathGraph


NODE_COLORS = {
    "source": "#60a5fa",       # lighter blue
    "destination": "#4ade80",  # lighter green
    "hop": "#9ca3af",          # lighter grey
    "error": "#f87171",        # lighter red
    "highlight": "#f59e0b",    # amber for emphasized paths
}


def build_pyvis_network(
    graph: NetworkPathGraph,
    *,
    highlight_path: Optional[Iterable[str]] = None,
    physics: bool = False,
):
    """Return a PyVis Network populated from NetworkPathGraph.

    Args:
        graph: The populated NetworkPathGraph instance.
        highlight_path: Optional iterable of node identifiers to highlight.
        physics: Whether to enable PyVis physics simulation.

    Returns:
        pyvis.network.Network: Configured network visualization instance.
    """
    try:
        from pyvis.network import Network
    except ImportError as exc:  # pragma: no cover - visualization is optional
        raise RuntimeError("pyvis is required to build visualizations") from exc

    net = Network(height="600px", width="100%", notebook=False, directed=True)
    net.toggle_physics(physics)

    highlight = set(highlight_path or [])

    id_map: dict[object, str] = {}

    for node_id, data in graph.graph.nodes(data=True):
        node_key = str(node_id)
        id_map[node_id] = node_key
        label = data.get("label") or node_id
        if not isinstance(label, str):
            label = str(label)
        title_lines = [f"{key}: {value}" for key, value in sorted(data.items()) if key != "label"]
        title = "<br/>".join(title_lines) if title_lines else label
        color = NODE_COLORS["hop"]
        role = data.get("role")
        shape = "dot"
        if role == "layer2":
            shape = "box"
        if data.get("error"):
            color = NODE_COLORS["error"]
        elif role == "source":
            color = NODE_COLORS["source"]
        elif role == "destination":
            color = NODE_COLORS["destination"]
        elif node_id in highlight:
            color = NODE_COLORS["highlight"]
        net.add_node(node_key, label=label, title=title, color=color, shape=shape)

    edge_occurrences: dict[tuple[str, str], int] = {}

    for source, target, key, data in graph.graph.edges(keys=True, data=True):
        title_lines = [
            f"{attr}: {value}"
            for attr, value in sorted(data.items())
            if attr != "hop"
        ]
        hop = data.get("hop")
        if hop is not None:
            hop_title = [f"{field}: {getattr(hop, field)}" for field in ("next_hop_ip", "egress_interface", "details")]
            title_lines.extend(hop_title)
        title = "<br/>".join(title_lines) if title_lines else None
        idx = edge_occurrences.get((source, target), 0)
        edge_occurrences[(source, target)] = idx + 1
        smooth = None
        if idx:
            direction = "curvedCW" if idx % 2 == 1 else "curvedCCW"
            roundness = min(0.8, 0.25 + 0.15 * (idx // 2))
            smooth = {"enabled": True, "type": direction, "roundness": roundness}
        source_key = id_map.get(source, str(source))
        target_key = id_map.get(target, str(target))
        edge_id = f"{source_key}->{target_key}::{key}_{idx}"
        label = data.get("egress_interface") or data.get("next_hop_ip")
        dashes = bool(data.get("dashed"))
        net.add_edge(
            source_key,
            target_key,
            id=edge_id,
            title=title,
            label=label,
            smooth=smooth,
            dashes=dashes,
        )

    return net


__all__ = ["build_pyvis_network"]
