"""PyVis helpers for interactive visualization (optional)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import re
from typing import Any, Iterable, Mapping, Optional

from .network_graph import NetworkPathGraph


NODE_COLORS = {
    "source": "#60a5fa",       # lighter blue
    "destination": "#4ade80",  # lighter green
    "hop": "#9ca3af",          # lighter grey
    "error": "#f87171",        # lighter red
    "deny": "#ef4444",         # red for firewall deny highlighting
    "highlight": "#f59e0b",    # amber for emphasized paths
}

_BR_TAG_RE = re.compile(r"<\s*br\s*/?\s*>", re.IGNORECASE)
_WHITESPACE_RE = re.compile(r"\s+")


def _normalize_device_name(name: object) -> Optional[str]:
    if name is None:
        return None
    try:
        normalized = str(name).strip()
    except Exception:
        return None
    if not normalized:
        return None
    normalized = normalized.casefold()
    if "." in normalized:
        normalized = normalized.split(".", 1)[0]
    return normalized or None


def _sanitize_tooltip_text(value: object, *, max_len: int = 120) -> str:
    """Return a safe, compact tooltip fragment (plain text, no HTML breaks)."""

    if value is None:
        return ""
    try:
        text = str(value)
    except Exception:
        return ""
    text = text.strip()
    if not text:
        return ""
    text = text.replace("\r", " ").replace("\n", " ")
    text = _BR_TAG_RE.sub(" ", text)
    text = _WHITESPACE_RE.sub(" ", text).strip()
    if max_len > 0 and len(text) > max_len:
        if max_len <= 3:
            return text[:max_len]
        return f"{text[: max_len - 3]}..."
    return text


def _display_role(raw_role: object) -> str:
    role = _sanitize_tooltip_text(raw_role, max_len=32)
    if not role:
        return "hop"
    canonical = role.casefold()
    if canonical == "start":
        return "gateway"
    if canonical in {"source", "gateway", "hop", "destination", "layer2"}:
        return canonical
    return "hop"


def _format_list(values: Iterable[object], *, max_items: int = 5) -> Optional[str]:
    items: list[str] = []
    for value in values:
        rendered = _sanitize_tooltip_text(value)
        if rendered:
            items.append(rendered)
    if not items:
        return None
    head = items[:max_items]
    remainder = max(0, len(items) - len(head))
    joined = ", ".join(head)
    return f"{joined} (+{remainder} more)" if remainder else joined


def _collect_interfaces(data: Mapping[str, Any]) -> list[str]:
    interfaces: list[str] = []

    single = data.get("interface")
    if isinstance(single, str) and single.strip():
        interfaces.append(single.strip())

    multi = data.get("interfaces")
    if isinstance(multi, (list, tuple, set)):
        for item in multi:
            if isinstance(item, str) and item.strip():
                interfaces.append(item.strip())
    elif isinstance(multi, str) and multi.strip():
        interfaces.append(multi.strip())

    deduped: list[str] = []
    seen: set[str] = set()
    for item in interfaces:
        key = item.casefold()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _is_deny_action(action: object) -> bool:
    raw = _sanitize_tooltip_text(action, max_len=32)
    if not raw:
        return True
    return raw.casefold() == "deny"


def _firewall_deny_entries_by_device(firewall_logs: object) -> dict[str, list[dict[str, Any]]]:
    if firewall_logs is None:
        return {}

    entries: object = None
    try:
        if isinstance(firewall_logs, Mapping):
            entries = firewall_logs.get("entries")
        else:
            entries = getattr(firewall_logs, "entries", None)
    except Exception:
        return {}

    if not entries:
        return {}

    if not isinstance(entries, list):
        try:
            entries = list(entries)
        except Exception:
            return {}

    deny_entries: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        if not _is_deny_action(entry.get("action")):
            continue
        normalized_device = _normalize_device_name(entry.get("device_name"))
        if not normalized_device:
            continue
        try:
            deny_entries.setdefault(normalized_device, []).append(dict(entry))
        except Exception:
            continue
    return deny_entries


def _parse_timestamp(value: str) -> Optional[datetime]:
    candidate = (value or "").strip()
    if not candidate:
        return None

    normalized = candidate
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        pass

    for fmt in (
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
    ):
        try:
            return datetime.strptime(candidate, fmt)
        except ValueError:
            continue
    return None


def _truncate(value: str, *, max_len: int) -> str:
    if max_len <= 0:
        return ""
    if len(value) <= max_len:
        return value
    if max_len <= 3:
        return value[:max_len]
    return f"{value[: max_len - 3]}..."


def _group_key(value: object) -> str:
    cleaned = _sanitize_tooltip_text(value)
    return cleaned if cleaned else "<unknown>"


def _format_top_counts(counter: Counter[str], *, limit: int = 3, truncate_len: Optional[int] = None) -> str:
    items = list(counter.items())
    items.sort(key=lambda item: (-item[1], item[0].casefold()))
    top = items[:limit]
    remainder = max(0, len(items) - len(top))

    rendered: list[str] = []
    for value, count in top:
        display_value = value
        if truncate_len is not None:
            display_value = _truncate(display_value, max_len=truncate_len)
        rendered.append(f"{display_value} ({count})")

    joined = ", ".join(rendered) if rendered else "<unknown> (0)"
    return f"{joined} (+{remainder} more)" if remainder else joined


def _firewall_logs_summary_lines(entries: Iterable[Mapping[str, Any]]) -> list[str]:
    deny_entries = [
        entry for entry in entries if isinstance(entry, Mapping) and _is_deny_action(entry.get("action"))
    ]
    if not deny_entries:
        return []

    timestamps: list[tuple[datetime, str]] = []
    for entry in deny_entries:
        raw_ts = entry.get("timestamp")
        ts_text = _sanitize_tooltip_text(raw_ts)
        if not ts_text:
            continue
        parsed = _parse_timestamp(ts_text)
        if parsed is not None:
            timestamps.append((parsed, ts_text))

    if timestamps:
        earliest = min(timestamps, key=lambda pair: pair[0])[1]
        latest = max(timestamps, key=lambda pair: pair[0])[1]
        time_range = f"{earliest} - {latest}"
    else:
        time_range = "unknown"

    rules = Counter(_group_key(entry.get("rule")) for entry in deny_entries)
    apps = Counter(_group_key(entry.get("app")) for entry in deny_entries)
    dports = Counter(_group_key(entry.get("destination_port")) for entry in deny_entries)

    return [
        "Firewall Logs (DENY):",
        f"denies: {len(deny_entries)}",
        f"time_range: {time_range}",
        f"top_rules: {_format_top_counts(rules, truncate_len=40)}",
        f"top_apps: {_format_top_counts(apps, truncate_len=40)}",
        f"top_dports: {_format_top_counts(dports)}",
    ]


def _build_node_tooltip(
    *,
    node_id: str,
    data: Mapping[str, Any],
    deny_entries: Optional[list[dict[str, Any]]] = None,
) -> str:
    label = data.get("label") or node_id
    header = _sanitize_tooltip_text(label)
    lines = [header or node_id]

    error = data.get("error")
    if error:
        error_text = _sanitize_tooltip_text(error)
        if error_text:
            lines.append(f"ERROR: {error_text}")

    lines.append(f"role: {_display_role(data.get('role'))}")

    ip_address = _sanitize_tooltip_text(data.get("ip_address"))
    if ip_address:
        lines.append(f"ip: {ip_address}")

    interfaces = _collect_interfaces(data)
    rendered_interfaces = _format_list(interfaces) if interfaces else None
    if rendered_interfaces:
        lines.append(f"interfaces: {rendered_interfaces}")

    if data.get("redundancy_member"):
        priority = data.get("redundancy_priority")
        priority_text = _sanitize_tooltip_text(priority, max_len=32)
        if priority_text:
            lines.append(f"redundancy: member (priority {priority_text})")
        else:
            lines.append("redundancy: member")

    if data.get("blackhole"):
        lines.append("blackhole: true")

    if deny_entries:
        summary = _firewall_logs_summary_lines(deny_entries)
        if summary:
            lines.append("")
            lines.extend(summary)

    return "\n".join(lines)


def _build_edge_tooltip(data: Mapping[str, Any]) -> Optional[str]:
    lines: list[str] = []
    for attr, value in sorted(data.items()):
        if attr == "hop":
            continue
        if value is None or value == "":
            continue
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        elif isinstance(value, (int, float)):
            rendered = str(value)
        elif isinstance(value, str):
            rendered = _sanitize_tooltip_text(value)
        elif isinstance(value, (list, tuple, set)):
            rendered = _format_list(value) or ""
        else:
            continue
        if rendered:
            lines.append(f"{attr}: {rendered}")

    hop = data.get("hop")
    if hop is not None:
        for field in ("next_hop_ip", "egress_interface", "egress_vrf", "details"):
            rendered = _sanitize_tooltip_text(getattr(hop, field, None))
            if rendered:
                lines.append(f"{field}: {rendered}")

    return "\n".join(lines) if lines else None


def build_pyvis_network(
    graph: NetworkPathGraph,
    *,
    highlight_path: Optional[Iterable[str]] = None,
    physics: bool = False,
    firewall_logs: Optional[Mapping[str, Any]] = None,
):
    """Return a PyVis Network populated from NetworkPathGraph.

    Args:
        graph: The populated NetworkPathGraph instance.
        highlight_path: Optional iterable of node identifiers to highlight.
        physics: Whether to enable PyVis physics simulation.
        firewall_logs: Optional firewall log payload to influence coloring/tooltips.

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
    deny_entries_by_device = _firewall_deny_entries_by_device(firewall_logs)

    id_map: dict[object, str] = {}

    for node_id, data in graph.graph.nodes(data=True):
        node_key = str(node_id)
        id_map[node_id] = node_key
        label = data.get("label") or node_id
        if not isinstance(label, str):
            label = str(label)
        normalized_device = _normalize_device_name(data.get("device_name"))
        deny_entries = deny_entries_by_device.get(normalized_device, []) if normalized_device else []
        title = _build_node_tooltip(node_id=node_key, data=data, deny_entries=deny_entries or None)
        color = NODE_COLORS["hop"]
        role = data.get("role")
        shape = "dot"
        if role == "layer2":
            shape = "box"
        if data.get("error"):
            color = NODE_COLORS["error"]
        elif deny_entries:
            color = NODE_COLORS["deny"]
        elif role == "source":
            color = NODE_COLORS["source"]
        elif role == "destination":
            color = NODE_COLORS["destination"]
        elif node_id in highlight:
            color = NODE_COLORS["highlight"]
        net.add_node(node_key, label=label, title=title, color=color, shape=shape)

    edge_occurrences: dict[tuple[str, str], int] = {}

    def _format_label(interface: Optional[str], vrf: Optional[str]) -> Optional[str]:
        if not interface:
            return None
        display_vrf = "global" if vrf in (None, "", "None") else str(vrf)
        return f"{interface} ({display_vrf})"

    for source, target, key, data in graph.graph.edges(keys=True, data=True):
        hop = data.get("hop")
        title = _build_edge_tooltip(data)
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
        label = None
        if hop is not None:
            label = _format_label(getattr(hop, "egress_interface", None), getattr(hop, "egress_vrf", None))
        if label is None:
            label = _format_label(data.get("egress_interface"), data.get("egress_vrf"))
        if label is None:
            label = data.get("next_hop_ip")
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
