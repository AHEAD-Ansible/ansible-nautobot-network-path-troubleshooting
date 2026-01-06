from jobs.network_path_tracing.graph.network_graph import NetworkPathGraph
from jobs.network_path_tracing.graph.visualization import NODE_COLORS, build_pyvis_network


def test_pyvis_node_colors_follow_roles_and_errors():
    graph = NetworkPathGraph()
    graph.ensure_node("src", role="source", label="src")
    graph.ensure_node("dst", role="destination", label="dst")
    graph.ensure_node("mid", label="mid")
    graph.ensure_node("err", label="err", error="boom")

    net = build_pyvis_network(graph)
    colors = {node["id"]: node.get("color") for node in net.nodes}

    assert colors["src"] == NODE_COLORS["source"]
    assert colors["dst"] == NODE_COLORS["destination"]
    assert colors["mid"] == NODE_COLORS["hop"]
    assert colors["err"] == NODE_COLORS["error"]


def test_pyvis_node_tooltips_are_plain_text_and_sanitized():
    graph = NetworkPathGraph()
    graph.ensure_node(
        "mid",
        label="mid",
        interfaces=["Ethernet1/1", "Ethernet1/2"],
        error="boom<br/>oops",
    )

    net = build_pyvis_network(graph)
    node = next(node for node in net.nodes if node["id"] == "mid")
    title = node.get("title") or ""

    assert "<br" not in title
    assert "ERROR: boom oops" in title
    assert "\nrole: " in title


def test_firewall_deny_coloring_and_summary_tooltip():
    graph = NetworkPathGraph()
    graph.ensure_node(
        "fw1",
        label="pa-edge-1",
        device_name="pa-edge-1",
        interfaces=["ethernet1/1", "ethernet1/2"],
    )
    graph.ensure_node(
        "fw1-dup",
        label="pa-edge-1",
        device_name="PA-EDGE-1.example.com",
    )
    graph.ensure_node(
        "fw1-error",
        label="pa-edge-1",
        device_name="pa-edge-1",
        error="routing loop",
    )
    graph.ensure_node("other", label="core-rtr-1", device_name="core-rtr-1")

    firewall_logs = {
        "entries": [
            {
                "timestamp": "2026/01/05 12:01:02",
                "action": "deny",
                "destination_port": 443,
                "rule": "block-bad",
                "app": "ssl",
                "device_name": "pa-edge-1.example.com",
            },
            {
                "timestamp": "2026/01/05 12:30:45",
                "action": "deny",
                "destination_port": 443,
                "rule": "",
                "app": "web-browsing",
                "device_name": "PA-EDGE-1",
            },
            {
                "timestamp": "2026/01/05 12:20:00",
                "action": "deny",
                "destination_port": 443,
                "rule": "block-bad",
                "app": "ssl",
                "device_name": "pa-edge-1",
            },
        ]
    }

    net = build_pyvis_network(graph, firewall_logs=firewall_logs)
    nodes = {node["id"]: node for node in net.nodes}

    assert nodes["fw1"]["color"] == NODE_COLORS["deny"]
    assert nodes["fw1-dup"]["color"] == NODE_COLORS["deny"]
    assert nodes["fw1-error"]["color"] == NODE_COLORS["error"]
    assert nodes["other"]["color"] == NODE_COLORS["hop"]

    title = nodes["fw1"].get("title") or ""
    assert "<br" not in title
    assert "Firewall Logs (DENY):" in title
    assert "denies: 3" in title
    assert "time_range: 2026/01/05 12:01:02 - 2026/01/05 12:30:45" in title
    assert "top_rules: block-bad (2), <unknown> (1)" in title
    assert "top_apps: ssl (2), web-browsing (1)" in title
    assert "top_dports: 443 (3)" in title


def test_firewall_deny_summary_is_grouped_per_device():
    graph = NetworkPathGraph()
    graph.ensure_node("fw1", label="pa-edge-1", device_name="pa-edge-1")
    graph.ensure_node("fw2", label="pa-edge-2", device_name="pa-edge-2.example.com")
    graph.ensure_node("other", label="core-rtr-1", device_name="core-rtr-1")

    firewall_logs = {
        "entries": [
            {
                "timestamp": "2026/01/05 12:01:02",
                "action": "deny",
                "rule": "block-1",
                "app": "ssl",
                "destination_port": 443,
                "device_name": "pa-edge-1",
            },
            {
                "timestamp": "2026/01/05 12:02:00",
                "action": "allow",
                "rule": "allow-1",
                "app": "ssl",
                "destination_port": 443,
                "device_name": "pa-edge-1",
            },
            {
                "timestamp": "2026/01/05 12:03:00",
                "action": "deny",
                "rule": "block-2",
                "app": "web-browsing",
                "destination_port": 443,
                "device_name": "pa-edge-1.example.com",
            },
            {
                "timestamp": "2026/01/05 12:10:00",
                "action": "deny",
                "rule": "block-3",
                "app": "dns",
                "destination_port": 53,
                "device_name": "pa-edge-2",
            },
        ]
    }

    net = build_pyvis_network(graph, firewall_logs=firewall_logs)
    nodes = {node["id"]: node for node in net.nodes}

    assert nodes["fw1"]["color"] == NODE_COLORS["deny"]
    assert nodes["fw2"]["color"] == NODE_COLORS["deny"]
    assert nodes["other"]["color"] == NODE_COLORS["hop"]

    fw1_title = nodes["fw1"].get("title") or ""
    fw2_title = nodes["fw2"].get("title") or ""

    assert "denies: 2" in fw1_title
    assert "denies: 1" in fw2_title


def test_firewall_deny_summary_truncates_long_values():
    graph = NetworkPathGraph()
    graph.ensure_node("fw1", label="pa-edge-1", device_name="pa-edge-1")

    long_rule = "block-" + ("x" * 80)
    long_app = "app-" + ("y" * 80)
    expected_truncated_rule = f"{long_rule[:37]}..."
    expected_truncated_app = f"{long_app[:37]}..."

    firewall_logs = {
        "entries": [
            {
                "timestamp": "2026/01/05 12:01:02",
                "action": "deny",
                "destination_port": 443,
                "rule": long_rule,
                "app": long_app,
                "device_name": "pa-edge-1",
            },
            {
                "timestamp": "2026/01/05 12:02:03",
                "action": "deny",
                "destination_port": 443,
                "rule": long_rule,
                "app": long_app,
                "device_name": "pa-edge-1",
            },
        ]
    }

    net = build_pyvis_network(graph, firewall_logs=firewall_logs)
    node = next(node for node in net.nodes if node["id"] == "fw1")

    assert node["color"] == NODE_COLORS["deny"]
    title = node.get("title") or ""
    assert f"{expected_truncated_rule} (2)" in title
    assert f"{expected_truncated_app} (2)" in title
