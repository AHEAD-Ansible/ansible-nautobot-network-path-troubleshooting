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
