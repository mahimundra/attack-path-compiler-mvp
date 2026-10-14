from __future__ import annotations

from backend.app.services.graph_compiler import GraphCompiler, graph_edges
from backend.app.simulation.generator import generate_demo_scenario


def test_generation_and_compilation_are_deterministic() -> None:
    left = generate_demo_scenario(event_count=80)
    right = generate_demo_scenario(event_count=80)
    assert left.events == right.events
    assert left.inventory == right.inventory

    compiler = GraphCompiler()
    left_graph = compiler.compile(left.inventory, left.events)
    right_graph = compiler.compile(right.inventory, right.events)
    assert graph_edges(left_graph.evidence) == graph_edges(right_graph.evidence)
    assert graph_edges(left_graph.projected) == graph_edges(right_graph.projected)


def test_graph_referential_integrity_and_projection(compiled) -> None:
    node_ids = set(compiled.evidence.nodes)
    evidence_ids = set()
    for edge in graph_edges(compiled.evidence):
        assert edge.source in node_ids
        assert edge.target in node_ids
        evidence_ids.update(edge.evidence_ids)

    for edge in graph_edges(compiled.projected):
        assert edge.source in node_ids
        assert edge.target in node_ids
        assert set(edge.evidence_ids) <= evidence_ids
        parallel = compiled.evidence.get_edge_data(edge.source, edge.target)
        assert edge.feasibility == max(attrs["edge"].feasibility for attrs in parallel.values())


def test_all_event_timestamps_are_fixed_utc(fixture) -> None:
    assert all(event.timestamp.utcoffset().total_seconds() == 0 for event in fixture.events)
    assert fixture.events[0].timestamp.year == 2026
