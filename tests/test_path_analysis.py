from __future__ import annotations

import math
from datetime import datetime, timezone

import networkx as nx

from backend.app.models.graph import (
    EntityNode,
    EntityType,
    RelationshipEdge,
    RelationshipType,
)
from backend.app.services.path_analyzer import PathAnalyzer


def test_expected_top_path_and_score_math(fixture, compiled) -> None:
    result = PathAnalyzer().analyze(compiled.projected)
    top = result.paths[0]
    assert list(top.node_ids) == fixture.ground_truth["expected_top_path"]
    expected = 0.92 * 0.95 * 0.94 * 0.93 * 0.92 * 1.0
    assert math.isclose(top.score, expected, rel_tol=1e-12)
    assert math.isclose(top.exposure_index, expected * 100, rel_tol=1e-12)
    assert result.candidate_count >= 3


def test_paths_are_ranked_and_loopless(compiled) -> None:
    paths = PathAnalyzer().analyze(compiled.projected).paths
    assert [path.rank for path in paths] == list(range(1, len(paths) + 1))
    assert [path.score for path in paths] == sorted(
        (path.score for path in paths), reverse=True
    )
    assert all(len(path.node_ids) == len(set(path.node_ids)) for path in paths)
    assert all(len(path.edge_ids) <= 8 for path in paths)


def test_overlong_candidates_do_not_hide_a_valid_bounded_path() -> None:
    graph = nx.DiGraph()
    nodes = [
        EntityNode(id="entry", label="Entry", type=EntityType.ATTACKER, entry_prior=1),
        EntityNode(id="long-a", label="Long A", type=EntityType.DEVICE),
        EntityNode(id="long-b", label="Long B", type=EntityType.ROLE),
        EntityNode(id="short", label="Short", type=EntityType.ROLE),
        EntityNode(id="target", label="Target", type=EntityType.RESOURCE, criticality=100),
    ]
    for node in nodes:
        graph.add_node(node.id, entity=node)

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for index, (source, target, feasibility) in enumerate(
        [
            ("entry", "long-a", 0.99),
            ("long-a", "long-b", 0.99),
            ("long-b", "target", 0.99),
            ("entry", "short", 0.10),
            ("short", "target", 0.10),
        ]
    ):
        edge = RelationshipEdge(
            id=f"edge-{index}",
            source=source,
            target=target,
            type=RelationshipType.OBSERVED,
            feasibility=feasibility,
            evidence_ids=(f"event-{index}",),
            first_seen=now,
            last_seen=now,
        )
        graph.add_edge(source, target, edge=edge)

    result = PathAnalyzer().analyze(
        graph, max_paths=1, max_hops=2, max_candidates=1
    )
    assert [list(path.node_ids) for path in result.paths] == [
        ["entry", "short", "target"]
    ]


def test_critical_resource_can_lead_to_a_higher_impact_target() -> None:
    graph = nx.DiGraph()
    for node in [
        EntityNode(id="entry", label="Entry", type=EntityType.ATTACKER, entry_prior=1),
        EntityNode(id="low", label="Low", type=EntityType.RESOURCE, criticality=10),
        EntityNode(id="high", label="High", type=EntityType.RESOURCE, criticality=100),
    ]:
        graph.add_node(node.id, entity=node)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for index, (source, target) in enumerate([("entry", "low"), ("low", "high")]):
        graph.add_edge(
            source,
            target,
            edge=RelationshipEdge(
                id=f"edge-{index}",
                source=source,
                target=target,
                type=RelationshipType.OBSERVED,
                feasibility=1,
                evidence_ids=(f"event-{index}",),
                first_seen=now,
                last_seen=now,
            ),
        )

    paths = PathAnalyzer().analyze(graph, max_paths=2, max_hops=2).paths
    assert list(paths[0].node_ids) == ["entry", "low", "high"]
    assert list(paths[1].node_ids) == ["entry", "low"]
