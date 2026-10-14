"""Compile correlated telemetry into evidence and projected graphs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import networkx as nx

from backend.app.models.events import NormalizedSecurityEvent
from backend.app.models.graph import EntityNode, RelationshipEdge
from backend.app.services.correlator import EventCorrelator
from backend.app.services.normalizer import deterministic_id


@dataclass
class CompiledGraph:
    evidence: nx.MultiDiGraph
    projected: nx.DiGraph


class GraphCompiler:
    def __init__(self, correlator: EventCorrelator | None = None) -> None:
        self.correlator = correlator or EventCorrelator()

    def compile(
        self,
        inventory: Iterable[EntityNode],
        events: Iterable[NormalizedSecurityEvent],
    ) -> CompiledGraph:
        nodes = sorted(inventory, key=lambda node: node.id)
        transitions = self.correlator.correlate(events, nodes)
        evidence = nx.MultiDiGraph()
        for node in nodes:
            evidence.add_node(node.id, entity=node)

        for ordinal, transition in enumerate(transitions):
            edge_id = deterministic_id(
                "edge",
                {
                    "ordinal": ordinal,
                    "source": transition.source,
                    "target": transition.target,
                    "relationship": transition.relationship,
                    "evidence": transition.evidence_ids,
                },
            )
            edge = RelationshipEdge(
                id=edge_id,
                source=transition.source,
                target=transition.target,
                type=transition.relationship,
                feasibility=transition.feasibility,
                evidence_ids=transition.evidence_ids,
                first_seen=transition.timestamp,
                last_seen=transition.timestamp,
                metadata={"session_id": transition.session_id},
            )
            evidence.add_edge(edge.source, edge.target, key=edge.id, edge=edge)

        projected = nx.DiGraph()
        for node_id, attrs in evidence.nodes(data=True):
            projected.add_node(node_id, **attrs)

        grouped: dict[tuple[str, str], list[RelationshipEdge]] = {}
        for source, target, _key, attrs in evidence.edges(keys=True, data=True):
            grouped.setdefault((source, target), []).append(attrs["edge"])
        for (source, target), parallel in sorted(grouped.items()):
            ordered = sorted(parallel, key=lambda edge: edge.id)
            strongest = min(
                ordered,
                key=lambda edge: (-edge.feasibility, edge.id),
            )
            evidence_ids = tuple(
                sorted({item for edge in ordered for item in edge.evidence_ids})
            )
            projected_edge = RelationshipEdge(
                id=deterministic_id("projected", {"source": source, "target": target}),
                source=source,
                target=target,
                type=strongest.type,
                feasibility=max(edge.feasibility for edge in ordered),
                evidence_ids=evidence_ids,
                first_seen=min(edge.first_seen for edge in ordered),
                last_seen=max(edge.last_seen for edge in ordered),
                metadata={"evidence_edge_ids": [edge.id for edge in ordered]},
            )
            projected.add_edge(source, target, edge=projected_edge)
        return CompiledGraph(evidence=evidence, projected=projected)


def graph_edges(graph: nx.MultiDiGraph | nx.DiGraph) -> list[RelationshipEdge]:
    if graph.is_multigraph():
        values = (
            attrs["edge"] for _u, _v, _key, attrs in graph.edges(keys=True, data=True)
        )
    else:
        values = (attrs["edge"] for _u, _v, attrs in graph.edges(data=True))
    return sorted(values, key=lambda edge: edge.id)
