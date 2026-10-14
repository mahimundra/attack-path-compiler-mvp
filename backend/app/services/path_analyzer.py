"""Risk-ranked loopless attack-path analysis."""

from __future__ import annotations

import math
from dataclasses import dataclass
from heapq import heappop, heappush

import networkx as nx

from backend.app.models.analysis import AttackPath, ExplainableStep, MetricSnapshot
from backend.app.models.graph import EntityNode, EntityType, RelationshipEdge

@dataclass(frozen=True)
class PathAnalysis:
    paths: list[AttackPath]
    candidate_count: int
    approximate: bool


def metric_snapshot(
    result: PathAnalysis, graph: nx.DiGraph | None = None
) -> MetricSnapshot:
    scores = [path.score for path in result.paths]
    reachable_assets = {path.node_ids[-1] for path in result.paths if path.node_ids}
    if graph is not None:
        entries = [
            node_id
            for node_id, attrs in graph.nodes(data=True)
            if attrs["entity"].entry_prior > 0
        ]
        critical_assets = [
            node_id
            for node_id, attrs in graph.nodes(data=True)
            if attrs["entity"].type == EntityType.RESOURCE
            and attrs["entity"].criticality > 0
        ]
        reachable_assets = {
            target
            for target in critical_assets
            if any(nx.has_path(graph, entry, target) for entry in entries)
        }
    return MetricSnapshot(
        exposure_index=100 * (1 - math.exp(-sum(scores))),
        reachable_critical_assets=len(reachable_assets),
        highest_risk_score=(scores[0] * 100) if scores else 0,
        path_count=len(result.paths),
    )


class PathAnalyzer:
    def analyze(
        self,
        graph: nx.DiGraph,
        *,
        max_paths: int = 10,
        max_hops: int = 8,
        max_candidates: int = 200,
    ) -> PathAnalysis:
        # Uniform-cost enumeration over path states is Dijkstra's algorithm lifted
        # to simple paths. The hop bound is enforced while expanding, so an
        # abundance of attractive but overlong paths cannot starve valid routes.
        queue: list[tuple[float, tuple[str, ...], bool]] = []
        for node_id, attrs in sorted(graph.nodes(data=True)):
            node: EntityNode = attrs["entity"]
            if node.entry_prior > 0:
                heappush(queue, (-math.log(node.entry_prior), (node_id,), False))

        raw_candidates: list[
            tuple[
                float,
                tuple[str, ...],
                tuple[str, ...],
                tuple[ExplainableStep, ...],
                float,
                float,
            ]
        ] = []
        expanded_states = 0
        max_states = max(1000, max_candidates * 50)
        truncated = False
        desired = min(max_paths, max_candidates)

        while queue and len(raw_candidates) < desired:
            cost, node_ids, finished = heappop(queue)
            expanded_states += 1
            if expanded_states > max_states:
                truncated = True
                break

            current = node_ids[-1]
            current_entity: EntityNode = graph.nodes[current]["entity"]
            if finished:
                entry: EntityNode = graph.nodes[node_ids[0]]["entity"]
                product = 1.0
                edge_ids: list[str] = []
                steps: list[ExplainableStep] = []
                for position, (source, destination) in enumerate(
                    zip(node_ids, node_ids[1:]), start=1
                ):
                    edge: RelationshipEdge = graph[source][destination]["edge"]
                    product *= edge.feasibility
                    edge_ids.append(edge.id)
                    steps.append(
                        ExplainableStep(
                            position=position,
                            source_id=source,
                            target_id=destination,
                            relationship=edge.type.value,
                            feasibility=edge.feasibility,
                            evidence_ids=edge.evidence_ids,
                            explanation=(
                                f"{edge.type.value.replace('_', ' ')} is supported by "
                                f"{len(edge.evidence_ids)} event(s)"
                            ),
                        )
                    )
                score = (
                    entry.entry_prior
                    * product
                    * (current_entity.criticality / 100)
                )
                raw_candidates.append(
                    (
                        score,
                        node_ids,
                        tuple(edge_ids),
                        tuple(steps),
                        entry.entry_prior,
                        current_entity.criticality,
                    )
                )
                continue

            if (
                len(node_ids) > 1
                and current_entity.type == EntityType.RESOURCE
                and current_entity.criticality > 0
            ):
                heappush(
                    queue,
                    (
                        cost - math.log(current_entity.criticality / 100),
                        node_ids,
                        True,
                    ),
                )

            if len(node_ids) - 1 >= max_hops:
                continue
            for successor in sorted(graph.successors(current)):
                if successor in node_ids:
                    continue
                edge: RelationshipEdge = graph[current][successor]["edge"]
                heappush(
                    queue,
                    (
                        cost - math.log(edge.feasibility),
                        (*node_ids, successor),
                        False,
                    ),
                )

        raw_candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
        paths = [
            AttackPath(
                rank=rank,
                node_ids=item[1],
                edge_ids=item[2],
                score=item[0],
                exposure_index=item[0] * 100,
                entry_prior=item[4],
                target_criticality=item[5],
                steps=item[3],
            )
            for rank, item in enumerate(raw_candidates[:max_paths], start=1)
        ]
        return PathAnalysis(
            paths=paths,
            candidate_count=len(raw_candidates),
            approximate=truncated,
        )
