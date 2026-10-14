"""Operational-cost minimum cuts and non-mutating intervention simulation."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

import networkx as nx

from backend.app.models.analysis import ControlKind, ControlOption, RemediationResponse
from backend.app.models.graph import EntityNode, EntityType
from backend.app.services.path_analyzer import PathAnalyzer, metric_snapshot

FLOW_SOURCE = "__flow_source__"
FLOW_SINK = "__flow_sink__"


class RemediationEngine:
    def __init__(self, analyzer: PathAnalyzer | None = None) -> None:
        self.analyzer = analyzer or PathAnalyzer()

    @staticmethod
    def _edge_matches(control: ControlOption, source: str, target: str, edge_id: str) -> bool:
        return control.target_id in {edge_id, f"{source}->{target}"}

    def _control_targets(
        self, graph: nx.DiGraph, controls: Iterable[ControlOption]
    ) -> tuple[list[str], list[str]]:
        edge_ids: set[str] = set()
        node_ids: set[str] = set()
        for control in controls:
            if control.kind == ControlKind.NODE:
                node_ids.add(control.target_id)
                continue
            for source, target, attrs in graph.edges(data=True):
                if self._edge_matches(control, source, target, attrs["edge"].id):
                    edge_ids.add(attrs["edge"].id)
        return sorted(edge_ids), sorted(node_ids)

    def _validate_controls(
        self, graph: nx.DiGraph, controls: Iterable[ControlOption]
    ) -> list[ControlOption]:
        result = sorted(controls, key=lambda item: (item.operational_cost, item.id))
        edge_targets = {
            attrs["edge"].id for _u, _v, attrs in graph.edges(data=True)
        } | {f"{u}->{v}" for u, v in graph.edges()}
        for control in result:
            if control.kind == ControlKind.NODE and control.target_id not in graph:
                raise ValueError(f"control {control.id} targets an unknown node")
            if control.kind == ControlKind.EDGE and control.target_id not in edge_targets:
                raise ValueError(f"control {control.id} targets an unknown edge")
        if len({control.id for control in result}) != len(result):
            raise ValueError("control IDs must be unique")
        return result

    def recommend(
        self,
        scenario_id: str,
        graph: nx.DiGraph,
        controls: Iterable[ControlOption],
    ) -> RemediationResponse:
        candidates = self._validate_controls(graph, controls)
        finite_sum = sum(control.operational_cost for control in candidates)
        infinity = 1 + finite_sum
        by_node: dict[str, list[ControlOption]] = defaultdict(list)
        by_edge: dict[tuple[str, str], list[ControlOption]] = defaultdict(list)
        for control in candidates:
            if control.kind == ControlKind.NODE:
                by_node[control.target_id].append(control)
            else:
                for source, target, attrs in graph.edges(data=True):
                    if self._edge_matches(control, source, target, attrs["edge"].id):
                        by_edge[(source, target)].append(control)

        flow = nx.DiGraph()
        capacity_control: dict[tuple[str, str], ControlOption] = {}
        for node_id in sorted(graph.nodes):
            choices = by_node.get(node_id, [])
            chosen = min(choices, key=lambda item: (item.operational_cost, item.id)) if choices else None
            capacity = chosen.operational_cost if chosen else infinity
            edge = (f"{node_id}:in", f"{node_id}:out")
            flow.add_edge(*edge, capacity=capacity)
            if chosen:
                capacity_control[edge] = chosen

        for source, target in sorted(graph.edges):
            choices = by_edge.get((source, target), [])
            chosen = min(choices, key=lambda item: (item.operational_cost, item.id)) if choices else None
            capacity = chosen.operational_cost if chosen else infinity
            edge = (f"{source}:out", f"{target}:in")
            flow.add_edge(*edge, capacity=capacity)
            if chosen:
                capacity_control[edge] = chosen

        flow.add_node(FLOW_SOURCE)
        flow.add_node(FLOW_SINK)
        for node_id, attrs in sorted(graph.nodes(data=True)):
            node: EntityNode = attrs["entity"]
            if node.entry_prior > 0:
                flow.add_edge(FLOW_SOURCE, f"{node_id}:in", capacity=infinity)
            if node.type == EntityType.RESOURCE and node.criticality > 0:
                flow.add_edge(f"{node_id}:out", FLOW_SINK, capacity=infinity)

        cut_value, partition = nx.minimum_cut(
            flow, FLOW_SOURCE, FLOW_SINK, capacity="capacity"
        )
        reachable, non_reachable = partition
        cut_edges = {
            (source, target)
            for source in reachable
            for target in flow.successors(source)
            if target in non_reachable
        }
        selected = sorted(
            {capacity_control[edge] for edge in cut_edges if edge in capacity_control},
            key=lambda item: item.id,
        )
        complete_cut = cut_value < infinity
        residual = self.apply_controls(graph, selected)
        before = self.analyzer.analyze(graph)
        after = self.analyzer.analyze(residual)
        before_metrics = metric_snapshot(before, graph)
        after_metrics = metric_snapshot(after, residual)
        cut_edge_ids, cut_node_ids = self._control_targets(graph, selected)
        if after.paths:
            complete_cut = False
        message = (
            "Selected controls disconnect every modeled entry-to-target path."
            if complete_cut
            else "No practical complete cut exists with the supplied controls."
        )
        return RemediationResponse(
            scenario_id=scenario_id,
            selected_controls=selected,
            cut_value=float(cut_value),
            total_cost=sum(control.operational_cost for control in selected),
            complete_cut=complete_cut,
            message=message,
            before_max_score=before.paths[0].score if before.paths else 0,
            after_max_score=after.paths[0].score if after.paths else 0,
            before=before_metrics,
            after=after_metrics,
            cut_edge_ids=cut_edge_ids,
            cut_node_ids=cut_node_ids,
            residual_paths=after.paths,
        )

    def apply_controls(
        self, graph: nx.DiGraph, controls: Iterable[ControlOption]
    ) -> nx.DiGraph:
        clone = graph.copy()
        for control in sorted(controls, key=lambda item: item.id):
            if control.kind == ControlKind.NODE:
                if clone.has_node(control.target_id):
                    clone.remove_node(control.target_id)
            else:
                for source, target, attrs in list(clone.edges(data=True)):
                    if self._edge_matches(control, source, target, attrs["edge"].id):
                        clone.remove_edge(source, target)
        return clone

    def simulate(
        self,
        scenario_id: str,
        graph: nx.DiGraph,
        controls: Iterable[ControlOption],
        *,
        max_paths: int = 10,
    ) -> RemediationResponse:
        selected = self._validate_controls(graph, controls)
        before = self.analyzer.analyze(graph, max_paths=max_paths)
        residual_graph = self.apply_controls(graph, selected)
        after = self.analyzer.analyze(residual_graph, max_paths=max_paths)
        before_metrics = metric_snapshot(before, graph)
        after_metrics = metric_snapshot(after, residual_graph)
        cut_edge_ids, cut_node_ids = self._control_targets(graph, selected)
        complete = not after.paths and not after.approximate
        return RemediationResponse(
            scenario_id=scenario_id,
            selected_controls=selected,
            cut_value=sum(control.operational_cost for control in selected),
            total_cost=sum(control.operational_cost for control in selected),
            complete_cut=complete,
            message=(
                "Selected controls disconnect every modeled entry-to-target path."
                if complete
                else "Residual modeled attack paths remain after these controls."
            ),
            before_max_score=before.paths[0].score if before.paths else 0,
            after_max_score=after.paths[0].score if after.paths else 0,
            before=before_metrics,
            after=after_metrics,
            cut_edge_ids=cut_edge_ids,
            cut_node_ids=cut_node_ids,
            residual_paths=after.paths,
        )
