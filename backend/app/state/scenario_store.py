"""Thread-safe in-memory scenario store for the hackathon MVP."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Iterable

from backend.app.models.analysis import ControlKind, ControlOption
from backend.app.models.events import NormalizedSecurityEvent
from backend.app.models.graph import EntityNode
from backend.app.services.graph_compiler import CompiledGraph, GraphCompiler
from backend.app.services.normalizer import deterministic_id
from backend.app.simulation.generator import ScenarioFixture, generate_demo_scenario


@dataclass
class ScenarioState:
    scenario_id: str
    inventory: tuple[EntityNode, ...]
    events: tuple[NormalizedSecurityEvent, ...]
    controls: tuple[ControlOption, ...]
    graph: CompiledGraph
    seed: int | None = None


class ScenarioStore:
    def __init__(self, compiler: GraphCompiler | None = None) -> None:
        self._compiler = compiler or GraphCompiler()
        self._states: dict[str, ScenarioState] = {}
        self._baselines: dict[str, tuple[tuple[EntityNode, ...], tuple[NormalizedSecurityEvent, ...], tuple[ControlOption, ...], int | None]] = {}
        self._lock = RLock()

    def load_demo(self, *, event_count: int = 2000) -> ScenarioState:
        fixture = generate_demo_scenario(event_count=event_count)
        return self.load_fixture(fixture)

    def load_fixture(self, fixture: ScenarioFixture) -> ScenarioState:
        return self.put(
            fixture.scenario_id,
            fixture.inventory,
            fixture.events,
            fixture.controls,
            seed=fixture.seed,
        )

    def put(
        self,
        scenario_id: str,
        inventory: Iterable[EntityNode],
        events: Iterable[NormalizedSecurityEvent],
        controls: Iterable[ControlOption] | None = None,
        *,
        seed: int | None = None,
    ) -> ScenarioState:
        nodes = tuple(sorted(inventory, key=lambda node: node.id))
        observations = tuple(sorted(events, key=lambda event: (event.timestamp, event.event_id)))
        chosen_controls = tuple(controls or self._default_controls(nodes))
        graph = self._compiler.compile(nodes, observations)
        state = ScenarioState(
            scenario_id=scenario_id,
            inventory=nodes,
            events=observations,
            controls=chosen_controls,
            graph=graph,
            seed=seed,
        )
        with self._lock:
            self._states[scenario_id] = state
            self._baselines[scenario_id] = (nodes, observations, chosen_controls, seed)
        return state

    def get(self, scenario_id: str) -> ScenarioState:
        with self._lock:
            try:
                return self._states[scenario_id]
            except KeyError as exc:
                raise KeyError(f"unknown scenario: {scenario_id}") from exc

    def exists(self, scenario_id: str) -> bool:
        with self._lock:
            return scenario_id in self._states or scenario_id in self._baselines

    def reset(self, scenario_id: str) -> ScenarioState:
        with self._lock:
            try:
                nodes, events, controls, seed = self._baselines[scenario_id]
            except KeyError as exc:
                raise KeyError(f"unknown scenario: {scenario_id}") from exc
        graph = self._compiler.compile(nodes, events)
        state = ScenarioState(scenario_id, nodes, events, controls, graph, seed)
        with self._lock:
            self._states[scenario_id] = state
        return state

    @staticmethod
    def _default_controls(nodes: tuple[EntityNode, ...]) -> tuple[ControlOption, ...]:
        return tuple(
            ControlOption(
                id=deterministic_id("ctl", node.id),
                label=f"Contain {node.label}",
                kind=ControlKind.NODE,
                target_id=node.id,
                operational_cost=5,
            )
            for node in nodes
            if node.entry_prior > 0 or node.criticality == 0
        )


store = ScenarioStore()
