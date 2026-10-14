"""FastAPI endpoints for scenario lifecycle and analysis."""

from __future__ import annotations

import csv
import json
import re
from typing import Annotated, Any

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from backend.app.ingestion.adapters import parse_uploaded_events
from backend.app.models.analysis import (
    AnalysisRequest,
    AnalysisResponse,
    InterventionRequest,
    RemediationResponse,
    SimulationRequest,
)
from backend.app.models.events import NormalizedSecurityEvent
from backend.app.models.graph import GraphResponse
from backend.app.services.graph_compiler import graph_edges
from backend.app.services.normalizer import EventNormalizer, derive_inventory
from backend.app.services.path_analyzer import PathAnalyzer, metric_snapshot
from backend.app.services.remediation import RemediationEngine
from backend.app.simulation.generator import DEMO_SCENARIO_ID
from backend.app.state.scenario_store import ScenarioState, store

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_UPLOAD_EVENTS = 10_000
SCENARIO_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

router = APIRouter()
normalizer = EventNormalizer()
analyzer = PathAnalyzer()
remediation = RemediationEngine(analyzer)


class LoadScenarioRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = DEMO_SCENARIO_ID
    event_count: int = Field(default=2000, ge=12, le=10_000)


class ScenarioSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    event_count: int
    node_count: int
    evidence_edge_count: int
    projected_edge_count: int
    seed: int | None


class EventPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    total: int
    offset: int
    limit: int
    events: list[NormalizedSecurityEvent]


def _state(scenario_id: str) -> ScenarioState:
    try:
        return store.get(scenario_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _summary(state: ScenarioState) -> ScenarioSummary:
    return ScenarioSummary(
        scenario_id=state.scenario_id,
        event_count=len(state.events),
        node_count=state.graph.evidence.number_of_nodes(),
        evidence_edge_count=state.graph.evidence.number_of_edges(),
        projected_edge_count=state.graph.projected.number_of_edges(),
        seed=state.seed,
    )


@router.get("/health")
@router.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/api/scenarios/load", response_model=ScenarioSummary)
def load_scenario(request: LoadScenarioRequest) -> ScenarioSummary:
    if request.scenario_id != DEMO_SCENARIO_ID:
        raise HTTPException(status_code=404, detail="only apc-demo-01 is built in")
    return _summary(store.load_demo(event_count=request.event_count))


@router.post("/api/scenarios/upload", response_model=ScenarioSummary, status_code=201)
async def upload_scenario(
    file: Annotated[UploadFile, File(description="JSON, JSONL, or CSV events")],
    scenario_id: Annotated[str, Form()] = "uploaded-scenario",
) -> ScenarioSummary:
    if not SCENARIO_ID_PATTERN.fullmatch(scenario_id):
        raise HTTPException(status_code=422, detail="invalid scenario_id")
    if scenario_id == DEMO_SCENARIO_ID or store.exists(scenario_id):
        raise HTTPException(status_code=409, detail="scenario_id is reserved or already exists")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="upload exceeds 5 MiB")
    try:
        rows = parse_uploaded_events(content, file.filename, file.content_type)
        if len(rows) > MAX_UPLOAD_EVENTS:
            raise ValueError(f"upload exceeds {MAX_UPLOAD_EVENTS} events")
        events = normalizer.normalize_many(rows)
        inventory = derive_inventory(events)
        state = store.put(scenario_id, inventory, events)
    except (csv.Error, ValueError, ValidationError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"malformed upload: {exc}") from exc
    return _summary(state)


@router.get("/api/scenarios/{scenario_id}/graph", response_model=GraphResponse)
def get_graph(scenario_id: str) -> GraphResponse:
    state = _state(scenario_id)
    return GraphResponse(
        scenario_id=scenario_id,
        nodes=list(state.inventory),
        evidence_edges=graph_edges(state.graph.evidence),
        projected_edges=graph_edges(state.graph.projected),
    )


@router.post("/api/scenarios/{scenario_id}/analyze", response_model=AnalysisResponse)
def analyze_scenario(scenario_id: str, request: AnalysisRequest) -> AnalysisResponse:
    state = _state(scenario_id)
    result = analyzer.analyze(
        state.graph.projected,
        max_paths=request.max_paths,
        max_hops=request.max_hops,
        max_candidates=request.max_candidates,
    )
    metrics = metric_snapshot(result, state.graph.projected)
    return AnalysisResponse(
        scenario_id=scenario_id,
        paths=result.paths,
        candidate_count=result.candidate_count,
        exposure_index=metrics.exposure_index,
        reachable_critical_assets=metrics.reachable_critical_assets,
        highest_risk_score=metrics.highest_risk_score,
        approximate=result.approximate,
    )


@router.post(
    "/api/scenarios/{scenario_id}/interventions",
    response_model=RemediationResponse,
)
def interventions(
    scenario_id: str, request: InterventionRequest
) -> RemediationResponse:
    state = _state(scenario_id)
    controls = (
        request.candidate_controls
        if request.candidate_controls is not None
        else list(state.controls)
    )
    try:
        return remediation.recommend(scenario_id, state.graph.projected, controls)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/scenarios/{scenario_id}/simulate", response_model=RemediationResponse)
def simulate(scenario_id: str, request: SimulationRequest) -> RemediationResponse:
    state = _state(scenario_id)
    by_id = {control.id: control for control in state.controls}
    unknown = sorted(set(request.control_ids) - by_id.keys())
    if unknown:
        raise HTTPException(status_code=400, detail=f"unknown controls: {unknown}")
    selected = [by_id[control_id] for control_id in dict.fromkeys(request.control_ids)]
    return remediation.simulate(
        scenario_id,
        state.graph.projected,
        selected,
        max_paths=request.max_paths,
    )


@router.post("/api/scenarios/{scenario_id}/reset", response_model=ScenarioSummary)
def reset(scenario_id: str) -> ScenarioSummary:
    try:
        return _summary(store.reset(scenario_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/scenarios/{scenario_id}/events", response_model=EventPage)
def get_events(
    scenario_id: str,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> EventPage:
    state = _state(scenario_id)
    return EventPage(
        scenario_id=scenario_id,
        total=len(state.events),
        offset=offset,
        limit=limit,
        events=list(state.events[offset:offset + limit]),
    )
