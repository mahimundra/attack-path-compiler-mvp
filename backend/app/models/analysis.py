"""Attack-path and remediation API contracts."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExplainableStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    position: int = Field(ge=1)
    source_id: str
    target_id: str
    relationship: str
    feasibility: float = Field(gt=0.0, le=1.0)
    evidence_ids: tuple[str, ...]
    explanation: str


class AttackPath(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rank: int = Field(ge=1)
    node_ids: tuple[str, ...] = Field(min_length=2)
    edge_ids: tuple[str, ...] = Field(min_length=1)
    score: float = Field(ge=0.0, le=1.0)
    exposure_index: float = Field(ge=0.0, le=100.0)
    entry_prior: float = Field(ge=0.0, le=1.0)
    target_criticality: float = Field(ge=0.0, le=100.0)
    steps: tuple[ExplainableStep, ...]

    @model_validator(mode="after")
    def path_shapes_match(self) -> "AttackPath":
        if len(self.edge_ids) != len(self.node_ids) - 1:
            raise ValueError("a path must contain exactly one edge per hop")
        if len(self.steps) != len(self.edge_ids):
            raise ValueError("steps must describe every edge")
        if len(set(self.node_ids)) != len(self.node_ids):
            raise ValueError("attack paths must be loopless")
        return self


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_paths: int = Field(default=10, ge=1, le=10)
    max_hops: int = Field(default=8, ge=1, le=8)
    max_candidates: int = Field(default=200, ge=1, le=200)


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    paths: list[AttackPath]
    candidate_count: int = Field(ge=0)
    exposure_index: float = Field(ge=0.0, le=100.0)
    reachable_critical_assets: int = Field(ge=0)
    highest_risk_score: float = Field(ge=0.0, le=100.0)
    approximate: bool = False


class MetricSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    exposure_index: float = Field(ge=0.0, le=100.0)
    reachable_critical_assets: int = Field(ge=0)
    highest_risk_score: float = Field(ge=0.0, le=100.0)
    path_count: int = Field(ge=0)


class ControlKind(StrEnum):
    NODE = "node"
    EDGE = "edge"


class ControlOption(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=128)
    label: str = Field(min_length=1, max_length=256)
    kind: ControlKind
    target_id: str = Field(min_length=1, max_length=128)
    operational_cost: float = Field(gt=0.0, le=100.0, allow_inf_nan=False)
    description: str = ""


class InterventionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_controls: list[ControlOption] | None = Field(default=None, max_length=500)


class SimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_ids: list[str] = Field(default_factory=list, max_length=500)
    max_paths: int = Field(default=10, ge=1, le=10)


class RemediationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    selected_controls: list[ControlOption]
    cut_value: float = Field(ge=0.0)
    total_cost: float = Field(ge=0.0)
    complete_cut: bool
    message: str
    before_max_score: float = Field(ge=0.0, le=1.0)
    after_max_score: float = Field(ge=0.0, le=1.0)
    before: MetricSnapshot
    after: MetricSnapshot
    cut_edge_ids: list[str] = Field(default_factory=list)
    cut_node_ids: list[str] = Field(default_factory=list)
    residual_paths: list[AttackPath]
