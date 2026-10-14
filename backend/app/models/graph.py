"""Graph entity and evidence-edge contracts."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class EntityType(StrEnum):
    ATTACKER = "attacker"
    IDENTITY = "identity"
    DEVICE = "device"
    ROLE = "role"
    RESOURCE = "resource"


class RelationshipType(StrEnum):
    TARGETED = "targeted"
    AUTHENTICATED_TO = "authenticated_to"
    SESSION_ON = "session_on"
    ASSUMED_ROLE = "assumed_role"
    ACCESSED = "accessed"
    OBSERVED = "observed"


class EntityNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=128)
    label: str = Field(min_length=1, max_length=256)
    type: EntityType
    criticality: float = Field(default=0.0, ge=0.0, le=100.0)
    entry_prior: float = Field(default=0.0, ge=0.0, le=1.0)
    aliases: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("aliases")
    @classmethod
    def aliases_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("aliases must be unique")
        return value


class RelationshipEdge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=128)
    target: str = Field(min_length=1, max_length=128)
    type: RelationshipType
    feasibility: float = Field(ge=0.000001, le=1.0)
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    first_seen: datetime
    last_seen: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("first_seen", "last_seen")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("edge timestamps must include a timezone")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_range_and_evidence(self) -> "RelationshipEdge":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot precede first_seen")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("evidence_ids must be unique")
        return self


class GraphResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    nodes: list[EntityNode]
    evidence_edges: list[RelationshipEdge]
    projected_edges: list[RelationshipEdge]
