"""Normalized event contract used by every ingestion adapter."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventSource(StrEnum):
    AUTH = "auth"
    ENDPOINT = "endpoint"
    NETWORK = "network"
    CLOUD = "cloud"
    IDENTITY = "identity"
    DATA = "data"


class EventType(StrEnum):
    NETWORK_CONNECTION = "network_connection"
    AUTHENTICATION = "authentication"
    DEVICE_SESSION = "device_session"
    ROLE_ASSUMPTION = "role_assumption"
    DATA_ACCESS = "data_access"
    BENIGN_ACTIVITY = "benign_activity"


class NormalizedSecurityEvent(BaseModel):
    """A strict, source-independent security observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(min_length=1, max_length=128)
    timestamp: datetime
    source: EventSource
    event_type: EventType
    source_ref: str = Field(min_length=1, max_length=256)
    target_ref: str = Field(min_length=1, max_length=256)
    session_id: str | None = Field(default=None, max_length=128)
    success: bool = True
    transition_feasibility: float = Field(default=0.5, ge=0.000001, le=1.0)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("attributes")
    @classmethod
    def json_safe_attributes(cls, value: dict[str, Any]) -> dict[str, Any]:
        # Validation here avoids surprising non-serializable state in the store.
        from json import dumps

        dumps(value, sort_keys=True)
        return value
