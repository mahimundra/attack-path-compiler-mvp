"""Deterministic raw-event normalization and exact alias resolution."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from backend.app.models.events import EventType, NormalizedSecurityEvent
from backend.app.models.graph import EntityNode, EntityType


def deterministic_id(prefix: str, value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return f"{prefix}-{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:20]}"


class EventNormalizer:
    def normalize_many(self, rows: Iterable[dict[str, Any]]) -> list[NormalizedSecurityEvent]:
        normalized: list[NormalizedSecurityEvent] = []
        for ordinal, raw in enumerate(rows):
            row = dict(raw)
            if not row.get("event_id"):
                row["event_id"] = deterministic_id("evt", {"ordinal": ordinal, "row": row})
            if not row.get("timestamp"):
                # Missing timestamps use a deterministic epoch, never wall-clock time.
                row["timestamp"] = datetime(1970, 1, 1, tzinfo=timezone.utc)
            row.setdefault("attributes", {})
            normalized.append(NormalizedSecurityEvent.model_validate(row))
        ids = [event.event_id for event in normalized]
        if len(ids) != len(set(ids)):
            raise ValueError("event_id values must be unique")
        return sorted(normalized, key=lambda event: (event.timestamp, event.event_id))


def alias_index(inventory: Iterable[EntityNode]) -> dict[str, str]:
    index: dict[str, str] = {}
    for node in sorted(inventory, key=lambda item: item.id):
        for alias in (node.id, node.label, *node.aliases):
            existing = index.get(alias)
            if existing is not None and existing != node.id:
                raise ValueError(f"ambiguous exact alias: {alias}")
            index[alias] = node.id
    return index


def resolve_exact(reference: str, aliases: dict[str, str]) -> str:
    try:
        return aliases[reference]
    except KeyError as exc:
        raise ValueError(f"unknown entity alias: {reference}") from exc


def _slug(reference: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", reference.lower()).strip("-")
    return slug[:70] or "entity"


def derive_inventory(events: Iterable[NormalizedSecurityEvent]) -> list[EntityNode]:
    """Infer a conservative canonical inventory for uploaded normalized events."""

    inferred: dict[str, EntityType] = {}
    labels: dict[str, str] = {}

    def add(reference: str, entity_type: EntityType) -> None:
        inferred.setdefault(reference, entity_type)
        labels.setdefault(reference, reference)

    for event in events:
        if event.event_type == EventType.NETWORK_CONNECTION:
            add(event.source_ref, EntityType.ATTACKER)
            add(event.target_ref, EntityType.IDENTITY)
        elif event.event_type in {EventType.AUTHENTICATION, EventType.DEVICE_SESSION}:
            add(event.source_ref, EntityType.IDENTITY)
            add(event.target_ref, EntityType.DEVICE)
        elif event.event_type == EventType.ROLE_ASSUMPTION:
            add(event.source_ref, EntityType.DEVICE)
            add(event.target_ref, EntityType.ROLE)
        elif event.event_type == EventType.DATA_ACCESS:
            add(event.source_ref, EntityType.ROLE)
            add(event.target_ref, EntityType.RESOURCE)
        else:
            add(event.source_ref, EntityType.IDENTITY)
            add(event.target_ref, EntityType.DEVICE)

    return [
        EntityNode(
            id=f"{entity_type.value}-{_slug(reference)}-{deterministic_id('x', reference)[2:10]}",
            label=labels[reference],
            type=entity_type,
            criticality=100 if entity_type == EntityType.RESOURCE else 0,
            entry_prior=0.5 if entity_type == EntityType.ATTACKER else 0,
            aliases=(reference,),
            metadata={"inferred": True},
        )
        for reference, entity_type in sorted(inferred.items())
    ]
