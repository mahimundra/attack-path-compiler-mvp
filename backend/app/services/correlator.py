"""Explicit, deterministic alias and session correlation rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from backend.app.models.events import EventType, NormalizedSecurityEvent
from backend.app.models.graph import EntityNode, RelationshipType
from backend.app.services.normalizer import alias_index, resolve_exact


@dataclass(frozen=True)
class CorrelatedTransition:
    source: str
    target: str
    relationship: RelationshipType
    feasibility: float
    evidence_ids: tuple[str, ...]
    timestamp: datetime
    session_id: str | None


_RELATIONSHIPS = {
    EventType.NETWORK_CONNECTION: RelationshipType.TARGETED,
    EventType.AUTHENTICATION: RelationshipType.AUTHENTICATED_TO,
    EventType.DEVICE_SESSION: RelationshipType.SESSION_ON,
    EventType.ROLE_ASSUMPTION: RelationshipType.ASSUMED_ROLE,
    EventType.DATA_ACCESS: RelationshipType.ACCESSED,
    EventType.BENIGN_ACTIVITY: RelationshipType.OBSERVED,
}


class EventCorrelator:
    """Correlate only exact aliases and exact session IDs; no fuzzy matching."""

    def correlate(
        self,
        events: Iterable[NormalizedSecurityEvent],
        inventory: Iterable[EntityNode],
    ) -> list[CorrelatedTransition]:
        aliases = alias_index(inventory)
        sessions: dict[str, dict[str, tuple[str, str]]] = {}
        transitions: list[CorrelatedTransition] = []
        for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
            if not event.success:
                continue
            source = resolve_exact(event.source_ref, aliases)
            target = resolve_exact(event.target_ref, aliases)
            evidence = [event.event_id]
            session = sessions.setdefault(event.session_id, {}) if event.session_id else {}

            if event.event_type == EventType.NETWORK_CONNECTION and event.session_id:
                session["network"] = (target, event.event_id)
            elif event.event_type in {EventType.AUTHENTICATION, EventType.DEVICE_SESSION}:
                if event.session_id and "network" in session:
                    network_identity, predecessor = session["network"]
                    if network_identity != source:
                        continue
                    evidence.append(predecessor)
                if event.session_id:
                    session["device"] = (target, event.event_id)
            elif event.event_type == EventType.ROLE_ASSUMPTION:
                if event.session_id:
                    device = session.get("device")
                    if device is None or device[0] != source:
                        continue
                    evidence.append(device[1])
                    session["role"] = (target, event.event_id)
            elif event.event_type == EventType.DATA_ACCESS and event.session_id:
                role = session.get("role")
                if role is None or role[0] != source:
                    continue
                evidence.append(role[1])

            transitions.append(
                CorrelatedTransition(
                    source=source,
                    target=target,
                    relationship=_RELATIONSHIPS[event.event_type],
                    feasibility=event.transition_feasibility,
                    evidence_ids=tuple(dict.fromkeys(evidence)),
                    timestamp=event.timestamp,
                    session_id=event.session_id,
                )
            )
        return transitions
