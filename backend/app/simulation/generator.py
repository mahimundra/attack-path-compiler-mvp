"""Seeded, reproducible security telemetry for the built-in demo."""

from __future__ import annotations

import csv
import io
import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.app.models.analysis import ControlKind, ControlOption
from backend.app.models.events import EventSource, EventType, NormalizedSecurityEvent
from backend.app.models.graph import EntityNode, EntityType

DEFAULT_SEED = 424242
DEMO_SCENARIO_ID = "apc-demo-01"
BASE_TIME = datetime(2026, 1, 15, 9, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class ScenarioFixture:
    scenario_id: str
    seed: int
    inventory: tuple[EntityNode, ...]
    events: tuple[NormalizedSecurityEvent, ...]
    controls: tuple[ControlOption, ...]
    ground_truth: dict[str, Any]


def _event(
    index: int,
    *,
    offset_seconds: int,
    source: EventSource,
    event_type: EventType,
    source_ref: str,
    target_ref: str,
    feasibility: float,
    session_id: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> NormalizedSecurityEvent:
    return NormalizedSecurityEvent(
        event_id=f"evt-{index:06d}",
        timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
        source=source,
        event_type=event_type,
        source_ref=source_ref,
        target_ref=target_ref,
        session_id=session_id,
        transition_feasibility=feasibility,
        attributes=attributes or {},
    )


def _inventory() -> list[EntityNode]:
    entities = [
        EntityNode(
            id="attacker-ip-198-51-100-77",
            label="198.51.100.77",
            type=EntityType.ATTACKER,
            entry_prior=0.92,
            aliases=("198.51.100.77", "ip:198.51.100.77"),
            metadata={"zone": "internet"},
        ),
        EntityNode(
            id="identity-ana-rao",
            label="Ana Rao",
            type=EntityType.IDENTITY,
            aliases=("Ana Rao", "ana.rao", "ana.rao@example.test"),
        ),
        EntityNode(
            id="device-eng-lt-042",
            label="ENG-LT-042",
            type=EntityType.DEVICE,
            aliases=("ENG-LT-042", "eng-lt-042.example.test"),
        ),
        EntityNode(
            id="role-etl-operator",
            label="etl-operator",
            type=EntityType.ROLE,
            aliases=("etl-operator", "arn:demo:iam::role/etl-operator"),
        ),
        EntityNode(
            id="role-analytics-reader",
            label="analytics-reader",
            type=EntityType.ROLE,
            aliases=("analytics-reader",),
        ),
        EntityNode(
            id="identity-legacy-etl",
            label="legacy-etl-service",
            type=EntityType.IDENTITY,
            aliases=("legacy-etl-service", "svc_legacy_etl"),
        ),
        EntityNode(
            id="device-batch-007",
            label="BATCH-007",
            type=EntityType.DEVICE,
            aliases=("BATCH-007",),
        ),
        EntityNode(
            id="resource-customer-exports-prod",
            label="customer-exports-prod",
            type=EntityType.RESOURCE,
            criticality=100,
            aliases=("customer-exports-prod", "s3://customer-exports-prod"),
            metadata={"classification": "restricted"},
        ),
    ]
    for i in range(30):
        entities.extend(
            (
                EntityNode(
                    id=f"noise-user-{i:02d}",
                    label=f"Noise User {i:02d}",
                    type=EntityType.IDENTITY,
                    aliases=(f"noise.user{i:02d}",),
                ),
                EntityNode(
                    id=f"noise-device-{i:02d}",
                    label=f"NOISE-LT-{i:02d}",
                    type=EntityType.DEVICE,
                    aliases=(f"NOISE-LT-{i:02d}",),
                ),
                EntityNode(
                    id=f"noise-resource-{i:02d}",
                    label=f"internal-dataset-{i:02d}",
                    type=EntityType.RESOURCE,
                    criticality=20,
                    aliases=(f"internal-dataset-{i:02d}",),
                ),
            )
        )
    return entities


def generate_demo_scenario(
    *, seed: int = DEFAULT_SEED, event_count: int = 2000
) -> ScenarioFixture:
    """Create the canonical demo. ``event_count`` may be reduced by unit tests."""

    if event_count < 12:
        raise ValueError("event_count must be at least 12")
    events = [
        # Highest-risk canonical path.
        _event(1, offset_seconds=1, source=EventSource.NETWORK,
               event_type=EventType.NETWORK_CONNECTION, source_ref="198.51.100.77",
               target_ref="ana.rao", feasibility=0.95, session_id="sess-primary"),
        _event(2, offset_seconds=2, source=EventSource.AUTH,
               event_type=EventType.AUTHENTICATION, source_ref="ana.rao",
               target_ref="ENG-LT-042", feasibility=0.94, session_id="sess-primary"),
        _event(3, offset_seconds=3, source=EventSource.CLOUD,
               event_type=EventType.ROLE_ASSUMPTION, source_ref="ENG-LT-042",
               target_ref="etl-operator", feasibility=0.93, session_id="sess-primary"),
        _event(4, offset_seconds=4, source=EventSource.DATA,
               event_type=EventType.DATA_ACCESS, source_ref="etl-operator",
               target_ref="customer-exports-prod", feasibility=0.92,
               session_id="sess-primary"),
        # Alternative through a lower privilege role.
        _event(5, offset_seconds=8, source=EventSource.CLOUD,
               event_type=EventType.ROLE_ASSUMPTION, source_ref="ENG-LT-042",
               target_ref="analytics-reader", feasibility=0.72,
               session_id="sess-primary"),
        _event(6, offset_seconds=9, source=EventSource.DATA,
               event_type=EventType.DATA_ACCESS, source_ref="analytics-reader",
               target_ref="customer-exports-prod", feasibility=0.78,
               session_id="sess-primary"),
        # Alternative service-account route.
        _event(7, offset_seconds=12, source=EventSource.NETWORK,
               event_type=EventType.NETWORK_CONNECTION, source_ref="198.51.100.77",
               target_ref="svc_legacy_etl", feasibility=0.67,
               session_id="sess-legacy"),
        _event(8, offset_seconds=13, source=EventSource.AUTH,
               event_type=EventType.AUTHENTICATION, source_ref="svc_legacy_etl",
               target_ref="BATCH-007", feasibility=0.74, session_id="sess-legacy"),
        _event(9, offset_seconds=14, source=EventSource.CLOUD,
               event_type=EventType.ROLE_ASSUMPTION, source_ref="BATCH-007",
               target_ref="etl-operator", feasibility=0.76, session_id="sess-legacy"),
        # Duplicate evidence demonstrates MultiDiGraph retention and max projection.
        _event(10, offset_seconds=20, source=EventSource.AUTH,
               event_type=EventType.AUTHENTICATION, source_ref="ana.rao@example.test",
               target_ref="eng-lt-042.example.test", feasibility=0.90,
               session_id="sess-primary"),
        _event(11, offset_seconds=21, source=EventSource.DATA,
               event_type=EventType.DATA_ACCESS, source_ref="arn:demo:iam::role/etl-operator",
               target_ref="s3://customer-exports-prod", feasibility=0.88,
               session_id="sess-primary"),
        _event(12, offset_seconds=22, source=EventSource.ENDPOINT,
               event_type=EventType.DEVICE_SESSION, source_ref="ana.rao",
               target_ref="ENG-LT-042", feasibility=0.80, session_id="sess-primary"),
    ]

    rng = random.Random(seed)
    for index in range(13, event_count + 1):
        n = rng.randrange(30)
        auth = index % 2 == 0
        events.append(
            _event(
                index,
                offset_seconds=60 + index,
                source=EventSource.AUTH if auth else EventSource.DATA,
                event_type=EventType.BENIGN_ACTIVITY,
                source_ref=f"noise.user{n:02d}" if auth else f"NOISE-LT-{n:02d}",
                target_ref=(
                    f"NOISE-LT-{n:02d}" if auth else f"internal-dataset-{n:02d}"
                ),
                feasibility=round(rng.uniform(0.05, 0.35), 6),
                session_id=f"noise-session-{n:02d}",
                attributes={"benign": True, "sequence": index},
            )
        )

    controls = (
        ControlOption(
            id="ctl-disable-ana",
            label="Suspend Ana Rao",
            kind=ControlKind.NODE,
            target_id="identity-ana-rao",
            operational_cost=4,
            description="Suspend the compromised identity pending investigation.",
        ),
        ControlOption(
            id="ctl-isolate-eng-lt-042",
            label="Isolate ENG-LT-042",
            kind=ControlKind.NODE,
            target_id="device-eng-lt-042",
            operational_cost=3,
        ),
        ControlOption(
            id="ctl-revoke-etl",
            label="Revoke etl-operator",
            kind=ControlKind.NODE,
            target_id="role-etl-operator",
            operational_cost=2,
        ),
        ControlOption(
            id="ctl-block-attacker",
            label="Block attacker IP",
            kind=ControlKind.NODE,
            target_id="attacker-ip-198-51-100-77",
            operational_cost=1,
        ),
        ControlOption(
            id="ctl-deny-etl-export",
            label="Deny ETL export access",
            kind=ControlKind.EDGE,
            target_id="role-etl-operator->resource-customer-exports-prod",
            operational_cost=1.5,
        ),
        ControlOption(
            id="ctl-deny-analytics-export",
            label="Deny analytics export access",
            kind=ControlKind.EDGE,
            target_id="role-analytics-reader->resource-customer-exports-prod",
            operational_cost=1.5,
        ),
    )
    ground_truth = {
        "scenario_id": DEMO_SCENARIO_ID,
        "seed": seed,
        "expected_top_path": [
            "attacker-ip-198-51-100-77",
            "identity-ana-rao",
            "device-eng-lt-042",
            "role-etl-operator",
            "resource-customer-exports-prod",
        ],
        "primary_evidence": ["evt-000001", "evt-000002", "evt-000003", "evt-000004"],
    }
    return ScenarioFixture(
        scenario_id=DEMO_SCENARIO_ID,
        seed=seed,
        inventory=tuple(_inventory()),
        events=tuple(events),
        controls=controls,
        ground_truth=ground_truth,
    )


def events_to_json(events: tuple[NormalizedSecurityEvent, ...] | list[NormalizedSecurityEvent]) -> str:
    return json.dumps([event.model_dump(mode="json") for event in events], separators=(",", ":"))


def events_to_csv(events: tuple[NormalizedSecurityEvent, ...] | list[NormalizedSecurityEvent]) -> str:
    output = io.StringIO()
    fields = [
        "event_id", "timestamp", "source", "event_type", "source_ref", "target_ref",
        "session_id", "success", "transition_feasibility", "attributes",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for event in events:
        row = event.model_dump(mode="json")
        row["attributes"] = json.dumps(row["attributes"], separators=(",", ":"), sort_keys=True)
        writer.writerow(row)
    return output.getvalue()
