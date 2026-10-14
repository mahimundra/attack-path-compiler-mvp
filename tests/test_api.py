from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_api_happy_path() -> None:
    health = client.get("/health")
    assert health.status_code == 200

    loaded = client.post(
        "/api/scenarios/load",
        json={"scenario_id": "apc-demo-01", "event_count": 60},
    )
    assert loaded.status_code == 200
    assert loaded.json()["event_count"] == 60

    graph = client.get("/api/scenarios/apc-demo-01/graph")
    assert graph.status_code == 200
    assert graph.json()["evidence_edges"]

    analysis = client.post(
        "/api/scenarios/apc-demo-01/analyze", json={"max_paths": 10}
    )
    assert analysis.status_code == 200
    body = analysis.json()
    assert body["paths"][0]["node_ids"][0] == "attacker-ip-198-51-100-77"
    assert body["highest_risk_score"] > 0
    assert body["reachable_critical_assets"] == 1
    assert body["exposure_index"] >= body["highest_risk_score"]

    interventions = client.post(
        "/api/scenarios/apc-demo-01/interventions", json={}
    )
    assert interventions.status_code == 200
    intervention_body = interventions.json()
    selected = intervention_body["selected_controls"]
    assert selected
    assert intervention_body["before"]["path_count"] >= 3
    assert intervention_body["after"]["path_count"] == 0
    assert intervention_body["total_cost"] > 0

    simulated = client.post(
        "/api/scenarios/apc-demo-01/simulate",
        json={"control_ids": [selected[0]["id"]]},
    )
    assert simulated.status_code == 200
    simulation_body = simulated.json()
    assert simulation_body["after_max_score"] <= simulation_body["before_max_score"]
    assert simulation_body["after"]["exposure_index"] <= simulation_body["before"]["exposure_index"]

    events = client.get("/api/scenarios/apc-demo-01/events?limit=5")
    assert events.status_code == 200
    assert len(events.json()["events"]) == 5

    reset = client.post("/api/scenarios/apc-demo-01/reset")
    assert reset.status_code == 200


def test_malformed_upload_is_rejected() -> None:
    response = client.post(
        "/api/scenarios/upload",
        data={"scenario_id": "bad-upload"},
        files={"file": ("events.json", b"{not-json", "application/json")},
    )
    assert response.status_code == 400
    assert "malformed upload" in response.json()["detail"]
