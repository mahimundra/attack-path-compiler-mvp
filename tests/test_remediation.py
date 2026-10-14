from __future__ import annotations

from backend.app.models.analysis import ControlKind
from backend.app.services.path_analyzer import PathAnalyzer
from backend.app.services.remediation import RemediationEngine


def test_min_cut_disconnects_and_residual_risk_does_not_increase(fixture, compiled) -> None:
    engine = RemediationEngine()
    recommendation = engine.recommend(
        fixture.scenario_id, compiled.projected, fixture.controls
    )
    assert recommendation.complete_cut
    assert recommendation.selected_controls
    assert recommendation.residual_paths == []
    assert recommendation.after_max_score <= recommendation.before_max_score

    residual = engine.apply_controls(
        compiled.projected, recommendation.selected_controls
    )
    assert PathAnalyzer().analyze(residual).paths == []


def test_edge_controls_are_supported(fixture, compiled) -> None:
    edge_controls = [
        control for control in fixture.controls if control.kind == ControlKind.EDGE
    ]
    result = RemediationEngine().recommend(
        fixture.scenario_id, compiled.projected, edge_controls
    )
    assert result.complete_cut
    assert {control.id for control in result.selected_controls} == {
        "ctl-deny-etl-export",
        "ctl-deny-analytics-export",
    }


def test_incomplete_control_set_is_reported_honestly(fixture, compiled) -> None:
    only_etl = [
        control for control in fixture.controls if control.id == "ctl-deny-etl-export"
    ]
    result = RemediationEngine().recommend(
        fixture.scenario_id, compiled.projected, only_etl
    )
    assert not result.complete_cut
    assert result.residual_paths
    assert "No practical complete cut" in result.message
