from __future__ import annotations

import pytest

from backend.app.services.graph_compiler import GraphCompiler
from backend.app.simulation.generator import ScenarioFixture, generate_demo_scenario


@pytest.fixture
def fixture() -> ScenarioFixture:
    return generate_demo_scenario(event_count=120)


@pytest.fixture
def compiled(fixture: ScenarioFixture):
    return GraphCompiler().compile(fixture.inventory, fixture.events)
