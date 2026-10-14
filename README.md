# Attack Path Compiler

A deterministic FastAPI MVP that turns normalized security telemetry into an
evidence graph, ranks plausible attack paths, and recommends operationally
weighted controls.

## Architecture

- `backend/app/models`: strict Pydantic v2 event, graph, analysis, and remediation contracts.
- `backend/app/ingestion`: JSON, JSONL, and CSV adapters.
- `backend/app/services/normalizer.py`: UTC validation, deterministic IDs, exact alias resolution, and inventory inference.
- `backend/app/services/correlator.py`: explicit exact-session correlation rules.
- `backend/app/services/graph_compiler.py`: evidence `MultiDiGraph` and projected `DiGraph`.
- `backend/app/services/path_analyzer.py`: bounded loopless path ranking.
- `backend/app/services/remediation.py`: node-split directed minimum cuts and intervention simulation.
- `backend/app/state`: thread-safe in-memory scenario lifecycle.
- `backend/app/simulation`: seeded demo generator and JSON/CSV export helpers.
- `schemas`: committed interchange schemas.
- `data/scenarios/apc-demo-01`: compact sample and hidden ground truth.

The full built-in scenario is generated with seed `424242`. It contains 2,000
normalized events by default, including benign noise, duplicate evidence, the
primary path
`198.51.100.77 -> Ana Rao -> ENG-LT-042 -> etl-operator -> customer-exports-prod`,
and two alternatives.

## Setup and run

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs`. If `frontend/dist` exists, the application
also serves it at `/`. Localhost origins on common frontend development ports
are allowed by CORS.

Dashboard development requires Node.js 20+:

```powershell
cd frontend
npm install
npm run dev
```

Vite proxies `/api` to FastAPI on port `8000`. For the single-process demo,
run `npm run build`, return to the repository root, and start Uvicorn; FastAPI
will serve `frontend/dist` at `http://127.0.0.1:8000`.

Run tests:

```powershell
python -m pytest
cd frontend
npm test
npm run build
```

## API

- `GET /health` and `GET /api/health`: liveness.
- `POST /api/scenarios/load`: load `apc-demo-01`; accepts optional `event_count`.
- `POST /api/scenarios/upload`: multipart JSON, JSONL, or CSV upload, up to 5 MiB and 10,000 events.
- `GET /api/scenarios/{id}/graph`: canonical nodes, every evidence edge, and projected edges.
- `POST /api/scenarios/{id}/analyze`: top paths with evidence-backed explanations.
- `POST /api/scenarios/{id}/interventions`: minimum-cost complete cut, or an honest no-cut response.
- `POST /api/scenarios/{id}/simulate`: clone the graph, apply selected control IDs, and rerun analysis.
- `POST /api/scenarios/{id}/reset`: rebuild the original scenario graph.
- `GET /api/scenarios/{id}/events`: paginated normalized events.

Load and analyze the demo:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/scenarios/load `
  -ContentType application/json -Body '{"scenario_id":"apc-demo-01"}'

Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/scenarios/apc-demo-01/analyze `
  -ContentType application/json -Body '{"max_paths":10,"max_hops":8,"max_candidates":200}'
```

For uploads, every event follows `schemas/normalized-security-event.schema.json`.
Omitted event IDs are deterministically generated; timestamps without a UTC
offset are rejected. Uploaded inventories are conservatively inferred from
event types.

## Algorithms

Correlation uses exact alias lookup and exact session IDs. Authentication must
match the identity observed in the same session; role assumption must match its
device; data access must match the active role. Each accepted transition retains
its evidence IDs in a `MultiDiGraph`. Projection combines parallel edges,
retains the union of evidence, and uses maximum transition feasibility.

Path analysis performs bounded uniform-cost enumeration of loopless path
states—the Dijkstra principle applied to simple paths—with
`-log(probability)` weights. The hop limit is enforced during expansion, a
state budget prevents path-explosion CPU exhaustion, and the API marks a
budget-truncated result as approximate. It allows at most eight attack hops
and returns at most ten paths with deterministic tie-breaking. The path score is:

```text
entry prior * product(edge feasibility) * target criticality / 100
```

The API reports each path score on a 0–1 scale and its display index on a
0–100 scale. Dashboard exposure is the bounded aggregate
`100 * (1 - exp(-sum(path scores)))`; it is a prioritization index, not a
breach probability. Exposure and path count describe the returned top-K paths;
reachable critical assets is calculated across the full compiled graph.

Remediation splits every node into `in` and `out` vertices. Node and edge
control costs become directed capacities. Uncontrolled capacities use
`INF = 1 + sum(all finite control capacities)`. A directed minimum cut selects
controls only when a finite complete cut exists. Simulation always works on a
clone and reports residual paths and before/after maximum score.

## Demo flow

1. Load `apc-demo-01`.
2. Inspect the evidence and projected graph.
3. Analyze and expand the top path's evidence-backed steps.
4. Request interventions.
5. Simulate the returned controls and compare residual risk.
6. Reset to the deterministic baseline.

## Risk interpretation

Scores and transition feasibilities are **modeled, not calibrated risk**. They
are suitable for transparent prioritization and demos, not empirical breach
probabilities or autonomous production response decisions.
