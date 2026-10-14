import type {
  AnalysisResult,
  AttackPath,
  Control,
  EntityNode,
  GraphData,
  InterventionResult,
  MetricSnapshot,
  RelationshipEdge,
  ScenarioSummary,
  SecurityEvent,
  SimulationResult,
} from './models'

const API_ROOT = '/api'
type Json = Record<string, unknown>

const obj = (value: unknown): Json => (value && typeof value === 'object' && !Array.isArray(value) ? value as Json : {})
const arr = (value: unknown): unknown[] => Array.isArray(value) ? value : []
const pick = (data: Json, ...keys: string[]) => keys.map((key) => data[key]).find((value) => value !== undefined)
const text = (value: unknown, fallback = '') => value == null ? fallback : String(value)
const num = (value: unknown, fallback = 0) => {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}
const bool = (value: unknown, fallback = false) => typeof value === 'boolean' ? value : fallback
const percent = (value: unknown) => {
  const parsed = num(value)
  return parsed > 0 && parsed <= 1 ? parsed * 100 : parsed
}

const nodeType = (value: unknown) => {
  const raw = text(value, 'host').toLowerCase()
  return ({ attacker: 'external', device: 'host', role: 'cloud', resource: 'database' } as Record<string, string>)[raw] ?? raw
}

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const response = await fetch(`${API_ROOT}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  if (!response.ok) {
    const message = await response.text().catch(() => '')
    throw new Error(message || `API request failed (${response.status})`)
  }
  return response.status === 204 ? {} : response.json()
}

const parseNode = (value: unknown): EntityNode => {
  const data = obj(value)
  const criticality = num(pick(data, 'criticality', 'risk_score', 'risk', 'score'))
  return {
    id: text(pick(data, 'id', 'node_id', 'entity_id')),
    label: text(pick(data, 'label', 'name', 'display_name'), 'Unknown entity'),
    type: nodeType(pick(data, 'type', 'entity_type', 'kind')),
    critical: bool(pick(data, 'critical', 'is_critical'), criticality >= 70),
    risk_score: criticality,
    metadata: obj(pick(data, 'metadata', 'properties', 'attributes')),
  }
}

const parseEdge = (value: unknown, index: number): RelationshipEdge => {
  const data = obj(value)
  return {
    id: text(pick(data, 'id', 'edge_id', 'relationship_id'), `edge-${index}`),
    source: text(pick(data, 'source', 'source_id', 'from')),
    target: text(pick(data, 'target', 'target_id', 'to')),
    label: text(pick(data, 'label', 'name', 'technique', 'relationship', 'type', 'relationship_type')).replaceAll('_', ' '),
    type: text(pick(data, 'type', 'relationship_type', 'kind')),
    risk_score: percent(pick(data, 'risk_score', 'risk', 'score', 'feasibility')),
    evidence: arr(pick(data, 'evidence', 'events', 'evidence_ids')).map((item) =>
      typeof item === 'string' ? { id: item, event_id: item } : obj(item)),
    metadata: obj(pick(data, 'metadata', 'properties', 'attributes')),
  }
}

const parsePath = (value: unknown, index: number): AttackPath => {
  const data = obj(value)
  const nodeIds = arr(pick(data, 'node_ids', 'nodes', 'nodeIds')).map((item) => typeof item === 'object' ? text(pick(obj(item), 'id', 'node_id')) : text(item)).filter(Boolean)
  const edgeIds = arr(pick(data, 'edge_ids', 'edges', 'edgeIds')).map((item) => typeof item === 'object' ? text(pick(obj(item), 'id', 'edge_id')) : text(item)).filter(Boolean)
  return {
    id: text(pick(data, 'id', 'path_id'), `path-${index + 1}`),
    name: text(pick(data, 'name', 'title', 'label'), `Attack path ${index + 1}`),
    node_ids: nodeIds,
    edge_ids: edgeIds,
    risk_score: percent(pick(data, 'risk_score', 'risk', 'score')),
    likelihood: num(pick(data, 'likelihood', 'probability', 'entry_prior')),
    impact: num(pick(data, 'impact', 'impact_score', 'target_criticality')),
    hops: arr(pick(data, 'hops', 'steps')).map((hop) => {
      const item = obj(hop)
      return {
        source: text(pick(item, 'source', 'source_id', 'from')),
        target: text(pick(item, 'target', 'target_id', 'to')),
        edge_id: text(pick(item, 'edge_id', 'id')),
        technique: text(pick(item, 'technique', 'label', 'relationship')),
        evidence: arr(pick(item, 'evidence', 'events', 'evidence_ids')).map((e) =>
          typeof e === 'string' ? { id: e, event_id: e } : obj(e)),
      }
    }),
    evidence: arr(pick(data, 'evidence', 'events')).map((item) => obj(item)),
  }
}

const parseMetrics = (value: unknown): MetricSnapshot | undefined => {
  if (!value || typeof value !== 'object') return undefined
  const data = obj(value)
  return {
    exposure_index: num(pick(data, 'exposure_index', 'exposureIndex', 'exposure')),
    reachable_critical_assets: num(pick(data, 'reachable_critical_assets', 'reachableCriticalAssets', 'critical_assets')),
    highest_risk_score: num(pick(data, 'highest_risk_score', 'highestRiskScore', 'max_risk')),
    path_count: num(pick(data, 'path_count', 'pathCount', 'paths')),
  }
}

export function parseSummary(value: unknown): ScenarioSummary {
  const data = obj(obj(value).scenario ?? value)
  return {
    scenario_id: text(pick(data, 'scenario_id', 'scenarioId', 'id')),
    graph_revision: text(pick(data, 'graph_revision', 'graphRevision', 'revision'), '1'),
    event_count: num(pick(data, 'event_count', 'eventCount', 'events')),
    node_count: num(pick(data, 'node_count', 'nodeCount', 'nodes')),
    edge_count: num(pick(data, 'edge_count', 'edgeCount', 'projected_edge_count', 'evidence_edge_count', 'edges')),
    name: text(pick(data, 'name', 'title')),
  }
}

export function parseGraph(value: unknown): GraphData {
  const data = obj(obj(value).graph ?? value)
  return {
    scenario_id: text(pick(data, 'scenario_id', 'scenarioId', 'id')),
    graph_revision: text(pick(data, 'graph_revision', 'graphRevision', 'revision'), '1'),
    nodes: arr(pick(data, 'nodes', 'entities')).map(parseNode).filter((node) => node.id),
    edges: arr(pick(data, 'edges', 'relationships', 'projected_edges', 'evidence_edges')).map(parseEdge).filter((edge) => edge.source && edge.target),
    stats: obj(data.stats) as Record<string, number>,
  }
}

export function parseAnalysis(value: unknown): AnalysisResult {
  const data = obj(obj(value).analysis ?? value)
  const metrics = obj(data.metrics)
  const paths = arr(pick(data, 'paths', 'attack_paths', 'attackPaths')).map(parsePath)
  const rawScores = paths.map((path) => path.risk_score / 100)
  const endpointCount = new Set(paths.map((path) => path.node_ids.at(-1)).filter(Boolean)).size
  return {
    paths,
    exposure_index: num(pick(data, 'exposure_index', 'exposureIndex') ?? pick(metrics, 'exposure_index', 'exposureIndex'), 100 * (1 - Math.exp(-rawScores.reduce((sum, score) => sum + score, 0)))),
    reachable_critical_assets: num(pick(data, 'reachable_critical_assets', 'reachableCriticalAssets') ?? pick(metrics, 'reachable_critical_assets', 'reachableCriticalAssets'), endpointCount),
    highest_risk_score: num(pick(data, 'highest_risk_score', 'highestRiskScore') ?? pick(metrics, 'highest_risk_score', 'highestRiskScore') ?? paths[0]?.risk_score),
    graph_revision: text(pick(data, 'graph_revision', 'graphRevision', 'revision'), '1'),
    approximate: bool(pick(data, 'approximate', 'is_approximate')),
  }
}

const parseControl = (value: unknown, index: number): Control => {
  const data = obj(value)
  const kind = text(pick(data, 'kind', 'category', 'type'))
  const target = text(pick(data, 'target_id', 'target'))
  return {
    id: text(pick(data, 'id', 'control_id'), `control-${index}`),
    name: text(pick(data, 'name', 'title', 'control', 'label'), `Control ${index + 1}`),
    description: text(pick(data, 'description', 'detail', 'rationale')),
    cost: num(pick(data, 'cost', 'weight', 'operational_cost'), 1),
    target_node_id: text(pick(data, 'target_node_id', 'node_id'), kind === 'node' ? target : ''),
    target_edge_id: text(pick(data, 'target_edge_id', 'edge_id'), kind === 'edge' ? target : ''),
    category: kind,
  }
}

export function parseIntervention(value: unknown): InterventionResult {
  const data = obj(obj(value).recommendation ?? value)
  const controls = arr(pick(data, 'selected_controls', 'controls', 'recommendations')).map(parseControl)
  const residualPaths = arr(pick(data, 'residual_paths', 'residualPaths')).map(parsePath)
  const before = parseMetrics(pick(data, 'before', 'before_metrics')) ?? {
    exposure_index: percent(data.before_max_score),
    reachable_critical_assets: 1,
    highest_risk_score: percent(data.before_max_score),
  }
  const after = parseMetrics(pick(data, 'after', 'after_metrics')) ?? {
    exposure_index: percent(data.after_max_score),
    reachable_critical_assets: new Set(residualPaths.map((path) => path.node_ids.at(-1))).size,
    highest_risk_score: percent(data.after_max_score),
    path_count: residualPaths.length,
  }
  return {
    selected_controls: controls,
    total_cost: num(pick(data, 'total_cost', 'totalCost', 'cost', 'cut_value')),
    complete_cut: bool(pick(data, 'complete_cut', 'completeCut', 'is_complete')),
    before,
    after,
    residual_paths: residualPaths,
    cut_edge_ids: arr(pick(data, 'cut_edge_ids', 'cutEdges')).map((item) => text(item)),
    cut_node_ids: arr(pick(data, 'cut_node_ids', 'cutNodes')).map((item) => text(item)),
  }
}

export function parseSimulation(value: unknown): SimulationResult {
  const data = obj(obj(value).simulation ?? value)
  const graphValue = pick(data, 'graph', 'updated_graph')
  const analysisValue = pick(data, 'analysis', 'result')
  const intervention = parseIntervention(data)
  return {
    graph: graphValue ? parseGraph(graphValue) : undefined,
    analysis: analysisValue ? parseAnalysis(analysisValue) : undefined,
    complete_cut: intervention.complete_cut,
    message: text(pick(data, 'message', 'detail')),
    before: intervention.before,
    after: intervention.after,
    residual_paths: intervention.residual_paths,
    applied_controls: arr(pick(data, 'applied_controls', 'controls', 'selected_controls')).map(parseControl),
  }
}

export const api = {
  loadScenario: () => request('/scenarios/load', { method: 'POST', body: JSON.stringify({ scenario_id: 'apc-demo-01' }) }).then(parseSummary),
  getGraph: (id: string) => request(`/scenarios/${encodeURIComponent(id)}/graph`).then(parseGraph),
  getEvents: async (id: string): Promise<SecurityEvent[]> => {
    const value = await request(`/scenarios/${encodeURIComponent(id)}/events?limit=1000`)
    const data = obj(value)
    return arr(pick(data, 'events', 'items') ?? value).map((raw, index) => {
      const item = obj(raw)
      return {
        ...item,
        id: text(pick(item, 'id', 'event_id'), `event-${index}`),
        timestamp: text(pick(item, 'timestamp', 'time', 'occurred_at')),
        severity: text(pick(item, 'severity', 'level'), 'medium').toLowerCase(),
        title: text(pick(item, 'title', 'name', 'event_type'), 'Security event'),
        actor: text(pick(item, 'actor', 'principal', 'source_ref', 'source')),
        target: text(pick(item, 'target', 'target_ref', 'resource', 'destination')),
        technique: text(pick(item, 'technique', 'mitre_id')),
      } as SecurityEvent
    })
  },
  analyze: (id: string) => request(`/scenarios/${encodeURIComponent(id)}/analyze`, { method: 'POST', body: '{}' }).then(parseAnalysis),
  interventions: (id: string) => request(`/scenarios/${encodeURIComponent(id)}/interventions`, { method: 'POST', body: '{}' }).then(parseIntervention),
  simulate: (id: string, controls: Control[]) => request(`/scenarios/${encodeURIComponent(id)}/simulate`, { method: 'POST', body: JSON.stringify({ control_ids: controls.map((control) => control.id) }) }).then(parseSimulation),
  reset: (id: string) => request(`/scenarios/${encodeURIComponent(id)}/reset`, { method: 'POST', body: '{}' }),
}
