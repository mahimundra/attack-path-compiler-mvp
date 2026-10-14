export type EntityType =
  | 'identity'
  | 'host'
  | 'service'
  | 'cloud'
  | 'database'
  | 'critical_asset'
  | 'external'
  | string

export interface Evidence {
  id?: string
  event_id?: string
  timestamp?: string
  source?: string
  title?: string
  detail?: string
  raw?: Record<string, unknown>
}

export interface EntityNode {
  id: string
  label: string
  type: EntityType
  critical?: boolean
  risk_score?: number
  metadata?: Record<string, unknown>
}

export interface RelationshipEdge {
  id: string
  source: string
  target: string
  label?: string
  type?: string
  risk_score?: number
  evidence?: Evidence[]
  metadata?: Record<string, unknown>
}

export interface GraphData {
  scenario_id: string
  graph_revision: string | number
  nodes: EntityNode[]
  edges: RelationshipEdge[]
  stats?: Record<string, number>
}

export interface ScenarioSummary {
  scenario_id: string
  graph_revision: string | number
  event_count: number
  node_count: number
  edge_count: number
  name?: string
}

export interface SecurityEvent extends Evidence {
  id: string
  timestamp: string
  severity: 'critical' | 'high' | 'medium' | 'low' | string
  title: string
  actor?: string
  target?: string
  technique?: string
}

export interface AttackHop {
  source: string
  target: string
  edge_id?: string
  technique?: string
  evidence?: Evidence[]
}

export interface AttackPath {
  id: string
  name?: string
  node_ids: string[]
  edge_ids: string[]
  risk_score: number
  likelihood?: number
  impact?: number
  hops?: AttackHop[]
  evidence?: Evidence[]
}

export interface AnalysisResult {
  paths: AttackPath[]
  exposure_index: number
  reachable_critical_assets: number
  highest_risk_score: number
  graph_revision: string | number
  approximate?: boolean
}

export interface Control {
  id: string
  name: string
  description?: string
  cost: number
  target_node_id?: string
  target_edge_id?: string
  category?: string
}

export interface MetricSnapshot {
  exposure_index: number
  reachable_critical_assets: number
  highest_risk_score: number
  path_count?: number
}

export interface InterventionResult {
  selected_controls: Control[]
  total_cost: number
  complete_cut: boolean
  before?: MetricSnapshot
  after?: MetricSnapshot
  residual_paths?: AttackPath[]
  cut_edge_ids?: string[]
  cut_node_ids?: string[]
}

export interface SimulationResult {
  graph?: GraphData
  analysis?: AnalysisResult
  complete_cut?: boolean
  message?: string
  before?: MetricSnapshot
  after?: MetricSnapshot
  residual_paths?: AttackPath[]
  applied_controls?: Control[]
}

export type AppPhase = 'idle' | 'loaded' | 'analyzed' | 'remediated' | 'simulated'
