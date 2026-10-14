import type {
  AnalysisResult,
  GraphData,
  InterventionResult,
  ScenarioSummary,
  SecurityEvent,
  SimulationResult,
} from './models'

export const fallbackSummary: ScenarioSummary = {
  scenario_id: 'mit-demo-local',
  graph_revision: 'local-r1',
  event_count: 14,
  node_count: 9,
  edge_count: 10,
  name: 'MIT Breach Emulation',
}

export const fallbackGraph: GraphData = {
  scenario_id: fallbackSummary.scenario_id,
  graph_revision: fallbackSummary.graph_revision,
  nodes: [
    { id: 'internet', label: 'External Actor', type: 'external', risk_score: 91 },
    { id: 'vpn', label: 'VPN Gateway', type: 'service', risk_score: 78 },
    { id: 'jchen', label: 'j.chen', type: 'identity', risk_score: 82 },
    { id: 'workstation', label: 'WKSTN-042', type: 'host', risk_score: 74 },
    { id: 'iam', label: 'Cloud IAM', type: 'cloud', risk_score: 68 },
    { id: 'build', label: 'Build Runner', type: 'service', risk_score: 87 },
    { id: 'prod', label: 'prod-cluster', type: 'cloud', risk_score: 92 },
    { id: 'db', label: 'Customer DB', type: 'database', critical: true, risk_score: 98 },
    { id: 'vault', label: 'Secrets Vault', type: 'critical_asset', critical: true, risk_score: 89 },
  ],
  edges: [
    { id: 'e1', source: 'internet', target: 'vpn', label: 'valid account', type: 'initial_access', risk_score: 86 },
    { id: 'e2', source: 'vpn', target: 'jchen', label: 'session hijack', type: 'credential_access', risk_score: 83 },
    { id: 'e3', source: 'jchen', target: 'workstation', label: 'interactive login', type: 'lateral_movement', risk_score: 72 },
    { id: 'e4', source: 'workstation', target: 'iam', label: 'token theft', type: 'credential_access', risk_score: 89 },
    { id: 'e5', source: 'iam', target: 'prod', label: 'assume role', type: 'privilege_escalation', risk_score: 93 },
    { id: 'e6', source: 'prod', target: 'db', label: 'service trust', type: 'collection', risk_score: 96 },
    { id: 'e7', source: 'jchen', target: 'build', label: 'repo access', type: 'lateral_movement', risk_score: 77 },
    { id: 'e8', source: 'build', target: 'prod', label: 'deploy token', type: 'privilege_escalation', risk_score: 91 },
    { id: 'e9', source: 'build', target: 'vault', label: 'secret read', type: 'credential_access', risk_score: 85 },
    { id: 'e10', source: 'vault', target: 'db', label: 'database secret', type: 'collection', risk_score: 88 },
  ],
  stats: { identities: 1, critical_assets: 2 },
}

export const fallbackEvents: SecurityEvent[] = [
  { id: 'evt-01', timestamp: '2026-10-14T08:41:03Z', severity: 'high', title: 'Impossible travel authentication', actor: 'j.chen', target: 'VPN Gateway', technique: 'T1078' },
  { id: 'evt-02', timestamp: '2026-10-14T08:43:17Z', severity: 'critical', title: 'Session token replayed', actor: 'External Actor', target: 'j.chen', technique: 'T1539' },
  { id: 'evt-03', timestamp: '2026-10-14T08:49:52Z', severity: 'high', title: 'Cloud access key exported', actor: 'j.chen', target: 'Cloud IAM', technique: 'T1552' },
  { id: 'evt-04', timestamp: '2026-10-14T08:54:29Z', severity: 'critical', title: 'Privileged role assumed', actor: 'j.chen', target: 'prod-cluster', technique: 'T1078.004' },
  { id: 'evt-05', timestamp: '2026-10-14T09:02:11Z', severity: 'critical', title: 'Unusual customer table scan', actor: 'prod-cluster', target: 'Customer DB', technique: 'T1213' },
]

export const fallbackAnalysis: AnalysisResult = {
  graph_revision: 'local-r1',
  exposure_index: 86,
  reachable_critical_assets: 2,
  highest_risk_score: 96,
  approximate: false,
  paths: [
    {
      id: 'path-1',
      name: 'Stolen identity → customer data',
      node_ids: ['internet', 'vpn', 'jchen', 'workstation', 'iam', 'prod', 'db'],
      edge_ids: ['e1', 'e2', 'e3', 'e4', 'e5', 'e6'],
      risk_score: 96,
      likelihood: 0.86,
      impact: 0.98,
      hops: [
        { source: 'internet', target: 'vpn', edge_id: 'e1', technique: 'Valid Accounts', evidence: [fallbackEvents[0]] },
        { source: 'vpn', target: 'jchen', edge_id: 'e2', technique: 'Session Cookie Theft', evidence: [fallbackEvents[1]] },
        { source: 'workstation', target: 'iam', edge_id: 'e4', technique: 'Unsecured Credentials', evidence: [fallbackEvents[2]] },
        { source: 'iam', target: 'prod', edge_id: 'e5', technique: 'Cloud Accounts', evidence: [fallbackEvents[3]] },
        { source: 'prod', target: 'db', edge_id: 'e6', technique: 'Data from Information Repositories', evidence: [fallbackEvents[4]] },
      ],
    },
    {
      id: 'path-2',
      name: 'CI token → secrets → database',
      node_ids: ['internet', 'vpn', 'jchen', 'build', 'vault', 'db'],
      edge_ids: ['e1', 'e2', 'e7', 'e9', 'e10'],
      risk_score: 88,
      likelihood: 0.74,
      impact: 0.94,
    },
    {
      id: 'path-3',
      name: 'Build runner → production',
      node_ids: ['internet', 'vpn', 'jchen', 'build', 'prod', 'db'],
      edge_ids: ['e1', 'e2', 'e7', 'e8', 'e6'],
      risk_score: 91,
      likelihood: 0.79,
      impact: 0.96,
    },
  ],
}

export const fallbackIntervention: InterventionResult = {
  selected_controls: [
    { id: 'ctrl-1', name: 'Revoke compromised VPN sessions', description: 'Invalidate all active sessions for j.chen and require phishing-resistant reauthentication.', cost: 1, target_edge_id: 'e2', category: 'Identity' },
    { id: 'ctrl-2', name: 'Remove build runner secret access', description: 'Deny the build service principal read access to production vault paths.', cost: 2, target_edge_id: 'e9', category: 'Least privilege' },
  ],
  total_cost: 3,
  complete_cut: true,
  before: { exposure_index: 86, reachable_critical_assets: 2, highest_risk_score: 96, path_count: 3 },
  after: { exposure_index: 12, reachable_critical_assets: 0, highest_risk_score: 24, path_count: 0 },
  cut_edge_ids: ['e2', 'e9'],
  residual_paths: [],
}

export const fallbackSimulation: SimulationResult = {
  complete_cut: true,
  message: 'Selected controls disconnect every modeled entry-to-target path.',
  graph: {
    ...fallbackGraph,
    graph_revision: 'local-r2',
    edges: fallbackGraph.edges.filter((edge) => !fallbackIntervention.cut_edge_ids?.includes(edge.id)),
  },
  before: fallbackIntervention.before,
  after: fallbackIntervention.after,
  residual_paths: [],
  applied_controls: fallbackIntervention.selected_controls,
  analysis: {
    paths: [],
    exposure_index: 12,
    reachable_critical_assets: 0,
    highest_risk_score: 24,
    graph_revision: 'local-r2',
  },
}
