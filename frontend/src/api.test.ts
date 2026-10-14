import { describe, expect, it } from 'vitest'
import { parseAnalysis, parseGraph, parseIntervention, parseSummary } from './api'

describe('API response normalization', () => {
  it('accepts camelCase scenario and graph fields', () => {
    expect(parseSummary({ scenario: { id: 'demo', graphRevision: 7, eventCount: 3, nodeCount: 2, edgeCount: 1 } })).toMatchObject({
      scenario_id: 'demo',
      graph_revision: '7',
      event_count: 3,
    })
    expect(parseGraph({
      graph: {
        scenarioId: 'demo',
        entities: [{ entity_id: 'a', display_name: 'Admin', entity_type: 'identity' }, { id: 'b', name: 'DB', kind: 'database' }],
        relationships: [{ relationship_id: 'r1', from: 'a', to: 'b', technique: 'valid account' }],
      },
    })).toMatchObject({
      scenario_id: 'demo',
      nodes: [{ id: 'a', label: 'Admin' }, { id: 'b', label: 'DB' }],
      edges: [{ id: 'r1', source: 'a', target: 'b' }],
    })
  })

  it('normalizes nested analysis metrics and intervention controls', () => {
    expect(parseAnalysis({
      analysis: {
        attackPaths: [{ path_id: 'p1', nodes: ['a', 'b'], edges: ['r1'], score: 92 }],
        metrics: { exposureIndex: 80, reachableCriticalAssets: 1, highestRiskScore: 92 },
      },
    })).toMatchObject({ exposure_index: 80, paths: [{ id: 'p1', risk_score: 92 }] })

    expect(parseIntervention({
      recommendation: {
        controls: [{ control_id: 'c1', title: 'Revoke token', edge_id: 'r1', weight: 2 }],
        totalCost: 2,
        completeCut: true,
        cutEdges: ['r1'],
      },
    })).toMatchObject({
      total_cost: 2,
      complete_cut: true,
      selected_controls: [{ id: 'c1', name: 'Revoke token', cost: 2 }],
      cut_edge_ids: ['r1'],
    })
  })

  it('normalizes the FastAPI backend contract', () => {
    expect(parseGraph({
      scenario_id: 'apc-demo-01',
      nodes: [
        { id: 'attacker', label: '198.51.100.77', type: 'attacker', entry_prior: 0.9 },
        { id: 'bucket', label: 'customer-exports-prod', type: 'resource', criticality: 100 },
      ],
      projected_edges: [
        { id: 'edge-1', source: 'attacker', target: 'bucket', type: 'accessed', feasibility: 0.82, evidence_ids: ['evt-1'] },
      ],
    })).toMatchObject({
      nodes: [
        { id: 'attacker', type: 'external' },
        { id: 'bucket', type: 'database', critical: true },
      ],
      edges: [{ id: 'edge-1', label: 'accessed', risk_score: 82 }],
    })

    expect(parseAnalysis({
      scenario_id: 'apc-demo-01',
      paths: [{
        rank: 1,
        node_ids: ['attacker', 'bucket'],
        edge_ids: ['edge-1'],
        score: 0.72,
        entry_prior: 0.9,
        target_criticality: 100,
        steps: [{ source_id: 'attacker', target_id: 'bucket', relationship: 'accessed', evidence_ids: ['evt-1'] }],
      }],
      exposure_index: 51.3,
      reachable_critical_assets: 1,
      highest_risk_score: 72,
    })).toMatchObject({
      exposure_index: 51.3,
      highest_risk_score: 72,
      paths: [{ risk_score: 72, hops: [{ source: 'attacker', target: 'bucket' }] }],
    })

    expect(parseIntervention({
      selected_controls: [{
        id: 'ctl-1',
        label: 'Block route',
        kind: 'edge',
        target_id: 'attacker->bucket',
        operational_cost: 2,
      }],
      total_cost: 2,
      complete_cut: true,
      before: { exposure_index: 51, reachable_critical_assets: 1, highest_risk_score: 72, path_count: 1 },
      after: { exposure_index: 0, reachable_critical_assets: 0, highest_risk_score: 0, path_count: 0 },
      cut_edge_ids: ['edge-1'],
      residual_paths: [],
    })).toMatchObject({
      total_cost: 2,
      selected_controls: [{ name: 'Block route', cost: 2, target_edge_id: 'attacker->bucket' }],
      after: { path_count: 0 },
    })
  })
})
