import { useCallback, useMemo, useState } from 'react'
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Activity, CircleDot, Cpu, DatabaseZap, GitCompareArrows, RotateCcw, Shield, Sparkles, Waypoints } from 'lucide-react'
import { api } from './api'
import { fallbackAnalysis, fallbackEvents, fallbackGraph, fallbackIntervention, fallbackSimulation, fallbackSummary } from './fallback'
import type {
  AppPhase,
  AttackPath,
  EntityNode,
  GraphData,
  InterventionResult,
  ScenarioSummary,
  SecurityEvent,
  SimulationResult,
} from './models'
import { AlertTimeline } from './components/AlertTimeline'
import { AttackGraph } from './components/AttackGraph'
import { EvidenceDrawer, type EvidenceSelection } from './components/EvidenceDrawer'
import { KpiCards } from './components/KpiCards'
import { PathPanel } from './components/PathPanel'
import { RemediationPanel } from './components/RemediationPanel'

type BusyAction = 'load' | 'analyze' | 'intervene' | 'simulate' | 'reset'

const isOfflineError = (error: unknown) =>
  error instanceof TypeError || /fetch|network|failed to fetch|load failed/i.test(error instanceof Error ? error.message : String(error))

export default function App() {
  const [phase, setPhase] = useState<AppPhase>('idle')
  const [summary, setSummary] = useState<ScenarioSummary>()
  const [graph, setGraph] = useState<GraphData>()
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [analysis, setAnalysis] = useState<typeof fallbackAnalysis>()
  const [intervention, setIntervention] = useState<InterventionResult>()
  const [simulation, setSimulation] = useState<SimulationResult>()
  const [selectedPath, setSelectedPath] = useState<AttackPath>()
  const [selection, setSelection] = useState<EvidenceSelection>()
  const [busy, setBusy] = useState<BusyAction>()
  const [error, setError] = useState<string>()
  const [offline, setOffline] = useState(false)

  const run = async (action: BusyAction, task: () => Promise<void>) => {
    setBusy(action)
    setError(undefined)
    try {
      await task()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'An unexpected compiler error occurred.')
    } finally {
      setBusy(undefined)
    }
  }

  const loadScenario = () => run('load', async () => {
    try {
      const loaded = await api.loadScenario()
      if (!loaded.scenario_id) throw new Error('Scenario response did not include an identifier.')
      const [loadedGraph, loadedEvents] = await Promise.all([api.getGraph(loaded.scenario_id), api.getEvents(loaded.scenario_id)])
      setSummary(loaded)
      setGraph(loadedGraph)
      setEvents(loadedEvents)
      setOffline(false)
    } catch (caught) {
      if (!isOfflineError(caught)) throw caught
      setSummary(fallbackSummary)
      setGraph(fallbackGraph)
      setEvents(fallbackEvents)
      setOffline(true)
    }
    setPhase('loaded')
  })

  const compilePaths = () => run('analyze', async () => {
    if (!summary) return
    const result = offline ? fallbackAnalysis : await api.analyze(summary.scenario_id)
    setAnalysis(result)
    setSelectedPath(result.paths[0])
    setPhase('analyzed')
  })

  const findIntervention = () => run('intervene', async () => {
    if (!summary) return
    const result = offline ? fallbackIntervention : await api.interventions(summary.scenario_id)
    setIntervention(result)
    setPhase('remediated')
  })

  const simulate = () => run('simulate', async () => {
    if (!summary || !intervention) return
    const result = offline ? fallbackSimulation : await api.simulate(summary.scenario_id, intervention.selected_controls)
    if (!result.graph && graph) {
      const nodeTargets = intervention.selected_controls.flatMap((control) => control.target_node_id ? [control.target_node_id] : [])
      const edgeControlTargets = intervention.selected_controls.flatMap((control) => control.target_edge_id ? [control.target_edge_id] : [])
      const cutNodes = new Set(intervention.cut_node_ids ?? nodeTargets)
      const cutEdges = new Set(intervention.cut_edge_ids ?? [])
      const edgeTargets = new Set(edgeControlTargets)
      result.graph = {
        ...graph,
        graph_revision: Number(graph.graph_revision) + 1,
        nodes: graph.nodes.filter((node) => !cutNodes.has(node.id)),
        edges: graph.edges.filter((edge) =>
          !cutNodes.has(edge.source)
          && !cutNodes.has(edge.target)
          && !cutEdges.has(edge.id)
          && !edgeTargets.has(edge.id)
          && !edgeTargets.has(`${edge.source}->${edge.target}`)),
      }
    }
    if (!result.analysis && result.after) {
      result.analysis = {
        paths: result.residual_paths ?? [],
        exposure_index: result.after.exposure_index,
        reachable_critical_assets: result.after.reachable_critical_assets,
        highest_risk_score: result.after.highest_risk_score,
        graph_revision: result.graph?.graph_revision ?? summary.graph_revision,
      }
    }
    setSimulation(result)
    if (result.graph) setGraph(result.graph)
    if (result.analysis) {
      setAnalysis(result.analysis)
      setSelectedPath(result.analysis.paths[0])
    }
    setPhase('simulated')
  })

  const reset = () => run('reset', async () => {
    if (summary && !offline) await api.reset(summary.scenario_id)
    setSummary(undefined)
    setGraph(undefined)
    setEvents([])
    setAnalysis(undefined)
    setIntervention(undefined)
    setSimulation(undefined)
    setSelectedPath(undefined)
    setSelection(undefined)
    setOffline(false)
    setPhase('idle')
  })

  const selectNode = useCallback((node: EntityNode) => setSelection({ kind: 'node', item: node }), [])
  const selectEdge = useCallback((edge: GraphData['edges'][number]) => setSelection({ kind: 'edge', item: edge }), [])
  const inspectHop = useCallback((path: AttackPath, index: number) => {
    const hop = path.hops?.[index] ?? {
      source: path.node_ids[index],
      target: path.node_ids[index + 1],
      edge_id: path.edge_ids[index],
      evidence: graph?.edges.find((edge) => edge.id === path.edge_ids[index])?.evidence,
    }
    const source = graph?.nodes.find((node) => node.id === hop.source)?.label ?? hop.source
    const target = graph?.nodes.find((node) => node.id === hop.target)?.label ?? hop.target
    setSelection({ kind: 'hop', item: hop, title: `${source} → ${target}` })
  }, [graph])

  const metricData = useMemo(() => {
    if (!simulation?.before || !simulation.after) return []
    return [
      { metric: 'Exposure', before: simulation.before.exposure_index, after: simulation.after.exposure_index },
      { metric: 'Risk', before: simulation.before.highest_risk_score, after: simulation.after.highest_risk_score },
    ]
  }, [simulation])

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand"><div className="brand-mark"><Waypoints size={19} /></div><div><strong>ATTACK PATH</strong><span>COMPILER</span></div></div>
        <div className="scenario-meta">
          <span className={`live-dot ${offline ? 'offline' : ''}`} />
          <span>{offline ? 'LOCAL FALLBACK' : summary ? 'ENGINE CONNECTED' : 'ENGINE STANDBY'}</span>
          {summary && <><i /><span className="mono">{summary.scenario_id}</span><i /><span>REV {summary.graph_revision}</span></>}
        </div>
        <div className="top-actions">
          <button className="icon-button" title="Reset scenario" aria-label="Reset scenario" disabled={!summary || !!busy} onClick={reset}><RotateCcw size={16} /></button>
          <div className="analyst"><span>AP</span><div><strong>Analyst</strong><small>Investigation mode</small></div></div>
        </div>
      </header>

      <main>
        {offline && <div className="fallback-banner"><CircleDot size={13} /> Demo fallback active — backend is unreachable; deterministic local data is being used.</div>}
        {analysis?.approximate && <div className="fallback-banner"><CircleDot size={13} /> Analysis reached its safety limit. Displayed paths are valid, but additional routes may exist.</div>}
        {error && <div className="error-banner" role="alert"><strong>Compiler request failed</strong><span>{error}</span><button onClick={() => setError(undefined)}>Dismiss</button></div>}

        <section className="command-strip">
          <div className="command-title">
            <span className="eyebrow">Investigation workspace / MIT emulation</span>
            <h1>{phase === 'idle' ? 'Map compromise. Cut the path.' : summary?.name || 'MIT Demo Scenario'}</h1>
          </div>
          <div className="workflow">
            <span className={phase !== 'idle' ? 'done' : 'active'}>01 Ingest</span><i />
            <span className={['analyzed', 'remediated', 'simulated'].includes(phase) ? 'done' : phase === 'loaded' ? 'active' : ''}>02 Compile</span><i />
            <span className={['remediated', 'simulated'].includes(phase) ? 'done' : phase === 'analyzed' ? 'active' : ''}>03 Intervene</span><i />
            <span className={phase === 'simulated' ? 'done' : phase === 'remediated' ? 'active' : ''}>04 Verify</span>
          </div>
          <div className="primary-actions">
            {phase === 'idle' && <button className="action-button primary" onClick={loadScenario} disabled={!!busy}>{busy === 'load' ? <><span className="spinner" /> Loading telemetry…</> : <><DatabaseZap size={16} /> Load MIT Demo Scenario</>}</button>}
            {phase === 'loaded' && <button className="action-button primary" onClick={compilePaths} disabled={!!busy}>{busy === 'analyze' ? <><span className="spinner" /> Compiling graph…</> : <><Cpu size={16} /> Compile Attack Paths</>}</button>}
            {phase === 'analyzed' && <button className="action-button primary" onClick={findIntervention} disabled={!!busy}>{busy === 'intervene' ? <><span className="spinner" /> Solving cut set…</> : <><Shield size={16} /> Find Smallest Defensive Intervention</>}</button>}
            {phase === 'simulated' && <button className={`action-button ${simulation?.complete_cut ? 'verified' : ''}`} disabled><Sparkles size={16} /> {simulation?.complete_cut ? 'Critical reachability severed' : 'Residual paths require action'}</button>}
          </div>
        </section>

        <KpiCards summary={summary} analysis={analysis} before={simulation?.before} after={simulation?.after} />

        <section className="workspace">
          <PathPanel paths={analysis?.paths ?? []} graph={graph} selectedPathId={selectedPath?.id} loading={busy === 'analyze'} onSelect={setSelectedPath} onInspectHop={inspectHop} />
          <section className="graph-panel">
            <div className="graph-header">
              <div><span className="eyebrow">Compiled topology</span><h2>Attack reachability graph</h2></div>
              <div className="graph-stats"><span><b>{graph?.nodes.length ?? 0}</b> entities</span><span><b>{graph?.edges.length ?? 0}</b> relationships</span><span><b>{analysis?.paths.length ?? 0}</b> paths</span></div>
            </div>
            <AttackGraph graph={graph} paths={analysis?.paths} selectedPath={selectedPath} selectedElementId={selection?.item && 'id' in selection.item ? selection.item.id : undefined} cutEdgeIds={intervention?.cut_edge_ids} cutNodeIds={intervention?.cut_node_ids} onSelectNode={selectNode} onSelectEdge={selectEdge} />
          </section>
          <RemediationPanel intervention={intervention} loading={busy === 'intervene'} simulating={busy === 'simulate'} simulated={phase === 'simulated'} simulationComplete={simulation?.complete_cut} onSimulate={simulate} />
        </section>

        {phase === 'simulated' && metricData.length > 0 && (
          <section className="outcome-panel">
            <div className="outcome-copy"><span className="outcome-icon"><GitCompareArrows size={20} /></span><div><span className="eyebrow">Simulation outcome</span><h2>{simulation?.complete_cut ? 'Control set breaks all known routes to critical assets' : 'Residual modeled routes remain after intervention'}</h2><p>{simulation?.applied_controls?.length ?? intervention?.selected_controls.length} controls applied · graph revision {simulation?.graph?.graph_revision ?? summary?.graph_revision}</p></div></div>
            <div className="delta-chart" aria-label="Before and after exposure chart">
              <ResponsiveContainer width="100%" height={108}>
                <AreaChart data={metricData} margin={{ top: 5, right: 8, bottom: 0, left: -28 }}>
                  <defs><linearGradient id="before" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#ff6b4a" stopOpacity=".4" /><stop offset="1" stopColor="#ff6b4a" stopOpacity="0" /></linearGradient><linearGradient id="after" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#b7f34a" stopOpacity=".4" /><stop offset="1" stopColor="#b7f34a" stopOpacity="0" /></linearGradient></defs>
                  <XAxis dataKey="metric" tick={{ fill: '#718095', fontSize: 10 }} axisLine={false} tickLine={false} /><YAxis domain={[0, 100]} tick={{ fill: '#526174', fontSize: 9 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#0b1017', border: '1px solid #243142', fontSize: 11 }} />
                  <Area type="monotone" dataKey="before" stroke="#ff6b4a" fill="url(#before)" strokeWidth={2} /><Area type="monotone" dataKey="after" stroke="#b7f34a" fill="url(#after)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </section>
        )}

        <AlertTimeline events={events} total={summary?.event_count} />
      </main>
      <EvidenceDrawer selection={selection} onClose={() => setSelection(undefined)} />
      <footer><span><Activity size={12} /> COMPILER STATUS: {busy ? busy.toUpperCase() : phase === 'idle' ? 'READY' : 'NOMINAL'}</span><span>Graph analysis · deterministic minimum cut · evidence linked</span></footer>
    </div>
  )
}
