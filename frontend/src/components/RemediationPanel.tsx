import { CheckCircle2, CircleDollarSign, Network, Play, ShieldCheck } from 'lucide-react'
import type { InterventionResult } from '../models'

interface Props {
  intervention?: InterventionResult
  loading?: boolean
  simulating?: boolean
  simulated?: boolean
  simulationComplete?: boolean
  onSimulate: () => void
}

export function RemediationPanel({ intervention, loading, simulating, simulated, simulationComplete, onSimulate }: Props) {
  return (
    <aside className="panel remediation-panel">
      <div className="panel-heading">
        <div><span className="eyebrow">Minimum cut set</span><h2>Defensive intervention</h2></div>
        {intervention && <span className={intervention.complete_cut ? 'status-complete' : 'status-partial'}>{intervention.complete_cut ? 'Complete' : 'Partial'}</span>}
      </div>
      {loading ? <div className="panel-loading"><span /><span /><span /></div> : !intervention ? (
        <div className="small-empty"><Network size={24} /><strong>No controls computed</strong><span>Compile paths, then find the smallest control set that severs critical reachability.</span></div>
      ) : (
        <>
          <div className="intervention-summary">
            <div><CircleDollarSign size={15} /><span>Control cost</span><strong>{intervention.total_cost}</strong></div>
            <div><ShieldCheck size={15} /><span>Paths cut</span><strong>{intervention.complete_cut ? 'ALL' : 'PART'}</strong></div>
          </div>
          <div className="control-list">
            {intervention.selected_controls.map((control, index) => (
              <article key={control.id}>
                <span className="control-index">{String(index + 1).padStart(2, '0')}</span>
                <div><strong>{control.name}</strong><p>{control.description || 'Apply the recommended boundary control.'}</p><small>{control.category || 'Control'} · cost {control.cost}</small></div>
              </article>
            ))}
          </div>
          <button className="action-button simulate" onClick={onSimulate} disabled={simulating || simulated}>
            {simulated ? <><CheckCircle2 size={16} /> {simulationComplete ? 'Cut verified' : 'Residual paths found'}</> : simulating ? <><span className="spinner" /> Simulating…</> : <><Play size={16} /> Simulate fix</>}
          </button>
        </>
      )}
    </aside>
  )
}
