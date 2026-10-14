import { ChevronRight, Route, ScanSearch } from 'lucide-react'
import type { AttackPath, GraphData } from '../models'

interface Props {
  paths: AttackPath[]
  graph?: GraphData
  selectedPathId?: string
  loading?: boolean
  onSelect: (path: AttackPath) => void
  onInspectHop: (path: AttackPath, hopIndex: number) => void
}

export function PathPanel({ paths, graph, selectedPathId, loading, onSelect, onInspectHop }: Props) {
  const name = (id: string) => graph?.nodes.find((node) => node.id === id)?.label ?? id
  const selected = paths.find((path) => path.id === selectedPathId)

  return (
    <aside className="panel path-panel">
      <div className="panel-heading">
        <div><span className="eyebrow">Compiler output</span><h2>Viable paths</h2></div>
        <span className="count-badge">{paths.length}</span>
      </div>
      {loading ? <div className="panel-loading"><span /><span /><span /></div> : paths.length === 0 ? (
        <div className="small-empty"><ScanSearch size={24} /><strong>Awaiting compilation</strong><span>Attack paths will be ranked by exploitability and blast radius.</span></div>
      ) : (
        <div className="path-list">
          {paths.map((path, index) => (
            <button key={path.id} className={`path-card ${selectedPathId === path.id ? 'active' : ''}`} onClick={() => onSelect(path)}>
              <span className="path-rank">0{index + 1}</span>
              <span className="path-card-main">
                <strong>{path.name || `Path ${index + 1}`}</strong>
                <small>{name(path.node_ids[0])} <ChevronRight size={10} /> {name(path.node_ids.at(-1) ?? '')}</small>
              </span>
              <span className="risk-score">{Math.round(path.risk_score)}</span>
            </button>
          ))}
        </div>
      )}
      {selected && (
        <div className="hop-inspector">
          <div className="section-label"><Route size={13} /> Hop sequence</div>
          <div className="hop-list">
            {selected.node_ids.slice(0, -1).map((nodeId, index) => {
              const edge = graph?.edges.find((item) => item.id === selected.edge_ids[index])
              return (
                <button key={`${nodeId}-${index}`} onClick={() => onInspectHop(selected, index)}>
                  <i>{index + 1}</i>
                  <span><strong>{name(nodeId)} → {name(selected.node_ids[index + 1])}</strong><small>{edge?.label || selected.hops?.[index]?.technique || 'Observed relationship'}</small></span>
                  <ChevronRight size={13} />
                </button>
              )
            })}
          </div>
        </div>
      )}
    </aside>
  )
}
