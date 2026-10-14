import { Braces, FileSearch, X } from 'lucide-react'
import type { AttackHop, EntityNode, Evidence, RelationshipEdge } from '../models'

export type EvidenceSelection =
  | { kind: 'node'; item: EntityNode }
  | { kind: 'edge'; item: RelationshipEdge }
  | { kind: 'hop'; item: AttackHop; title: string }

interface Props {
  selection?: EvidenceSelection
  onClose: () => void
}

function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  if (!evidence.length) return <div className="evidence-empty">No direct event artifact attached. Relationship was inferred from the compiled event sequence.</div>
  return <div className="evidence-list">{evidence.map((item, index) => (
    <article key={item.id || item.event_id || index}>
      <div><FileSearch size={14} /><strong>{item.title || item.source || `Evidence ${index + 1}`}</strong></div>
      {item.timestamp && <time>{new Date(item.timestamp).toLocaleString()}</time>}
      {item.detail && <p>{item.detail}</p>}
      {item.raw && <pre>{JSON.stringify(item.raw, null, 2)}</pre>}
    </article>
  ))}</div>
}

export function EvidenceDrawer({ selection, onClose }: Props) {
  const item = selection?.item
  const evidence = !selection ? [] : selection.kind === 'node' ? [] : selection.item.evidence ?? []
  return (
    <div className={`drawer ${selection ? 'open' : ''}`} aria-hidden={!selection}>
      <div className="drawer-header">
        <div><span className="eyebrow">Evidence inspection</span><h2>{selection?.kind === 'hop' ? selection.title : item && 'label' in item ? item.label : item && 'source' in item ? `${item.source} → ${item.target}` : 'Selection'}</h2></div>
        <button onClick={onClose} aria-label="Close evidence drawer" title="Close"><X size={18} /></button>
      </div>
      {selection && (
        <div className="drawer-body">
          <div className="evidence-meta">
            <span><Braces size={13} /> {selection.kind}</span>
            {'type' in selection.item && selection.item.type && <span>{selection.item.type.replaceAll('_', ' ')}</span>}
            {'risk_score' in selection.item && selection.item.risk_score !== undefined && <span>Risk {Math.round(selection.item.risk_score)}</span>}
          </div>
          <h3>Corroborating artifacts</h3>
          <EvidenceList evidence={evidence} />
          <h3>Compiler record</h3>
          <pre className="record-json">{JSON.stringify(item, null, 2)}</pre>
        </div>
      )}
    </div>
  )
}
