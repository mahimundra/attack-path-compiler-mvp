import { AlertTriangle, Clock3 } from 'lucide-react'
import type { SecurityEvent } from '../models'

export function AlertTimeline({ events, total }: { events: SecurityEvent[]; total?: number }) {
  return (
    <section className="timeline-panel">
      <div className="timeline-title"><span><AlertTriangle size={14} /> Alert sequence</span><small>{total ?? events.length} normalized events</small></div>
      {events.length === 0 ? <div className="timeline-empty"><Clock3 size={14} /> Event stream will appear after scenario load.</div> : (
        <div className="timeline-track">
          {events.slice(0, 8).map((event) => (
            <article key={event.id}>
              <i className={`severity-${event.severity}`} />
              <time>{event.timestamp ? new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '--:--'}</time>
              <strong>{event.title}</strong>
              <span>{event.actor && event.target ? `${event.actor} → ${event.target}` : event.target || event.actor || 'Observed entity'}</span>
              {event.technique && <code>{event.technique}</code>}
            </article>
          ))}
        </div>
      )}
    </section>
  )
}
