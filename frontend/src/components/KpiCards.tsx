import { Activity, Crosshair, Route, ShieldAlert } from 'lucide-react'
import type { AnalysisResult, MetricSnapshot, ScenarioSummary } from '../models'

interface Props {
  summary?: ScenarioSummary
  analysis?: AnalysisResult
  before?: MetricSnapshot
  after?: MetricSnapshot
}

const items = [
  { key: 'exposure', label: 'Exposure index', icon: Activity, suffix: '' },
  { key: 'paths', label: 'Viable attack paths', icon: Route, suffix: '' },
  { key: 'assets', label: 'Critical assets reachable', icon: Crosshair, suffix: '' },
  { key: 'risk', label: 'Peak path risk', icon: ShieldAlert, suffix: '%' },
] as const

export function KpiCards({ summary, analysis, before, after }: Props) {
  const current = {
    exposure: after?.exposure_index ?? analysis?.exposure_index ?? 0,
    paths: after?.path_count ?? analysis?.paths.length ?? 0,
    assets: after?.reachable_critical_assets ?? analysis?.reachable_critical_assets ?? 0,
    risk: after?.highest_risk_score ?? analysis?.highest_risk_score ?? 0,
  }
  const previous = before && {
    exposure: before.exposure_index,
    paths: before.path_count ?? analysis?.paths.length ?? 0,
    assets: before.reachable_critical_assets,
    risk: before.highest_risk_score,
  }

  return (
    <section className="kpi-grid" aria-label="Exposure metrics">
      {items.map(({ key, label, icon: Icon, suffix }) => {
        const delta = previous ? current[key] - previous[key] : undefined
        return (
          <article className="kpi-card" key={key}>
            <div className="kpi-top"><span>{label}</span><Icon size={15} aria-hidden /></div>
            <div className="kpi-value-row">
              <strong>{analysis || after ? `${Math.round(current[key])}${suffix}` : '—'}</strong>
              {delta !== undefined && delta !== 0 && <span className={delta < 0 ? 'delta-good' : 'delta-bad'}>{delta > 0 ? '+' : ''}{Math.round(delta)}{suffix}</span>}
            </div>
            <small>
              {key === 'paths' && !analysis ? `${summary?.node_count ?? 0} entities awaiting analysis` : key === 'risk' ? 'normalized risk score' : 'compiled graph metric'}
            </small>
          </article>
        )
      })}
    </section>
  )
}
