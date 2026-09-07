/** Artifact detail drawer: the evidence view.
 *
 * The point of this panel is that every number Atlas reports can be traced to a
 * file, a line, and a snippet. A finding without evidence is an opinion.
 */
import { IMPACT_LABEL, fmt } from '../api'
import type { Artifact } from '../api'

export function Detail({ a, onClose }: { a: Artifact; onClose: () => void }) {
  const p = a.properties || {}
  const rec = a.recommendation
  const show = Object.entries(p).filter(([, v]) => v !== null && v !== '' && v !== undefined)

  return (
    <div className="drawer">
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 14 }}>
        <div className="row" style={{ gap: 8 }}>
          <div className={`dot bg-${a.severity}`} />
          <span className={`sev sev-${a.severity}`}>{a.severity}</span>
          <span className="mono t4">risk {a.risk_score.toFixed(1)}</span>
        </div>
        <button onClick={onClose}>Close</button>
      </div>

      <h2 style={{ marginBottom: 3 }}>{a.name}</h2>
      <div className="row wrap" style={{ gap: 5, marginBottom: 16 }}>
        <span className="chip">{a.artifact_type}</span>
        <span className="chip">{IMPACT_LABEL[a.quantum_impact] ?? a.quantum_impact}</span>
        <span className="chip">{a.business_criticality} criticality</span>
        {a.mosca_violated && <span className="chip warn">Mosca violated</span>}
      </div>

      <div className="label" style={{ marginBottom: 6 }}>Evidence</div>
      <div className="path" style={{ marginBottom: 6 }}>
        {fmt.dir(a.evidence.file_path)}/<b>{fmt.file(a.evidence.file_path)}</b>
        {a.evidence.line ? <span className="t4">:{a.evidence.line}</span> : null}
      </div>
      {a.evidence.snippet && <div className="code" style={{ marginBottom: 8 }}>{a.evidence.snippet}</div>}
      {a.evidence.container_layer && (
        <div className="mono t4" style={{ marginBottom: 8 }}>layer {a.evidence.container_layer}</div>
      )}

      <div className="label" style={{ margin: '18px 0 6px' }}>Risk model</div>
      <dl className="kv">
        <dt>discovery</dt><dd>{a.source}</dd>
        <dt>impact</dt><dd>{IMPACT_LABEL[a.quantum_impact] ?? a.quantum_impact}</dd>
        {a.lifetime_years != null && <><dt>data lifetime</dt><dd>{a.lifetime_years} years</dd></>}
        {a.migration_months != null && <><dt>migration</dt><dd>{a.migration_months} months</dd></>}
        {a.mosca_margin_years != null && (
          <>
            <dt>Mosca margin</dt>
            <dd style={{ color: a.mosca_margin_years < 0 ? 'var(--crit)' : 'var(--safe)' }}>
              {a.mosca_margin_years > 0 ? '+' : ''}{a.mosca_margin_years.toFixed(1)} years
              {a.mosca_margin_years < 0 ? ' — past the deadline' : ' of slack'}
            </dd>
          </>
        )}
        {a.hndl_exposure != null && (
          <><dt>HNDL exposure</dt><dd>{a.hndl_exposure.toFixed(1)} / 10</dd></>
        )}
        {a.quantum_year != null && <><dt>at risk from</dt><dd>{a.quantum_year}</dd></>}
      </dl>

      {rec && (
        <>
          <div className="label" style={{ margin: '18px 0 6px' }}>Remediation</div>
          <div className="panel" style={{ padding: 12, background: 'var(--panel-2)' }}>
            <div className="row" style={{ gap: 7, marginBottom: 7 }}>
              <span className="mono t4">{a.name}</span>
              <span className="t4">→</span>
              <span className="chip on">{rec.target}</span>
              {rec.hybrid && <span className="chip">hybrid: {rec.hybrid}</span>}
            </div>
            <div style={{ color: 'var(--t2)', fontSize: 12.5 }}>{rec.action}</div>
            {rec.note && <div className="t3" style={{ fontSize: 12, marginTop: 6 }}>{rec.note}</div>}
            <div className="row wrap" style={{ gap: 5, marginTop: 9 }}>
              {rec.standard && <span className="chip">{rec.standard}</span>}
              {rec.effort_days != null && <span className="chip">{rec.effort_days}d effort</span>}
              {rec.wire_delta_bytes != null && (
                <span className="chip">
                  {rec.wire_delta_bytes > 0 ? '+' : ''}{fmt.n(rec.wire_delta_bytes)} B on the wire
                </span>
              )}
            </div>
            {rec.target_perf && Object.keys(rec.target_perf).length > 0 && (
              <div className="mono t4" style={{ marginTop: 8, fontSize: 10.5 }}>
                {Object.entries(rec.target_perf).map(([k, v]) => `${k}=${v}`).join('  ')}
              </div>
            )}
          </div>
        </>
      )}

      {show.length > 0 && (
        <>
          <div className="label" style={{ margin: '18px 0 6px' }}>Observed properties</div>
          <dl className="kv">
            {show.map(([k, v]) => (
              <>
                <dt key={k}>{k}</dt>
                <dd key={k + 'v'}>{typeof v === 'boolean' ? (v ? 'yes' : 'no') : String(v)}</dd>
              </>
            ))}
          </dl>
        </>
      )}

      <div className="mono t4" style={{ marginTop: 20, fontSize: 10 }}>{a.id}</div>
    </div>
  )
}
