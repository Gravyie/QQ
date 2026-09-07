import { useEffect, useState } from 'react'
import { api, fmt, STATUS_LABEL, STATUS_COLOR } from '../api'
import type { ScanDetail, ComplianceReport } from '../api'
import { ShieldCheck } from 'lucide-react'

export function Compliance({
  d,
  onGoInventory,
}: {
  d: ScanDetail
  onGoInventory: (f: Record<string, string>) => void
}) {
  const [data, setData] = useState<ComplianceReport | null>(null)
  const [activeStd, setActiveStd] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    setData(null)
    setErr(null)
    api.compliance(d.scan_id)
      .then(r => {
        setData(r)
        if (r.standards.length > 0) setActiveStd(r.standards[0].standard_short)
      })
      .catch(e => setErr(e instanceof Error ? e.message : 'could not load compliance report'))
  }, [d.scan_id])

  const curStandard = data?.standards.find(s => s.standard_short === activeStd) ?? data?.standards[0]

  return (
    <div className="page">
      <div className="head">
        <div>
          <div className="eyebrow-tag">
            <ShieldCheck size={13} className="text-accent" />
            REGULATORY COMPLIANCE MANDATES
          </div>
          <h1>Compliance & Standards</h1>
          <p>
            Audit discovered cryptography against NIST IR 8547, CNSA 2.0, and SP 800-131A mandates.
            Identifies prohibited algorithms, deprecation horizons, and compliance deadlines.
          </p>
        </div>
      </div>

      {err && <div className="panel notice crit">Could not load compliance data — {err}</div>}
      {!data && !err && <div className="panel empty">Evaluating crypto artefacts against global standards…</div>}

      {data && (
        <>
          <div className="grid g4">
            <div className="panel stat">
              <div className="v" style={{
                color: data.posture.band === 'critical' ? 'var(--crit)' :
                       data.posture.band === 'weak' ? 'var(--high)' : 'var(--safe)'
              }}>
                {data.posture.score.toFixed(0)}<span style={{ fontSize: 16 }}>/100</span>
              </div>
              <div className="k label">Posture Score</div>
              <div className="sub">{data.posture.headline}</div>
            </div>

            <div className="panel stat">
              <div className="v" style={{ color: 'var(--crit)' }}>
                {fmt.n(data.posture.disallowed_artifacts)}
              </div>
              <div className="k label">Disallowed Artefacts</div>
              <div className="sub">Prohibited by current baseline standards</div>
            </div>

            <div className="panel stat">
              <div className="v" style={{ color: 'var(--high)' }}>
                {fmt.n(data.posture.failing_artifacts)}
              </div>
              <div className="k label">Action Required</div>
              <div className="sub">Need migration before enforcement horizon</div>
            </div>

            <div className="panel stat">
              <div className="v" style={{ color: 'var(--safe)' }}>
                {fmt.n(data.artifacts_assessed)}
              </div>
              <div className="k label">Artefacts Evaluated</div>
              <div className="sub">Mappable against standard definitions</div>
            </div>
          </div>

          <div className="tabs-row" style={{ marginTop: 24, display: 'flex', gap: 8, borderBottom: '1px solid var(--line)', paddingBottom: 10 }}>
            {data.standards.map(s => (
              <button
                key={s.standard_short}
                className={`tab-pill ${activeStd === s.standard_short ? 'active' : ''}`}
                onClick={() => setActiveStd(s.standard_short)}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 8,
                  background: activeStd === s.standard_short ? 'var(--elevated)' : 'transparent',
                  border: '1px solid',
                  borderColor: activeStd === s.standard_short ? 'var(--accent)' : 'var(--line)',
                  color: activeStd === s.standard_short ? 'var(--t1)' : 'var(--t3)',
                  padding: '6px 14px',
                  borderRadius: 6,
                }}
              >
                <b>{s.standard_short}</b>
                <span className="mono t4" style={{ fontSize: 11 }}>
                  ({s.failing} non-compliant)
                </span>
              </button>
            ))}
          </div>

          {curStandard && (
            <div className="panel" style={{ marginTop: 14, padding: 18 }}>
              <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <h2>{curStandard.standard}</h2>
                  <p className="t3" style={{ marginTop: 4, maxWidth: 840 }}>{curStandard.summary}</p>
                </div>
                {curStandard.url_or_ref && (
                  <span className="mono t4" style={{ fontSize: 11 }}>
                    {curStandard.document_status} · {curStandard.url_or_ref}
                  </span>
                )}
              </div>

              <div className="grid g4" style={{ marginTop: 18 }}>
                {Object.entries(curStandard.counts_by_status).map(([status, count]) => (
                  <div key={status} className="panel" style={{ padding: 12, background: 'var(--panel-2)' }}>
                    <div className="mono" style={{ fontSize: 11, color: STATUS_COLOR[status] ?? 'var(--t3)', textTransform: 'uppercase' }}>
                      {STATUS_LABEL[status] ?? status}
                    </div>
                    <div className="mono" style={{ fontSize: 20, fontWeight: 500, marginTop: 4 }}>
                      {count}
                    </div>
                  </div>
                ))}
              </div>

              {curStandard.offenders && curStandard.offenders.length > 0 && (
                <div style={{ marginTop: 24 }}>
                  <div className="label" style={{ marginBottom: 10 }}>Non-Compliant Findings for {curStandard.standard_short}</div>
                  <div className="panel" style={{ overflow: 'hidden' }}>
                    <table>
                      <thead>
                        <tr>
                          <th>Artefact</th>
                          <th>Location</th>
                          <th>Status</th>
                          <th>Control</th>
                          <th>Horizon</th>
                          <th>Mandate Note</th>
                        </tr>
                      </thead>
                      <tbody>
                        {curStandard.offenders.slice(0, 20).map((o, idx) => (
                          <tr key={idx}>
                            <td>
                              <span className="t1" style={{ fontWeight: 500 }}>{o.name}</span>
                              <span className={`sev sev-${o.severity}`} style={{ marginLeft: 8 }}>{o.severity}</span>
                            </td>
                            <td className="path">
                              {fmt.file(o.location)}{o.line ? `:${o.line}` : ''}
                            </td>
                            <td>
                              <span
                                className="chip"
                                style={{
                                  color: STATUS_COLOR[o.status] ?? 'var(--t3)',
                                  borderColor: STATUS_COLOR[o.status] ?? 'var(--line)',
                                }}
                              >
                                {STATUS_LABEL[o.status] ?? o.status}
                              </span>
                            </td>
                            <td className="mono t3" style={{ fontSize: 11 }}>{o.control}</td>
                            <td className="mono" style={{ color: o.deadline_year ? 'var(--crit)' : 'var(--t4)' }}>
                              {o.deadline_year ?? 'Immediate'}
                            </td>
                            <td className="t3" style={{ fontSize: 12 }}>{o.note}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {data.worst_first && data.worst_first.length > 0 && (
            <div style={{ marginTop: 24 }}>
              <div className="label" style={{ marginBottom: 10 }}>Priority Remediation Queue (Worst Violations First)</div>
              <div className="panel" style={{ overflow: 'hidden' }}>
                <table>
                  <thead>
                    <tr>
                      <th style={{ width: 60 }}>Risk</th>
                      <th>Artefact</th>
                      <th>Location</th>
                      <th>Compliance Verdict</th>
                      <th>Mandate Deadline</th>
                      <th style={{ textAlign: 'right' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.worst_first.slice(0, 15).map(item => (
                      <tr key={item.id}>
                        <td className="num" style={{ color: 'var(--crit)', fontWeight: 600 }}>
                          {item.risk_score.toFixed(1)}
                        </td>
                        <td>
                          <span className="t1">{item.name}</span>
                          <span className={`sev sev-${item.severity}`} style={{ marginLeft: 8 }}>
                            {item.severity}
                          </span>
                        </td>
                        <td className="path">
                          {fmt.file(item.location)}{item.line ? `:${item.line}` : ''}
                        </td>
                        <td>
                          <span
                            className="chip"
                            style={{
                              color: STATUS_COLOR[item.status] ?? 'var(--t3)',
                              borderColor: STATUS_COLOR[item.status] ?? 'var(--line)',
                            }}
                          >
                            {STATUS_LABEL[item.status] ?? item.status}
                          </span>
                        </td>
                        <td className="mono" style={{ color: item.deadline_year ? 'var(--high)' : 'var(--crit)' }}>
                          {item.deadline_year ? `Year ${item.deadline_year}` : 'Immediate'}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            style={{ padding: '3px 8px', fontSize: 11 }}
                            onClick={() => onGoInventory({ q: item.name })}
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
