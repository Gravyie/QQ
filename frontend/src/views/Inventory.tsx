/** Inventory: the filterable artefact table with evidence drawer. */
import { useEffect, useState } from 'react'
import { api, IMPACT_LABEL, SEVS, fmt } from '../api'
import type { Artifact } from '../api'
import { Detail } from '../components/Detail'

const IMPACTS = ['broken_classically', 'shor_broken', 'grover', 'unknown',
                 'classical_ok', 'pq_safe']
const CRITS = ['critical', 'high', 'medium', 'low']

const split = (v?: string) => v?.split(',').filter(Boolean) ?? []

export function Inventory({ scanId, initial, types }: {
  scanId: string
  initial: Record<string, string>
  types: string[]
}) {
  const [sev, setSev] = useState<string[]>(split(initial.severity))
  const [type, setType] = useState<string[]>(split(initial.artifact_type))
  // Impact and criticality are the two axes of the Overview heatmap. They must
  // be real filters here, otherwise clicking a cell silently drops half the
  // query and the table shows more rows than the cell claimed.
  const [impact, setImpact] = useState<string[]>(split(initial.impact))
  const [crit, setCrit] = useState<string[]>(split(initial.criticality))
  const [mosca, setMosca] = useState(initial.mosca_only === 'true')
  const [q, setQ] = useState(initial.q ?? '')
  const [rows, setRows] = useState<Artifact[]>([])
  const [total, setTotal] = useState(0)
  const [sel, setSel] = useState<Artifact | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    setSev(split(initial.severity))
    setType(split(initial.artifact_type))
    setImpact(split(initial.impact))
    setCrit(split(initial.criticality))
    setMosca(initial.mosca_only === 'true')
    setQ(initial.q ?? '')
  }, [initial])

  useEffect(() => {
    const t = setTimeout(() => {
      const p: Record<string, string> = { limit: '400' }
      if (sev.length) p.severity = sev.join(',')
      if (type.length) p.artifact_type = type.join(',')
      if (impact.length) p.impact = impact.join(',')
      if (crit.length) p.criticality = crit.join(',')
      if (mosca) p.mosca_only = 'true'
      if (q.trim()) p.q = q.trim()
      setBusy(true)
      api.artifacts(scanId, p)
        .then(r => { setRows(r.artifacts); setTotal(r.total) })
        .finally(() => setBusy(false))
    }, 180)
    return () => clearTimeout(t)
  }, [scanId, sev, type, impact, crit, mosca, q])

  const flip = (arr: string[], set: (v: string[]) => void, v: string) =>
    set(arr.includes(v) ? arr.filter(x => x !== v) : [...arr, v])

  const active = sev.length + type.length + impact.length + crit.length
    + (mosca ? 1 : 0) + (q ? 1 : 0)
  const reset = () => {
    setSev([]); setType([]); setImpact([]); setCrit([]); setMosca(false); setQ('')
  }

  return (
    <div className="page">
      <div className="head">
        <div>
          <h1>Inventory</h1>
          <p>
            Every artefact with the evidence it was derived from. Click a row to see the file,
            line, snippet, risk derivation and the specific replacement.
          </p>
        </div>
      </div>

      <div className="panel" style={{ padding: 13, marginBottom: 12 }}>
        <div className="row wrap" style={{ gap: 6, marginBottom: 10 }}>
          <span className="label" style={{ width: 74 }}>Severity</span>
          {SEVS.map(s => (
            <span key={s} className={`chip click ${sev.includes(s) ? 'on' : ''}`}
                  onClick={() => flip(sev, setSev, s)}>
              <i className={`dot bg-${s}`} />{s}
            </span>
          ))}
        </div>
        <div className="row wrap" style={{ gap: 6, marginBottom: 10 }}>
          <span className="label" style={{ width: 74 }}>Impact</span>
          {IMPACTS.map(i => (
            <span key={i} className={`chip click ${impact.includes(i) ? 'on' : ''}`}
                  onClick={() => flip(impact, setImpact, i)}>
              {IMPACT_LABEL[i] ?? i}
            </span>
          ))}
        </div>
        <div className="row wrap" style={{ gap: 6, marginBottom: 10 }}>
          <span className="label" style={{ width: 74 }}>Criticality</span>
          {CRITS.map(c => (
            <span key={c} className={`chip click ${crit.includes(c) ? 'on' : ''}`}
                  onClick={() => flip(crit, setCrit, c)}>{c}</span>
          ))}
        </div>
        <div className="row wrap" style={{ gap: 6, marginBottom: 10 }}>
          <span className="label" style={{ width: 74 }}>Class</span>
          {types.map(t => (
            <span key={t} className={`chip click ${type.includes(t) ? 'on' : ''}`}
                  onClick={() => flip(type, setType, t)}>{t}</span>
          ))}
        </div>
        <div className="row wrap" style={{ gap: 8 }}>
          <input className="grow" style={{ minWidth: 220 }} value={q}
                 onChange={e => setQ(e.target.value)}
                 placeholder="Search algorithm, path or snippet…" />
          <span className={`chip click ${mosca ? 'on' : ''}`} onClick={() => setMosca(m => !m)}>
            Mosca violations only
          </span>
          {active > 0 && (
            <button onClick={reset}>Reset {active} filter{active === 1 ? '' : 's'}</button>
          )}
          <div className="row grow" style={{ justifyContent: 'flex-end', gap: 8 }}>
            {busy && <div className="spin" />}
            <span className="mono t3">
              {fmt.n(total)} match{total === 1 ? '' : 'es'}
              {rows.length < total ? ` · showing ${fmt.n(rows.length)}` : ''}
            </span>
          </div>
        </div>
      </div>

      <div className="panel" style={{ overflow: 'hidden' }}>
        {rows.length === 0
          ? <div className="empty">{busy ? 'Loading…' : 'No artefacts match these filters.'}</div>
          : <div style={{ maxHeight: '64vh', overflowY: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 62, textAlign: 'right' }}>Risk</th>
                    <th style={{ width: 74 }}>Severity</th>
                    <th>Artefact</th>
                    <th>Impact</th>
                    <th>Evidence</th>
                    <th style={{ width: 132 }}>Replace with</th>
                    <th style={{ width: 62, textAlign: 'right' }}>Mosca</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map(a => (
                    <tr key={a.id} className={sel?.id === a.id ? 'sel' : ''}
                        style={{ cursor: 'pointer' }} onClick={() => setSel(a)}>
                      <td className="num" style={{
                        color: a.risk_score >= 8 ? 'var(--crit)'
                          : a.risk_score >= 5 ? 'var(--high)' : 'var(--t3)',
                      }}>{a.risk_score.toFixed(1)}</td>
                      <td><span className={`sev sev-${a.severity}`}>{a.severity}</span></td>
                      <td>
                        <div style={{ color: 'var(--t1)' }}>{a.name}</div>
                        <div className="mono t4" style={{ fontSize: 10 }}>{a.artifact_type}</div>
                      </td>
                      <td className="mono t3" style={{ fontSize: 11 }}>
                        {IMPACT_LABEL[a.quantum_impact] ?? a.quantum_impact}
                      </td>
                      <td className="path" style={{ maxWidth: 330 }}>
                        <b>{fmt.file(a.evidence.file_path)}</b>
                        {a.evidence.line ? `:${a.evidence.line}` : ''}
                        {a.evidence.snippet && (
                          <div className="t4" style={{ fontSize: 10.5, marginTop: 2 }}>
                            {a.evidence.snippet.slice(0, 76)}
                          </div>
                        )}
                      </td>
                      <td className="mono" style={{ fontSize: 11, color: 'var(--t2)' }}>
                        {a.recommendation?.target ?? '—'}
                      </td>
                      <td className="num">
                        {a.mosca_violated == null ? '—'
                          : a.mosca_violated
                            ? <span style={{ color: 'var(--crit)' }}>
                                {a.mosca_margin_years?.toFixed(1)}y
                              </span>
                            : <span className="t4">ok</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>}
      </div>

      {sel && <Detail a={sel} onClose={() => setSel(null)} />}
    </div>
  )
}
