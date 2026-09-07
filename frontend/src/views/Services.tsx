/** Services: which application in the estate owns the most risk.
 *
 *  Severity ranking tells you the worst finding. A programme manager needs the
 *  other cut — which team's slice is biggest, what it costs, and whether they
 *  have started at all. Attribution rules are documented in atlas/services.py
 *  and their limits are surfaced here rather than hidden: the `unattributed`
 *  bucket is shown as a row, and the count is called out.
 */
import { useEffect, useMemo, useState } from 'react'
import { IMPACT_LABEL, api, fmt } from '../api'
import type { ScanDetail, ServiceRow, ServicesResponse } from '../api'
import { MiniStack } from '../components/Charts'

const KIND_LABEL: Record<string, string> = {
  source: 'source tree',
  endpoint: 'live endpoint',
  container: 'container image',
  binary: 'compiled binary',
  infrastructure: 'infrastructure',
  cloud: 'managed service',
  hardware: 'hardware module',
  unknown: 'unattributed',
}

type SortKey = 'risk' | 'artifacts' | 'effort' | 'mosca'

export function Services({ d, onGoInventory }: {
  d: ScanDetail
  onGoInventory: (f: Record<string, string>) => void
}) {
  const [data, setData] = useState<ServicesResponse | null>(null)
  const [sel, setSel] = useState<string | null>(null)
  const [sort, setSort] = useState<SortKey>('risk')
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    setData(null); setErr(null); setSel(null)
    api.services(d.scan_id).then(setData)
      .catch(e => setErr(e instanceof Error ? e.message : 'could not load services'))
  }, [d.scan_id])

  const rows = useMemo(() => {
    if (!data) return []
    const r = [...data.services]
    if (sort === 'artifacts') r.sort((a, b) => b.artifacts - a.artifacts)
    else if (sort === 'effort') r.sort((a, b) => b.effort_days - a.effort_days)
    else if (sort === 'mosca') r.sort((a, b) => b.mosca_violations - a.mosca_violations)
    return r
  }, [data, sort])

  const selected = rows.find(r => r.service === sel) ?? null
  const maxEffort = Math.max(1, ...rows.map(r => r.effort_days))

  return (
    <div className="page">
      <div className="head">
        <div>
          <h1>Services</h1>
          <p>
            Every artefact attributed to the application, endpoint, image or
            infrastructure directory that owns it. Ranked by worst finding, because
            that is the conversation you have first.
          </p>
        </div>
        <div className="row" style={{ gap: 4 }}>
          <span className="label" style={{ marginRight: 4 }}>Rank by</span>
          {([['risk', 'Risk'], ['artifacts', 'Artefacts'], ['effort', 'Effort'],
             ['mosca', 'Mosca']] as [SortKey, string][]).map(([k, label]) => (
            <span key={k} className={`chip click ${sort === k ? 'on' : ''}`}
                  onClick={() => setSort(k)}>{label}</span>
          ))}
        </div>
      </div>

      {err && <div className="panel notice crit">Could not load services — {err}</div>}
      {!data && !err && <div className="panel empty">Attributing artefacts…</div>}

      {data && (
        <>
          <div className="grid g4">
            <Stat v={fmt.n(data.totals.services)} k="Components"
                  sub={`${fmt.n(data.totals.artifacts)} artefacts attributed`} />
            <Stat v={rows[0]?.service ?? '—'} k="Highest risk"
                  sub={rows[0] ? `worst finding scores ${rows[0].max_risk.toFixed(1)}` : ''}
                  small />
            <Stat v={fmt.n(data.totals.effort_days)} k="Total effort"
                  sub="engineer-days, deduplicated by file and target" />
            <Stat v={`${data.totals.with_pqc} of ${data.totals.services}`}
                  k="Any PQC present"
                  sub={data.totals.with_pqc === 0
                    ? 'no component has started migrating'
                    : 'components with at least one post-quantum artefact'}
                  color={data.totals.with_pqc ? 'var(--safe)' : 'var(--high)'} />
          </div>

          {data.totals.unattributed > 0 && (
            <div className="panel notice" style={{ marginTop: 12 }}>
              {fmt.n(data.totals.unattributed)} artefacts could not be attributed to a
              component and are grouped as <b>unattributed</b> rather than dropped.
              They sit outside every scanned target root.
            </div>
          )}

          <div className="panel" style={{ marginTop: 12, overflow: 'hidden' }}>
            <table>
              <thead>
                <tr>
                  <th style={{ width: 34, textAlign: 'right' }}>#</th>
                  <th>Component</th>
                  <th style={{ width: 168 }}>Severity mix</th>
                  <th style={{ width: 64, textAlign: 'right' }}>Risk</th>
                  <th style={{ width: 62, textAlign: 'right' }}>Items</th>
                  <th style={{ width: 62, textAlign: 'right' }}>Mosca</th>
                  <th style={{ width: 150 }}>Effort</th>
                  <th style={{ width: 92 }}>PQC</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(r => (
                  <tr key={r.service} className={sel === r.service ? 'sel' : ''}
                      style={{ cursor: 'pointer' }}
                      onClick={() => setSel(sel === r.service ? null : r.service)}>
                    <td className="num t4">{r.risk_rank}</td>
                    <td>
                      <div className="row" style={{ gap: 7 }}>
                        <span style={{ color: 'var(--t1)' }}>{r.service}</span>
                        <span className={`sev sev-${r.worst_severity}`}>
                          {r.worst_severity}
                        </span>
                      </div>
                      <div className="mono t4" style={{ fontSize: 10, marginTop: 1 }}>
                        {KIND_LABEL[r.kind] ?? r.kind} · {r.files} file{r.files === 1 ? '' : 's'}
                        {r.languages.length ? ` · ${r.languages.slice(0, 3).join(' ')}` : ''}
                        {' · '}{r.business_criticality} criticality
                      </div>
                    </td>
                    <td><MiniStack counts={r.by_severity} total={r.artifacts} /></td>
                    <td className="num" style={{
                      color: r.max_risk >= 8 ? 'var(--crit)'
                        : r.max_risk >= 5 ? 'var(--high)' : 'var(--t3)',
                    }}>{r.max_risk.toFixed(1)}</td>
                    <td className="num">{fmt.n(r.artifacts)}</td>
                    <td className="num" style={{
                      color: r.mosca_violations ? 'var(--crit)' : 'var(--t4)',
                    }}>{r.mosca_violations || '—'}</td>
                    <td>
                      <div className="row" style={{ gap: 8 }}>
                        <div className="bar grow">
                          <i style={{ width: `${(r.effort_days / maxEffort) * 100}%` }} />
                        </div>
                        <span className="mono t3" style={{ width: 46, textAlign: 'right' }}>
                          {fmt.n(r.effort_days)}d
                        </span>
                      </div>
                    </td>
                    <td>
                      {r.pqc_present
                        ? <span className="chip ok">present</span>
                        : <span className="chip t4">none</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {selected && <Detail r={selected} onGoInventory={onGoInventory} />}
        </>
      )}
    </div>
  )
}

function Stat({ v, k, sub, color, small }: {
  v: string; k: string; sub?: string; color?: string; small?: boolean
}) {
  return (
    <div className="panel stat">
      <div className="v" style={{ color, fontSize: small ? 17 : undefined,
                                  letterSpacing: small ? '-0.3px' : undefined,
                                  wordBreak: small ? 'break-word' : undefined }}>{v}</div>
      <div className="k label">{k}</div>
      {sub && <div className="sub">{sub}</div>}
    </div>
  )
}

function Detail({ r, onGoInventory }: {
  r: ServiceRow
  onGoInventory: (f: Record<string, string>) => void
}) {
  return (
    <div className="panel" style={{ marginTop: 12, padding: 16 }}>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 14 }}>
        <div>
          <h2 style={{ fontSize: 16 }}>{r.service}</h2>
          <div className="t3" style={{ fontSize: 12.5, marginTop: 3 }}>
            {KIND_LABEL[r.kind] ?? r.kind} · {fmt.n(r.artifacts)} artefacts across{' '}
            {r.files} file{r.files === 1 ? '' : 's'} · mean risk {r.mean_risk.toFixed(2)} ·{' '}
            {fmt.n(r.effort_days)} engineer-days over {r.work_units} work unit
            {r.work_units === 1 ? '' : 's'}
          </div>
        </div>
        <button onClick={() => onGoInventory({ q: r.service })}>
          Open in inventory
        </button>
      </div>

      <div className="grid g3" style={{ alignItems: 'start' }}>
        <div>
          <div className="label" style={{ marginBottom: 8 }}>Quantum impact</div>
          <div className="col" style={{ gap: 5 }}>
            {Object.entries(r.by_impact).map(([k, v]) => (
              <div key={k} className="row" style={{ gap: 8, fontSize: 12.5 }}>
                <span className="grow t2">{IMPACT_LABEL[k] ?? k}</span>
                <span className="mono t3">{fmt.n(v)}</span>
              </div>
            ))}
          </div>
        </div>

        <div>
          <div className="label" style={{ marginBottom: 8 }}>Algorithms in use</div>
          <div className="col" style={{ gap: 5 }}>
            {r.top_algorithms.map(a => (
              <div key={a.name} className="row" style={{ gap: 8, fontSize: 12.5 }}>
                <span className="grow t2">{a.name}</span>
                <span className="mono t4" style={{ fontSize: 10.5 }}>
                  {IMPACT_LABEL[a.impact] ?? a.impact}
                </span>
                <span className="mono t3">{a.count}</span>
              </div>
            ))}
          </div>
        </div>

        {r.worst_finding && (
          <div>
            <div className="label" style={{ marginBottom: 8 }}>Worst finding</div>
            <div className="row" style={{ gap: 8, marginBottom: 4 }}>
              <span className="mono" style={{ color: 'var(--crit)', fontSize: 13 }}>
                {r.worst_finding.risk_score.toFixed(1)}
              </span>
              <span className="t1" style={{ fontSize: 13 }}>{r.worst_finding.name}</span>
              <span className={`sev sev-${r.worst_finding.severity}`}>
                {r.worst_finding.severity}
              </span>
            </div>
            <div className="path">
              {fmt.file(r.worst_finding.location)}
              {r.worst_finding.line ? `:${r.worst_finding.line}` : ''}
            </div>
            {r.worst_finding.target && (
              <div className="t3" style={{ fontSize: 12, marginTop: 6 }}>
                replace with <span className="mono t2">{r.worst_finding.target}</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
