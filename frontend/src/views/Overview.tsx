/** Overview: what the estate looks like and what is already past its deadline. */
import { IMPACT_LABEL, fmt } from '../api'
import type { ScanDetail } from '../api'
import { Bars, Heat, StackBar } from '../components/Charts'

export function Overview({ d, onGoInventory }: {
  d: ScanDetail
  onGoInventory: (filter: Record<string, string>) => void
}) {
  const s = d.summary
  const sched = d.plan.schedule
  const sev = (['critical', 'high', 'medium', 'low', 'info'] as const)
    .map(k => [k, s.by_severity[k] ?? 0] as [string, number])
  const impacts = ['broken_classically', 'shor_broken', 'grover', 'unknown', 'classical_ok', 'pq_safe']
    .map(k => [k, s.by_impact[k] ?? 0] as [string, number])
    .filter(([, v]) => v > 0)
  const types = Object.entries(s.by_type).sort((a, b) => b[1] - a[1])

  const stats = [
    {
      k: 'Artefacts discovered', v: fmt.n(s.artifacts_found),
      sub: `${fmt.n(s.files_scanned)} files · ${s.duration_seconds.toFixed(2)}s`,
    },
    {
      k: 'Quantum-vulnerable', v: fmt.pct(s.quantum_vulnerable_pct),
      sub: `${fmt.n((s.by_impact.shor_broken ?? 0) + (s.by_impact.grover ?? 0))} Shor/Grover · ${fmt.n(s.by_impact.broken_classically ?? 0)} already broken today`,
      color: 'var(--high)',
    },
    {
      k: 'Mosca violations', v: fmt.n(s.mosca_violations),
      sub: `past the ${d.config.crqc_year} deadline`,
      color: s.mosca_violations ? 'var(--crit)' : 'var(--safe)',
    },
    {
      k: 'Migration effort', v: `${fmt.n(s.migration_effort_days)}`,
      sub: `engineer-days · ${fmt.months(sched.total_months)} elapsed at ${sched.engineers} engineers`,
    },
  ]

  return (
    <div className="page">
      <div className="head">
        <div>
          <h1>{d.config.organization}</h1>
          <p>
            {fmt.n(s.artifacts_found)} cryptographic artefacts across {s.targets} target
            {s.targets === 1 ? '' : 's'}, evaluated against a {d.config.crqc_year} cryptographically
            relevant quantum computer.
          </p>
        </div>
        <div className="row" style={{ gap: 6 }}>
          <a href={d.exports.cbom + '?download=true'}><button>CBOM</button></a>
          <a href={d.exports.sarif + '?download=true'}><button>SARIF</button></a>
          <a href={d.exports.report} target="_blank" rel="noreferrer"><button>Report</button></a>
        </div>
      </div>

      <div className="grid g4">
        {stats.map(x => (
          <div key={x.k} className="panel stat">
            <div className="v" style={{ color: x.color }}>{x.v}</div>
            <div className="k label">{x.k}</div>
            <div className="sub">{x.sub}</div>
          </div>
        ))}
      </div>

      <div className="panel" style={{
        marginTop: 12, padding: '14px 16px',
        borderColor: sched.meets_deadline ? 'rgba(63,154,138,0.3)' : 'rgba(229,85,79,0.32)',
        background: sched.meets_deadline ? 'rgba(63,154,138,0.05)' : 'rgba(229,85,79,0.05)',
      }}>
        <div className="row wrap" style={{ gap: 12 }}>
          <div className={`dot ${sched.meets_deadline ? 'bg-low' : 'bg-critical'}`} />
          <div className="grow">
            <div style={{ fontSize: 14, color: 'var(--t1)' }}>
              {sched.meets_deadline
                ? `On track: at ${sched.engineers} engineers the programme completes ${sched.finish_label}, ${sched.slack_years.toFixed(1)} years before the ${sched.crqc_year} horizon.`
                : `Off track: at ${sched.engineers} engineers the programme completes ${sched.finish_label}, ${Math.abs(sched.slack_years).toFixed(1)} years after the ${sched.crqc_year} horizon.`}
            </div>
            <div className="t3" style={{ fontSize: 12.5, marginTop: 3 }}>
              {fmt.n(d.plan.total_effort_days)} engineer-days across {d.plan.total_work_units} work
              units. {fmt.n(d.plan.nothing_to_do)} artefacts need no migration.
            </div>
          </div>
        </div>
      </div>

      <div className="grid g2" style={{ marginTop: 12, alignItems: 'start' }}>
        <div className="panel" style={{ padding: 15 }}>
          <div className="label" style={{ marginBottom: 10 }}>Severity</div>
          <div style={{ marginBottom: 12 }}><StackBar data={sev} total={s.artifacts_found} /></div>
          <Bars data={sev} />
          <div className="row" style={{ marginTop: 12, gap: 5 }}>
            <button onClick={() => onGoInventory({ severity: 'critical,high' })}>
              Show critical + high
            </button>
            <button onClick={() => onGoInventory({ mosca_only: 'true' })}>
              Show Mosca violations
            </button>
          </div>
        </div>

        <div className="panel" style={{ padding: 15 }}>
          <div className="label" style={{ marginBottom: 10 }}>Quantum impact</div>
          <Bars data={impacts} labels={IMPACT_LABEL} />
        </div>
      </div>

      <div className="panel" style={{ marginTop: 12, padding: 15 }}>
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
          <div className="label">Business criticality vs quantum impact</div>
          <span className="t4" style={{ fontSize: 11.5 }}>
            top-left is where a migration programme starts · click a cell to open it
          </span>
        </div>
        <Heat cells={d.exposure_matrix}
              onPick={(criticality, impact) => onGoInventory({ criticality, impact })} />
      </div>

      <div className="grid g2" style={{ marginTop: 12, alignItems: 'start' }}>
        <div className="panel" style={{ padding: 15 }}>
          <div className="label" style={{ marginBottom: 10 }}>Artefact classes</div>
          <Bars data={types} />
        </div>

        <div className="panel" style={{ overflow: 'hidden' }}>
          <div className="label" style={{ padding: '14px 15px 10px' }}>
            Algorithms in use · highest risk first
          </div>
          <div style={{ maxHeight: 328, overflowY: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th>Algorithm</th><th>Impact</th>
                  <th style={{ textAlign: 'right' }}>Uses</th>
                  <th style={{ textAlign: 'right' }}>Risk</th>
                  <th>Replace with</th>
                </tr>
              </thead>
              <tbody>
                {d.algorithms.map(a => (
                  <tr key={a.name} style={{ cursor: 'pointer' }}
                      onClick={() => onGoInventory({ q: a.name })}>
                    <td>{a.name}</td>
                    <td className="mono t3" style={{ fontSize: 11 }}>
                      {IMPACT_LABEL[a.impact] ?? a.impact}
                    </td>
                    <td className="num">{fmt.n(a.count)}</td>
                    <td className="num" style={{
                      color: a.max_risk >= 8 ? 'var(--crit)' : a.max_risk >= 5 ? 'var(--high)' : 'var(--t3)',
                    }}>{a.max_risk.toFixed(1)}</td>
                    <td className="mono" style={{ fontSize: 11, color: 'var(--t2)' }}>
                      {a.target ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}
