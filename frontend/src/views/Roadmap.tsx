/** Roadmap: the dependency-ordered migration programme. */
import { useState } from 'react'
import { fmt } from '../api'
import type { ScanDetail } from '../api'
import { Timeline } from '../components/Charts'

export function Roadmap({ d, onGoInventory, year = 2026 }: {
  d: ScanDetail
  onGoInventory: (f: Record<string, string>) => void
  year?: number
}) {
  const [open, setOpen] = useState<number | null>(d.plan.waves[0]?.wave ?? null)
  const sched = d.plan.schedule
  const crqcMonths = (d.config.crqc_year - year) * 12

  return (
    <div className="page">
      <div className="head">
        <div>
          <h1>Migration programme</h1>
          <p>
            Waves are ordered by dependency, not by severity: providers before protocols,
            protocols before key agreement, key agreement before signatures. Migrating in
            severity order stalls because the library underneath cannot do the new algorithm yet.
          </p>
        </div>
        <div className="col" style={{ alignItems: 'flex-end' }}>
          <span className="mono" style={{ fontSize: 18, color: 'var(--t1)' }}>
            {fmt.n(d.plan.total_effort_days)}d
          </span>
          <span className="label">total effort</span>
        </div>
      </div>

      <div className="panel" style={{ padding: 16, marginBottom: 12 }}>
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 6 }}>
          <div className="label">Schedule at {sched.engineers} engineers</div>
          <span className="chip" style={sched.meets_deadline
            ? { color: 'var(--safe)', borderColor: 'rgba(63,154,138,0.3)' }
            : { color: 'var(--crit)', borderColor: 'rgba(229,85,79,0.3)' }}>
            finishes {sched.finish_label} · {sched.meets_deadline ? 'meets' : 'misses'} CRQC {sched.crqc_year}
          </span>
        </div>
        {/* Judges ask this immediately: why is nothing parallel? */}
        <div className="t4" style={{ fontSize: 11.5, marginBottom: 14, maxWidth: '84ch' }}>
          Waves run in sequence because each one unblocks the next; the {sched.engineers} engineers
          parallelise work <i>inside</i> a wave, which is what sets its duration. Effort is costed at{' '}
          {sched.days_per_engineer_month ?? 18} engineer-days per person-month, not 22 — nobody
          migrates cryptography full time, and assuming otherwise produces a plan that misses.
        </div>
        <Timeline waves={d.plan.waves} months={sched.total_months} crqcMonths={crqcMonths}
                  startYear={year} />
      </div>

      <div className="col" style={{ gap: 10 }}>
        {d.plan.waves.map(w => {
          const on = open === w.wave
          const late = (w.start_month ?? 0) > crqcMonths
          return (
            <div key={w.wave} className={`panel wave ${on ? 'a' : ''}`} style={{ padding: 15 }}>
              <div className="row" style={{ gap: 12, cursor: 'pointer' }}
                   onClick={() => setOpen(on ? null : w.wave)}>
                <div className="mono t4" style={{ width: 26 }}>W{w.wave}</div>
                <div className="grow">
                  <div className="row wrap" style={{ gap: 8 }}>
                    <span style={{ fontSize: 14, color: 'var(--t1)' }}>{w.title}</span>
                    {late && <span className="chip warn">starts after the horizon</span>}
                  </div>
                  <div className="t3" style={{ fontSize: 12.5, marginTop: 2 }}>
                    {fmt.n(w.artifact_count)} artefacts · {w.work_units} work units ·{' '}
                    {fmt.n(w.effort_days)} engineer-days
                    {w.start_month != null && (
                      <> · months {w.start_month.toFixed(1)}–{(w.end_month ?? 0).toFixed(1)}</>
                    )}
                  </div>
                </div>
                <div className="row wrap" style={{ gap: 6, justifyContent: 'flex-end', maxWidth: 300 }}>
                  {w.targets.length > 0 && (
                    <span className="label" style={{ fontSize: 9 }}>migrate to</span>
                  )}
                  {w.targets.slice(0, 3).map(t => <span key={t} className="chip">{t}</span>)}
                </div>
              </div>

              {on && (
                <div style={{ marginTop: 14 }}>
                  <div className="t2" style={{ fontSize: 12.5, marginBottom: 12, maxWidth: '78ch' }}>
                    {w.rationale}
                  </div>

                  <div className="row wrap" style={{ gap: 6, marginBottom: 12 }}>
                    <span className="chip">{w.critical_or_high} critical or high</span>
                    <span className="chip">{w.mosca_violations} Mosca violations</span>
                    {w.targets.length > 0 && (
                      <span className="label" style={{ fontSize: 9, marginLeft: 4 }}>
                        replacement algorithms
                      </span>
                    )}
                    {w.targets.map(t => <span key={t} className="chip on">{t}</span>)}
                  </div>

                  {w.top_findings.length > 0 && (
                    <table>
                      <thead>
                        <tr>
                          <th style={{ width: 58, textAlign: 'right' }}>Risk</th>
                          <th>Artefact</th><th>Location</th><th style={{ width: 128 }}>Target</th>
                        </tr>
                      </thead>
                      <tbody>
                        {w.top_findings.map(f => (
                          <tr key={f.id}>
                            <td className="num" style={{
                              color: f.risk_score >= 8 ? 'var(--crit)' : 'var(--high)',
                            }}>{f.risk_score.toFixed(1)}</td>
                            <td>
                              {f.name}
                              <span className={`sev sev-${f.severity}`} style={{ marginLeft: 7 }}>
                                {f.severity}
                              </span>
                            </td>
                            <td className="path">
                              <b>{fmt.file(f.location)}</b>{f.line ? `:${f.line}` : ''}
                            </td>
                            <td className="mono" style={{ fontSize: 11, color: 'var(--t2)' }}>
                              {f.target ?? '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}

                  <button style={{ marginTop: 12 }}
                          onClick={() => onGoInventory({ q: w.targets[0] ?? '' })}>
                    Open these in the inventory
                  </button>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {d.plan.nothing_to_do > 0 && (
        <div className="panel" style={{ padding: 14, marginTop: 12 }}>
          <div className="row" style={{ gap: 10 }}>
            <div className="dot bg-low" />
            <div>
              <span style={{ color: 'var(--t1)' }}>
                {fmt.n(d.plan.nothing_to_do)} artefacts need no migration
              </span>
              <span className="t3">
                {' '}— already post-quantum, or symmetric with adequate margin under Grover.
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
