/** Mosca simulator: change the assumptions, watch the deadline move.
 *
 * This is the argument the tool exists to make. Nobody knows the CRQC year, so
 * the honest move is to make the assumption a control and show how the answer
 * responds. Every recomputation is a pure re-run of the risk model over the
 * stored inventory — no rescan, which is why it feels instant.
 */
import { useEffect, useMemo, useState } from 'react'
import { api, fmt } from '../api'
import type { CurvePoint, ScanDetail, SimResult } from '../api'
import { Bars, Curve, StackBar, Timeline } from '../components/Charts'

export function Simulator({ d, year = 2026 }: { d: ScanDetail; year?: number }) {
  const [crqc, setCrqc] = useState(d.config.crqc_year)
  const [life, setLife] = useState(5)
  const [months, setMonths] = useState(18)
  const [eng, setEng] = useState(d.plan.schedule.engineers)
  const [sim, setSim] = useState<SimResult | null>(null)
  const [curve, setCurve] = useState<CurvePoint[]>([])
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.curve(d.scan_id, 2028, 2045).then(r => setCurve(r.curve)).catch(() => {})
  }, [d.scan_id])

  useEffect(() => {
    const t = setTimeout(() => {
      setBusy(true)
      api.simulate({
        scan_id: d.scan_id, crqc_year: crqc, data_lifetime_years: life,
        migration_months: months, engineers: eng,
      }).then(setSim).finally(() => setBusy(false))
    }, 90)
    return () => clearTimeout(t)
  }, [d.scan_id, crqc, life, months, eng])

  const base = d.summary
  const s = sim?.summary
  const sched = sim?.plan.schedule
  const crqcMonths = (crqc - year) * 12

  const delta = useMemo(() => {
    if (!s) return 0
    return s.mosca_violations - base.mosca_violations
  }, [s, base.mosca_violations])

  const presets = [
    { label: 'NSA CNSA 2.0 (2033)', crqc: 2033, life: 5, months: 18 },
    { label: 'Aggressive (2030)', crqc: 2030, life: 7, months: 24 },
    { label: 'Consensus median (2035)', crqc: 2035, life: 5, months: 18 },
    { label: 'Long-lived records (2033)', crqc: 2033, life: 25, months: 18 },
  ]

  return (
    <div className="page">
      <div className="head">
        <div>
          <h1>Mosca simulator</h1>
          <p>
            Mosca's inequality: if data shelf-life plus migration time exceeds the years left
            before a quantum computer breaks your algorithm, you are already late. Nobody knows
            that year — so change it and watch which findings flip.
          </p>
        </div>
        {busy && <div className="spin" />}
      </div>

      <div className="grid" style={{ gridTemplateColumns: 'minmax(0,340px) minmax(0,1fr)', alignItems: 'start' }}>
        <div className="panel" style={{ padding: 16 }}>
          <div className="label" style={{ marginBottom: 12 }}>Assumptions</div>

          <Control label="CRQC arrival year" value={String(crqc)}
                   note={`${crqc - year} years from now`}
                   min={2027} max={2050} v={crqc} onChange={setCrqc}
                   minLabel="2027" maxLabel="2050" />
          <Control label="Data shelf-life" value={`${life}y`}
                   note="how long intercepted data stays sensitive"
                   min={1} max={30} v={life} onChange={setLife}
                   minLabel="1y" maxLabel="30y" />
          <Control label="Migration time per system" value={fmt.months(months)}
                   note="replacement effort for one system, in months"
                   min={1} max={72} v={months} onChange={setMonths}
                   minLabel="1mo" maxLabel="72mo" />
          <Control label="Engineers assigned" value={String(eng)}
                   note="drives the programme schedule"
                   min={1} max={40} v={eng} onChange={setEng}
                   minLabel="1" maxLabel="40" />

          <div className="label" style={{ margin: '18px 0 8px' }}>Presets</div>
          <div className="col" style={{ gap: 5 }}>
            {presets.map(p => (
              <button key={p.label} style={{ justifyContent: 'flex-start', textAlign: 'left' }}
                      onClick={() => { setCrqc(p.crqc); setLife(p.life); setMonths(p.months) }}>
                {p.label}
              </button>
            ))}
          </div>
        </div>

        <div className="col" style={{ gap: 12 }}>
          <div className="grid g3">
            <div className="panel stat">
              <div className="v" style={{ color: s?.mosca_violations ? 'var(--crit)' : 'var(--safe)' }}>
                {s ? fmt.n(s.mosca_violations) : '—'}
              </div>
              <div className="k label">Mosca violations</div>
              <div className="sub">
                {s ? `${fmt.pct(s.mosca_violation_pct)} of estate` : ''}
                {delta !== 0 && s ? ` · ${delta > 0 ? '+' : ''}${fmt.n(delta)} vs scan` : ''}
              </div>
            </div>
            <div className="panel stat">
              <div className="v" style={{ color: 'var(--crit)' }}>
                {s ? fmt.n(s.by_severity.critical ?? 0) : '—'}
              </div>
              <div className="k label">Critical findings</div>
              <div className="sub">
                {s && (s.by_severity.critical ?? 0) !== (base.by_severity.critical ?? 0)
                  ? `was ${base.by_severity.critical ?? 0} at the scanned ${d.config.crqc_year} horizon`
                  : `unchanged from the scanned ${d.config.crqc_year} horizon`}
              </div>
            </div>
            <div className="panel stat">
              <div className="v">{sched ? fmt.months(sched.total_months) : '—'}</div>
              <div className="k label">Programme length</div>
              <div className="sub">
                {sim ? `${fmt.n(sim.plan.total_effort_days)} engineer-days · ${sim.plan.total_work_units} work units` : ''}
              </div>
            </div>
          </div>

          {sched && (
            <div className="panel" style={{
              padding: '13px 15px',
              borderColor: sched.meets_deadline ? 'rgba(63,154,138,0.3)' : 'rgba(229,85,79,0.32)',
              background: sched.meets_deadline ? 'rgba(63,154,138,0.05)' : 'rgba(229,85,79,0.05)',
            }}>
              <div className="row" style={{ gap: 11 }}>
                <div className={`dot ${sched.meets_deadline ? 'bg-low' : 'bg-critical'}`} />
                <div style={{ fontSize: 13.5 }}>
                  {sched.meets_deadline
                    ? `Programme completes ${sched.finish_label}, ${sched.slack_years.toFixed(1)} years before CRQC ${crqc}.`
                    : `Programme completes ${sched.finish_label}, ${Math.abs(sched.slack_years).toFixed(1)} years after CRQC ${crqc}.`}
                  <span className="t3">
                    {' '}{fmt.n(sim!.plan.total_effort_days)} engineer-days ÷ {sched.engineers} engineers
                    = {fmt.months(sched.total_months)} elapsed. Separate from the per-artefact Mosca
                    margin above, which asks whether individual data is already exposed.
                  </span>
                </div>
              </div>
            </div>
          )}

          <div className="panel" style={{ padding: 15 }}>
            <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
              <div className="label">Violations vs assumed CRQC year</div>
              <span className="t4" style={{ fontSize: 11.5 }}>click a year to set it</span>
            </div>
            <Curve points={curve} active={crqc} onPick={setCrqc} />
          </div>

          {sim && (
            <div className="grid g2" style={{ alignItems: 'start' }}>
              <div className="panel" style={{ padding: 15 }}>
                <div className="label" style={{ marginBottom: 10 }}>Severity at these assumptions</div>
                <div style={{ marginBottom: 12 }}>
                  <StackBar
                    data={(['critical', 'high', 'medium', 'low', 'info'] as const)
                      .map(k => [k, sim.summary.by_severity[k] ?? 0])}
                    total={sim.summary.artifacts} />
                </div>
                <Bars data={(['critical', 'high', 'medium', 'low', 'info'] as const)
                  .map(k => [k, sim.summary.by_severity[k] ?? 0])} />
              </div>

              <div className="panel" style={{ padding: 15 }}>
                <div className="label" style={{ marginBottom: 12 }}>Programme against the horizon</div>
                <Timeline waves={sim.plan.waves} months={sim.plan.schedule.total_months}
                          crqcMonths={crqcMonths} startYear={year} />
              </div>
            </div>
          )}

          {sim && sim.summary.top_risks.length > 0 && (
            <div className="panel" style={{ overflow: 'hidden' }}>
              <div className="label" style={{ padding: '13px 15px 9px' }}>
                Highest risk at CRQC {crqc}
              </div>
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 58, textAlign: 'right' }}>Risk</th>
                    <th>Artefact</th><th>Location</th>
                  </tr>
                </thead>
                <tbody>
                  {sim.summary.top_risks.slice(0, 10).map(r => (
                    <tr key={r.id}>
                      <td className="num" style={{ color: 'var(--crit)' }}>{r.risk_score.toFixed(1)}</td>
                      <td>{r.name}</td>
                      <td className="path">{fmt.file(r.location)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function Control({ label, value, note, min, max, v, onChange, minLabel, maxLabel }: {
  label: string; value: string; note: string
  min: number; max: number; v: number; onChange: (n: number) => void
  minLabel?: string; maxLabel?: string
}) {
  return (
    <div style={{ marginBottom: 15 }}>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 5 }}>
        <span className="label">{label}</span>
        <span className="mono" style={{ color: 'var(--t1)', fontSize: 12 }}>{value}</span>
      </div>
      <input className="slider" type="range" min={min} max={max} value={v}
             onChange={e => onChange(+e.target.value)} aria-label={label}
             aria-valuetext={value}
             style={{
               background: `linear-gradient(to right, var(--accent) 0%, var(--accent) ${
                 ((v - min) / (max - min)) * 100}%, rgba(255,255,255,0.1) ${
                 ((v - min) / (max - min)) * 100}%, rgba(255,255,255,0.1) 100%)`,
             }} />
      <div className="row" style={{ justifyContent: 'space-between', marginTop: 2 }}>
        <span className="mono t4" style={{ fontSize: 9.5 }}>{minLabel ?? min}</span>
        <span className="mono t4" style={{ fontSize: 9.5 }}>{maxLabel ?? max}</span>
      </div>
      <div className="t4" style={{ fontSize: 11, marginTop: 4 }}>{note}</div>
    </div>
  )
}
