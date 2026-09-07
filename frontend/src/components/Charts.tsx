/** Small SVG chart primitives.
 *
 * Hand-rolled rather than pulled from a chart library: the shapes needed here
 * are simple, and a dependency would bring its own default styling that fights
 * the token system.
 */
import { Fragment } from 'react'
import { fmt } from '../api'

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)',
  low: 'var(--low)', info: 'var(--t4)',
}

const IMPACT_COLOR: Record<string, string> = {
  broken_classically: 'var(--crit)',
  shor_broken: 'var(--high)',
  grover: 'var(--med)',
  classical_ok: 'var(--low)',
  pq_safe: 'var(--safe)',
  unknown: 'var(--t4)',
}

export function colorFor(key: string) {
  return SEV_COLOR[key] ?? IMPACT_COLOR[key] ?? 'var(--accent)'
}

/** Round up to the next 1/2/5 x 10^n step so axis labels are readable. */
function niceCeil(v: number) {
  if (v <= 5) return 5
  const mag = 10 ** Math.floor(Math.log10(v))
  for (const step of [1, 2, 2.5, 5, 10]) {
    const c = step * mag
    if (v <= c) return Math.round(c)
  }
  return Math.round(10 * mag)
}

/** Horizontal stacked bar — one row, proportional segments. */
export function StackBar({ data, total }: { data: [string, number][]; total: number }) {
  const t = total || data.reduce((s, [, v]) => s + v, 0) || 1
  return (
    <div style={{ display: 'flex', height: 6, borderRadius: 3, overflow: 'hidden', gap: 1 }}>
      {data.filter(([, v]) => v > 0).map(([k, v]) => (
        <div key={k} title={`${k}: ${v}`} style={{
          width: `${(v / t) * 100}%`, background: colorFor(k),
          transition: 'width 320ms var(--ease)',
        }} />
      ))}
    </div>
  )
}

/** Labelled distribution rows with a value bar. */
/** Labelled distribution rows.
 *
 *  The bar is the row background rather than a separate right-hand column. An
 *  earlier version put a fixed-width bar on the far right, which left a wide
 *  dead gutter between each label and its value and squeezed the bars into
 *  130px — so a value of 83 rendered as a 12px stub and small values could not
 *  be compared at all. Filling the row means the label sits *on* its own
 *  magnitude and the full panel width is available for encoding.
 */
export function Bars({ data, labels, max, onPick }: {
  data: [string, number][]
  labels?: Record<string, string>
  max?: number
  onPick?: (key: string) => void
}) {
  const m = max ?? Math.max(1, ...data.map(([, v]) => v))
  const total = data.reduce((s, [, v]) => s + v, 0) || 1
  return (
    <div className="col" style={{ gap: 3 }}>
      {data.map(([k, v]) => (
        <div key={k} className={`brow ${onPick ? 'click' : ''}`}
             onClick={onPick ? () => onPick(k) : undefined}
             title={`${labels?.[k] ?? k}: ${fmt.n(v)} (${((v / total) * 100).toFixed(1)}%)`}>
          <i className="fill" style={{ width: `${(v / m) * 100}%`,
                                       background: colorFor(k), opacity: 0.17 }} />
          <span className="dot" style={{ background: colorFor(k) }} />
          <span className="k">{labels?.[k] ?? k}</span>
          <span className="pc mono">{((v / total) * 100).toFixed(v / total < 0.1 ? 1 : 0)}%</span>
          <span className="v mono">{fmt.n(v)}</span>
        </div>
      ))}
    </div>
  )
}

/** Severity mix as a single compact bar, for use inside a table cell. */
export function MiniStack({ counts, total }: {
  counts: Record<string, number>; total: number
}) {
  const order = ['critical', 'high', 'medium', 'low', 'info']
  const t = total || Object.values(counts).reduce((s, v) => s + v, 0) || 1
  return (
    <div style={{ display: 'flex', height: 5, borderRadius: 3, overflow: 'hidden', gap: 1 }}>
      {order.filter(k => counts[k]).map(k => (
        <div key={k} title={`${counts[k]} ${k}`}
             style={{ width: `${(counts[k] / t) * 100}%`, background: colorFor(k) }} />
      ))}
    </div>
  )
}

/** Mosca risk curve: violations vs assumed CRQC year. */
export function Curve({ points, active, onPick }: {
  points: { crqc_year: number; mosca_violations: number; mosca_violation_pct: number; meets_deadline: boolean }[]
  active?: number
  onPick?: (year: number) => void
}) {
  if (!points.length) return null
  const W = 620, H = 150, PL = 34, PB = 22, PT = 10
  // Round the ceiling up to a readable step (5/10/25/50…) so the three gridline
  // labels are numbers a human would choose, not 0/23/45.
  const peak = Math.max(1, ...points.map(p => p.mosca_violations))
  const max = niceCeil(peak * 1.1)
  const x = (i: number) => PL + (i / Math.max(1, points.length - 1)) * (W - PL - 8)
  const y = (v: number) => PT + (1 - v / max) * (H - PT - PB)
  const activeIdx = points.findIndex(p => p.crqc_year === active)
  // Suppress a tick label that would collide with the highlighted year's label.
  const nearActive = (i: number) => activeIdx >= 0 && Math.abs(i - activeIdx) === 1
  const line = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p.mosca_violations).toFixed(1)}`).join(' ')
  const area = `${line} L${x(points.length - 1).toFixed(1)},${H - PB} L${x(0).toFixed(1)},${H - PB} Z`

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: 'auto', display: 'block' }}>
      <defs>
        <linearGradient id="cg" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--crit)" stopOpacity="0.24" />
          <stop offset="100%" stopColor="var(--crit)" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0, 0.5, 1].map(f => (
        <g key={f}>
          <line x1={PL} x2={W - 8} y1={y(max * f)} y2={y(max * f)} stroke="rgba(255,255,255,0.05)" />
          <text x={PL - 7} y={y(max * f) + 3.5} textAnchor="end"
                fill="var(--t4)" fontSize="9" fontFamily="var(--mono)">
            {Math.round(max * f)}
          </text>
        </g>
      ))}
      <path d={area} fill="url(#cg)" />
      <path d={line} fill="none" stroke="var(--crit)" strokeWidth="1.6" />
      {points.map((p, i) => {
        const on = p.crqc_year === active
        return (
          <g key={p.crqc_year} onClick={() => onPick?.(p.crqc_year)}
             style={{ cursor: onPick ? 'pointer' : 'default' }}>
            <rect x={x(i) - 9} y={PT} width={18} height={H - PT - PB} fill="transparent" />
            <circle cx={x(i)} cy={y(p.mosca_violations)} r={on ? 4 : 2.4}
                    fill={on ? 'var(--t1)' : 'var(--crit)'} />
            {(on || (i % 2 === 0 && !nearActive(i))) && (
              <text x={x(i)} y={H - 6} textAnchor="middle"
                    fill={on ? 'var(--t1)' : 'var(--t4)'} fontSize="9" fontFamily="var(--mono)">
                {p.crqc_year}
              </text>
            )}
          </g>
        )
      })}
    </svg>
  )
}

/** Criticality x quantum-impact heat grid.
 *
 *  Cells are clickable: the grid is the entry point to the inventory, since
 *  "critical business system running a Shor-broken primitive" is the query an
 *  analyst actually wants, and clicking the cell is faster than rebuilding it
 *  out of two filter dropdowns.
 */
export function Heat({ cells, onPick }: {
  cells: { criticality: string; impact: string; count: number; max_risk: number
           mosca?: number; lifetime_band?: string }[]
  onPick?: (criticality: string, impact: string) => void
}) {
  const crits = ['critical', 'high', 'medium', 'low']
  const impacts = ['broken_classically', 'shor_broken', 'grover', 'unknown', 'classical_ok', 'pq_safe']
  const short: Record<string, string> = {
    broken_classically: 'BROKEN', shor_broken: 'SHOR', grover: 'GROVER',
    classical_ok: 'ADEQ', pq_safe: 'PQC', unknown: 'UNCL',
  }
  const full: Record<string, string> = {
    broken_classically: 'already broken classically', shor_broken: 'falls to Shor',
    grover: 'weakened by Grover', classical_ok: 'quantum-adequate',
    pq_safe: 'post-quantum', unknown: 'unclassified',
  }
  const at = (c: string, i: string) => cells.find(x => x.criticality === c && x.impact === i)
  const max = Math.max(1, ...cells.map(c => c.count))

  return (
    <div style={{ display: 'grid', gridTemplateColumns: `74px repeat(${impacts.length}, minmax(0,1fr))`, gap: 3 }}>
      <div />
      {impacts.map(i => (
        <div key={i} className="label" title={full[i]}
             style={{ textAlign: 'center', fontSize: 9 }}>{short[i]}</div>
      ))}
      {crits.map(c => (
        <Fragment key={c}>
          <div className="label" style={{ display: 'flex', alignItems: 'center', fontSize: 9 }}>{c}</div>
          {impacts.map(i => {
            const cell = at(c, i)
            const n = cell?.count ?? 0
            const heat = n ? 0.1 + 0.72 * (n / max) : 0
            const danger = i === 'broken_classically' || i === 'shor_broken'
            const tip = cell
              ? [`${n} ${c}-criticality artefacts ${full[i]}`,
                 `worst risk ${cell.max_risk}`,
                 cell.mosca ? `${cell.mosca} past the Mosca deadline` : null,
                 cell.lifetime_band ? `longest shelf-life ${cell.lifetime_band}` : null,
                 onPick ? 'click to open in the inventory' : null,
                ].filter(Boolean).join(' · ')
              : `no ${c}-criticality artefacts ${full[i]}`
            return (
              <div key={c + i} title={tip}
                   onClick={n && onPick ? () => onPick(c, i) : undefined}
                   style={{
                     height: 34, borderRadius: 5, display: 'grid', placeItems: 'center',
                     fontFamily: 'var(--mono)', fontSize: 11,
                     cursor: n && onPick ? 'pointer' : 'default',
                     color: n ? 'var(--t1)' : 'var(--t4)',
                     background: n
                       ? (danger ? `rgba(229,85,79,${heat})` : `rgba(94,106,210,${heat})`)
                       : 'rgba(255,255,255,0.015)',
                     border: '1px solid var(--line)',
                     transition: 'background 200ms var(--ease)',
                   }}>
                {n ? fmt.n(n) : '·'}
              </div>
            )
          })}
        </Fragment>
      ))}
    </div>
  )
}

/** Wave timeline as proportional month blocks, with a year axis and the CRQC
 *  horizon marked. The axis always spans to the horizon so the gap between
 *  "programme done" and "quantum arrives" is the visible message. */
export function Timeline({ waves, months, crqcMonths, startYear = 2026 }: {
  waves: { wave: number; title: string; start_month?: number; end_month?: number; effort_days: number }[]
  months: number
  crqcMonths: number
  startYear?: number
}) {
  const span = Math.max(months, crqcMonths) * 1.04 || 1
  const crqcPct = (crqcMonths / span) * 100
  // Year ticks at a stride that keeps roughly 6-9 labels regardless of span.
  const years = Math.max(1, Math.ceil(span / 12))
  const stride = years <= 8 ? 1 : years <= 16 ? 2 : 5
  const ticks: number[] = []
  for (let y = 0; y <= years; y += stride) ticks.push(y)

  return (
    <div className="col" style={{ gap: 6 }}>
      {/* horizon marker; label flips to the left of the rule when it is near
          the right edge so it never overruns the panel or a duration label */}
      <div style={{ position: 'relative', height: 15, marginLeft: 32, marginRight: 78 }}>
        <div style={{
          position: 'absolute', left: `${crqcPct}%`, top: 0, bottom: -6,
          borderLeft: '1px dashed var(--crit)',
        }}>
          <span className="mono" style={{
            position: 'absolute', top: 0,
            ...(crqcPct > 62 ? { right: 5 } : { left: 5 }),
            color: 'var(--crit)', fontSize: 9.5, whiteSpace: 'nowrap',
          }}>
            CRQC {startYear + Math.round(crqcMonths / 12)}
          </span>
        </div>
      </div>
      {waves.map(w => {
        const s = w.start_month ?? 0, e = w.end_month ?? 0
        const late = s > crqcMonths
        return (
          <div key={w.wave} className="row" style={{ gap: 10 }}>
            <div className="mono t4" style={{ width: 22 }}>W{w.wave}</div>
            <div className="grow" style={{ position: 'relative', height: 20 }}>
              <div style={{
                position: 'absolute', left: `${(s / span) * 100}%`,
                width: `${Math.max(0.7, ((e - s) / span) * 100)}%`,
                top: 3, height: 14, borderRadius: 3,
                background: late ? 'rgba(229,85,79,0.55)' : 'var(--accent)',
                border: `1px solid ${late ? 'rgba(229,85,79,0.8)' : 'var(--accent-line)'}`,
                transition: 'all 320ms var(--ease)',
              }} title={`${w.title} — months ${s.toFixed(1)}–${e.toFixed(1)}`} />
            </div>
            <div className="mono t4" style={{ width: 68, textAlign: 'right' }}>
              {e - s < 0.5 ? '<2wk' : fmt.months(e - s)}
            </div>
          </div>
        )
      })}
      {/* year axis */}
      <div style={{ position: 'relative', height: 14, marginLeft: 32, marginRight: 78,
                    borderTop: '1px solid var(--line)', marginTop: 2 }}>
        {ticks.map(y => (
          <span key={y} className="mono t4" style={{
            position: 'absolute', left: `${((y * 12) / span) * 100}%`, top: 2,
            fontSize: 9, transform: 'translateX(-50%)', whiteSpace: 'nowrap',
          }}>{startYear + y}</span>
        ))}
      </div>
    </div>
  )
}
