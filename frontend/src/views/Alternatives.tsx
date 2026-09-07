import { useEffect, useState } from 'react'
import { api, fmt, IMPACT_LABEL } from '../api'
import type { ScanDetail, AlternativesRollup } from '../api'
import { ArrowRight, Zap, Info } from 'lucide-react'

export function Alternatives({
  d,
  onGoInventory,
}: {
  d: ScanDetail
  onGoInventory: (f: Record<string, string>) => void
}) {
  const [data, setData] = useState<AlternativesRollup | null>(null)
  const [selectedAlgo, setSelectedAlgo] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    setData(null)
    setErr(null)
    api.alternatives(d.scan_id)
      .then(r => {
        setData(r)
        if (r.by_algorithm.length > 0) setSelectedAlgo(r.by_algorithm[0].current)
      })
      .catch(e => setErr(e instanceof Error ? e.message : 'could not load alternatives advisory'))
  }, [d.scan_id])

  const curAlgo = data?.by_algorithm.find(a => a.current === selectedAlgo) ?? data?.by_algorithm[0]

  return (
    <div className="page">
      <div className="head">
        <div>
          <div className="eyebrow-tag">
            <Zap size={13} className="text-accent" />
            NIST PQC STANDARDS ENGINE
          </div>
          <h1>PQC & Hybrid Alternatives</h1>
          <p>
            Algorithmic recommendation engine scoring post-quantum candidates (ML-KEM, ML-DSA, SLH-DSA, LMS)
            against latency, wire payload budget, CPU constraints, and hybrid operational readiness.
          </p>
        </div>
      </div>

      {err && <div className="panel notice crit">Could not load alternatives data — {err}</div>}
      {!data && !err && <div className="panel empty">Computing optimal PQC replacement paths…</div>}

      {data && (
        <>
          <div className="grid g4">
            <div className="panel stat">
              <div className="v" style={{ color: 'var(--safe)' }}>
                {data.coverage.advised} <span style={{ fontSize: 15, color: 'var(--t3)' }}>/ {data.coverage.algorithms_seen}</span>
              </div>
              <div className="k label">Replacement Coverage</div>
              <div className="sub">Discovered algorithms with actionable PQC targets</div>
            </div>

            <div className="panel stat">
              <div className="v" style={{ color: 'var(--accent)' }}>
                +{fmt.bytes(data.wire_impact.total_added_bytes_per_op)}
              </div>
              <div className="k label">Net Wire Delta</div>
              <div className="sub">Additional wire overhead across all replaced primitives</div>
            </div>

            <div className="panel stat">
              <div className="v" style={{ color: 'var(--t1)', fontSize: 17 }}>
                {data.wire_impact.worst_offender ?? 'None'}
              </div>
              <div className="k label">Highest Wire Overhead</div>
              <div className="sub">Requires fragmentation or MTU optimization</div>
            </div>

            <div className="panel stat">
              <div className="v" style={{ color: 'var(--safe)' }}>
                FIPS 203/204
              </div>
              <div className="k label">Standard Alignment</div>
              <div className="sub">Prioritizes NIST standard ratified algorithms</div>
            </div>
          </div>

          <div style={{ marginTop: 24, display: 'grid', gridTemplateColumns: 'minmax(300px, 380px) 1fr', gap: 16 }}>
            {/* Left list of algorithms */}
            <div className="panel" style={{ padding: '12px 0', overflow: 'hidden' }}>
              <div style={{ padding: '0 16px 10px', borderBottom: '1px solid var(--line)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="label">Vulnerable Algorithms</span>
                <span className="mono t4" style={{ fontSize: 11 }}>{data.by_algorithm.length} found</span>
              </div>
              <div style={{ maxHeight: 520, overflowY: 'auto' }}>
                {data.by_algorithm.map(item => (
                  <div
                    key={item.current}
                    onClick={() => setSelectedAlgo(item.current)}
                    style={{
                      padding: '12px 16px',
                      borderBottom: '1px solid var(--line)',
                      cursor: 'pointer',
                      background: selectedAlgo === item.current ? 'var(--accent-dim)' : 'transparent',
                      borderLeft: selectedAlgo === item.current ? '3px solid var(--accent)' : '3px solid transparent',
                      transition: 'background 140ms ease',
                    }}
                  >
                    <div className="row" style={{ justifyContent: 'space-between' }}>
                      <span style={{ fontWeight: 500, color: 'var(--t1)' }}>{item.current}</span>
                      <span className="mono t4" style={{ fontSize: 11 }}>{item.uses} uses</span>
                    </div>
                    <div className="row" style={{ marginTop: 4, gap: 6 }}>
                      <span className="mono t4" style={{ fontSize: 10 }}>{IMPACT_LABEL[item.impact] ?? item.impact}</span>
                      <ArrowRight size={10} className="t4" />
                      <span className="mono" style={{ fontSize: 11, color: 'var(--safe)' }}>
                        {item.choose ?? 'Retire primitive'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Right details of chosen algorithm */}
            {curAlgo ? (
              <div className="panel" style={{ padding: 20 }}>
                <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--line)', paddingBottom: 16 }}>
                  <div>
                    <span className="label">REPLACEMENT BLUEPRINT</span>
                    <h2 style={{ fontSize: 20, marginTop: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span>{curAlgo.current}</span>
                      <ArrowRight size={16} className="t3" />
                      <span style={{ color: 'var(--safe)' }}>{curAlgo.choose ?? 'Deprecate'}</span>
                    </h2>
                    <div className="t3" style={{ fontSize: 12, marginTop: 4 }}>
                      Used across {curAlgo.uses} call-sites in {curAlgo.files} files · Profile: <b>{curAlgo.profile_label}</b>
                    </div>
                  </div>
                  <button
                    className="primary"
                    onClick={() => onGoInventory({ q: curAlgo.current })}
                  >
                    View in Inventory
                  </button>
                </div>

                <div className="grid g3" style={{ marginTop: 20 }}>
                  <div className="panel" style={{ padding: 14, background: 'var(--panel-2)' }}>
                    <div className="label">Wire Impact</div>
                    <div className="mono" style={{ fontSize: 18, fontWeight: 500, color: curAlgo.wire_delta_bytes && curAlgo.wire_delta_bytes > 2000 ? 'var(--high)' : 'var(--t1)', marginTop: 4 }}>
                      {curAlgo.wire_delta_bytes ? `+${fmt.bytes(curAlgo.wire_delta_bytes)}` : 'Negligible'}
                    </div>
                    <div className="mono t4" style={{ fontSize: 10, marginTop: 4 }}>
                      per cryptographic operation / packet
                    </div>
                  </div>

                  <div className="panel" style={{ padding: 14, background: 'var(--panel-2)' }}>
                    <div className="label">Estimated Migration Effort</div>
                    <div className="mono" style={{ fontSize: 18, fontWeight: 500, color: 'var(--accent)', marginTop: 4 }}>
                      {curAlgo.effort_days} engineer-days
                    </div>
                    <div className="mono t4" style={{ fontSize: 10, marginTop: 4 }}>
                      Refactoring, integration testing & rollout
                    </div>
                  </div>

                  <div className="panel" style={{ padding: 14, background: 'var(--panel-2)' }}>
                    <div className="label">Second-choice Candidate</div>
                    <div className="mono" style={{ fontSize: 15, fontWeight: 500, color: 'var(--t2)', marginTop: 6 }}>
                      {curAlgo.runner_up ?? 'None'}
                    </div>
                    <div className="mono t4" style={{ fontSize: 10, marginTop: 4 }}>
                      Viable fallback target
                    </div>
                  </div>
                </div>

                <div style={{ marginTop: 22 }}>
                  <div className="label" style={{ marginBottom: 6 }}>Selection Rationale</div>
                  <div className="panel" style={{ padding: 14, background: 'var(--panel-2)', fontSize: 13, lineHeight: 1.6, color: 'var(--t2)' }}>
                    {curAlgo.because}
                  </div>
                </div>

                {curAlgo.tradeoff && (
                  <div style={{ marginTop: 16 }}>
                    <div className="label" style={{ marginBottom: 6 }}>Known Tradeoffs & Considerations</div>
                    <div className="panel notice" style={{ padding: 12, fontSize: 12.5, color: 'var(--t3)' }}>
                      <Info size={14} style={{ flex: 'none', marginRight: 8, verticalAlign: 'middle' }} />
                      {curAlgo.tradeoff}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="panel empty">Select an algorithm on the left to inspect PQC recommendations</div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
