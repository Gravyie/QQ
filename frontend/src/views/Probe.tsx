/** Live TLS probe: what the estate actually negotiates on the wire.
 *
 * Source scanning shows intent; a handshake shows reality. A load balancer or
 * CDN in front of an application frequently negotiates something different from
 * what the code configures, which is exactly the gap this view exposes.
 */
import { useState } from 'react'
import { api } from '../api'
import type { ProbeResult } from '../api'

export function Probe() {
  const [input, setInput] = useState('cloudflare.com, github.com, google.com')
  const [results, setResults] = useState<ProbeResult[]>([])
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  async function run() {
    const eps = input.split(',').map(s => s.trim()).filter(Boolean)
    if (!eps.length) return
    setBusy(true); setErr(null)
    try {
      const r = await api.probe(eps)
      setResults(r.results)
    } catch (e) {
      setErr(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="page">
      <div className="head">
        <div>
          <h1>Live endpoint probe</h1>
          <p>
            Real TLS handshakes against real hosts. Atlas records the negotiated version, cipher
            and key-exchange group, tests whether legacy protocol versions are still accepted, and
            reads the served certificate — then feeds all of it through the same risk model.
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          {busy && <div className="spin" />}
          <button className="primary" onClick={run} disabled={busy}>Probe endpoints</button>
        </div>
      </div>

      <div className="panel" style={{ padding: 13, marginBottom: 12 }}>
        <div className="row" style={{ gap: 9 }}>
          <input className="grow" value={input} onChange={e => setInput(e.target.value)}
                 onKeyDown={e => e.key === 'Enter' && run()}
                 placeholder="host, host:port, …" />
        </div>
        <div className="t4" style={{ fontSize: 11, marginTop: 7 }}>
          Outbound TLS connections are made from this machine. Only probe hosts you are
          authorised to test.
        </div>
      </div>

      {err && <div className="panel" style={{ padding: 13, borderColor: 'rgba(229,85,79,0.3)' }}>
        <span style={{ color: 'var(--crit)' }}>{err}</span>
      </div>}

      {results.length === 0 && !busy && !err && (
        <div className="panel empty">No probes yet.</div>
      )}

      <div className="col" style={{ gap: 12 }}>
        {results.map(({ probe: p, artifacts }) => {
          const cert = (p.certificate ?? {}) as Record<string, unknown>
          return (
            <div key={`${p.host}:${p.port}`} className="panel" style={{ padding: 16 }}>
              <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
                <div className="row" style={{ gap: 9 }}>
                  <div className={`dot ${p.reachable ? 'bg-low' : 'bg-critical'}`} />
                  <span style={{ fontSize: 15, color: 'var(--t1)' }}>{p.host}</span>
                  <span className="mono t4">:{p.port}</span>
                </div>
                <div className="row wrap" style={{ gap: 5 }}>
                  {p.negotiated_version && <span className="chip on">{p.negotiated_version}</span>}
                  {p.pqc_hybrid_supported === true && <span className="chip ok">hybrid PQC</span>}
                  {p.pqc_hybrid_supported === false && <span className="chip">classical only</span>}
                  {p.pqc_probe_supported === false && <span className="chip">PQC test unavailable</span>}
                </div>
              </div>

              {p.error && (
                <div className="code" style={{ color: 'var(--crit)', marginBottom: 12 }}>{p.error}</div>
              )}

              <div className="grid g2" style={{ alignItems: 'start' }}>
                <dl className="kv">
                  <dt>negotiated</dt><dd>{p.negotiated_version ?? '—'}</dd>
                  <dt>cipher</dt><dd className="mono">{p.cipher ?? '—'}</dd>
                  <dt>kex group</dt><dd className="mono">{p.default_group ?? 'not observable'}</dd>
                  {p.pqc_group && <><dt>pqc group</dt><dd className="mono">{p.pqc_group}</dd></>}
                  <dt>accepts</dt>
                  <dd>
                    <div className="row wrap" style={{ gap: 4 }}>
                      {p.accepted_versions.length
                        ? p.accepted_versions.map(v => (
                            <span key={v} className={`chip ${v.startsWith('TLSv1.3') ? 'ok' : v === 'TLSv1.0' || v === 'TLSv1.1' ? 'warn' : ''}`}>
                              {v}
                            </span>))
                        : <span className="t4">—</span>}
                    </div>
                  </dd>
                  {p.rejected_versions.length > 0 && (
                    <>
                      <dt>rejects</dt>
                      <dd className="mono t4" style={{ fontSize: 11 }}>
                        {p.rejected_versions.join(', ')}
                      </dd>
                    </>
                  )}
                </dl>

                <dl className="kv">
                  {Object.entries(cert).length === 0
                    ? <><dt>certificate</dt><dd className="t4">not retrieved</dd></>
                    : Object.entries(cert).slice(0, 9).map(([k, v]) => (
                        <>
                          <dt key={k}>{k}</dt>
                          <dd key={k + 'v'} style={{ fontSize: 12 }}>
                            {typeof v === 'boolean' ? (v ? 'yes' : 'no') : String(v).slice(0, 90)}
                          </dd>
                        </>
                      ))}
                </dl>
              </div>

              {p.probe_notes && p.probe_notes.length > 0 && (
                <div className="t4" style={{ fontSize: 11, marginTop: 10 }}>
                  {p.probe_notes.join(' · ')}
                </div>
              )}

              {artifacts.length > 0 && (
                <div style={{ marginTop: 14 }}>
                  <div className="label" style={{ marginBottom: 7 }}>
                    Findings from this handshake
                  </div>
                  <table>
                    <thead>
                      <tr>
                        <th style={{ width: 58, textAlign: 'right' }}>Risk</th>
                        <th>Artefact</th><th>Impact</th><th style={{ width: 130 }}>Target</th>
                      </tr>
                    </thead>
                    <tbody>
                      {artifacts.map(a => (
                        <tr key={a.id}>
                          <td className="num" style={{
                            color: a.risk_score >= 8 ? 'var(--crit)'
                              : a.risk_score >= 5 ? 'var(--high)' : 'var(--t3)',
                          }}>{a.risk_score.toFixed(1)}</td>
                          <td>
                            {a.name}
                            <span className={`sev sev-${a.severity}`} style={{ marginLeft: 7 }}>
                              {a.severity}
                            </span>
                          </td>
                          <td className="mono t3" style={{ fontSize: 11 }}>{a.quantum_impact}</td>
                          <td className="mono" style={{ fontSize: 11, color: 'var(--t2)' }}>
                            {a.recommendation?.target ?? '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
