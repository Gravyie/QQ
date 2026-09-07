/** Knowledge base browser + resolver.
 *
 * The resolver is worth exposing because it is the honest part: paste any cipher
 * suite string from an nginx config or an sshd banner and see exactly what Atlas
 * thinks it is, or see it admit the string is unrecognised.
 */
import { useEffect, useState } from 'react'
import { api, IMPACT_LABEL, fmt } from '../api'

type Entry = {
  name: string; impact: string; family: string; primitive: string
  classical_bits: number; pq_bits: number; nist_pq_level: number
  nist_status: string; note?: string; oid?: string
  bits_basis?: string
  matched_aliases?: string[]
  matched_because?: string
}

type Component = {
  role: string; name: string; impact: string; primitive: string
  classical_bits: number; pq_bits: number; nist_status: string
  note?: string; weakest: boolean
}

export function Knowledge() {
  const [q, setQ] = useState('')
  const [rows, setRows] = useState<Entry[]>([])
  const [stats, setStats] = useState<{ algorithms: number; aliases: number; by_impact: Record<string, number> } | null>(null)
  const [probe, setProbe] = useState('TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA')
  const [res, setRes] = useState<{
    canonical: string; recognised: boolean; entry: Record<string, unknown> | null
    components?: Component[]
  } | null>(null)

  useEffect(() => {
    const t = setTimeout(() => {
      api.kb(q || undefined).then(r => { setRows(r.algorithms as Entry[]); setStats(r.stats) })
    }, 150)
    return () => clearTimeout(t)
  }, [q])

  useEffect(() => {
    const t = setTimeout(() => {
      if (probe.trim()) api.resolve(probe.trim()).then(setRes).catch(() => setRes(null))
    }, 200)
    return () => clearTimeout(t)
  }, [probe])

  return (
    <div className="page">
      <div className="head">
        <div>
          <h1>Knowledge base</h1>
          <p>
            {stats?.algorithms ?? '—'} algorithms and {stats?.aliases ?? '—'} aliases with NIST
            status, classical and post-quantum strength, and OIDs. This table is the source of
            every impact classification Atlas makes.
          </p>
        </div>
      </div>

      <div className="panel" style={{ padding: 15, marginBottom: 12 }}>
        <div className="label" style={{ marginBottom: 9 }}>Resolver — paste any real config string</div>
        <input className="grow" style={{ width: '100%' }} value={probe}
               onChange={e => setProbe(e.target.value)}
               placeholder="ECDHE-RSA-AES256-GCM-SHA384 · sntrup761x25519-sha512@openssh.com · sha256WithRSAEncryption" />
        {res && (
          <div className="row wrap" style={{ gap: 8, marginTop: 11 }}>
            {res.recognised ? (
              <>
                <span className="chip on">{res.canonical}</span>
                <span className="chip">{IMPACT_LABEL[String(res.entry?.impact)] ?? String(res.entry?.impact)}</span>
                <span className="chip">{String(res.entry?.primitive)}</span>
                <span className="chip">{String(res.entry?.classical_bits)} classical bits</span>
                <span className="chip">{String(res.entry?.pq_bits)} pq bits</span>
                <span className="chip">{String(res.entry?.nist_status)}</span>
                {res.entry?.oid ? <span className="chip">OID {String(res.entry.oid)}</span> : null}
              </>
            ) : (
              <span className="chip warn">unrecognised — Atlas reports it as unclassified rather than guessing</span>
            )}
          </div>
        )}
        {res?.recognised && Boolean(res.entry?.note) && (
          <div className="t3" style={{ fontSize: 12.5, marginTop: 9 }}>{String(res.entry?.note)}</div>
        )}

        {/* A cipher suite is several decisions at once. The risk score keys off
            the weakest one, but hiding the others would look like the matcher
            missed them, so every component is listed with its role. */}
        {res?.components && res.components.length > 1 && (
          <div style={{ marginTop: 14 }}>
            <div className="label" style={{ marginBottom: 8 }}>
              Full decomposition — {res.components.length} components, scored on the weakest
            </div>
            <table>
              <thead>
                <tr>
                  <th style={{ width: 120 }}>Role</th><th>Component</th><th>Impact</th>
                  <th className="num" style={{ textAlign: 'right', width: 76 }}>Classical</th>
                  <th className="num" style={{ textAlign: 'right', width: 76 }}>Post-quantum</th>
                  <th style={{ width: 118 }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {res.components.map(c => (
                  <tr key={c.role + c.name}>
                    <td className="mono t4" style={{ fontSize: 10.5, letterSpacing: 0.3 }}>
                      {c.role.toUpperCase()}
                    </td>
                    <td>
                      <span style={{ color: 'var(--t1)' }}>{c.name}</span>
                      {c.weakest && (
                        <span className="chip" style={{
                          marginLeft: 7, color: 'var(--crit)', borderColor: 'rgba(229,85,79,0.3)',
                        }}>scored</span>
                      )}
                      {c.note && (
                        <div className="t4" style={{ fontSize: 11, marginTop: 2, maxWidth: '70ch' }}>
                          {c.note}
                        </div>
                      )}
                    </td>
                    <td className="mono" style={{
                      fontSize: 11,
                      color: c.impact === 'broken_classically' ? 'var(--crit)'
                        : c.impact === 'shor_broken' ? 'var(--high)'
                        : c.impact === 'grover' ? 'var(--med)'
                        : c.impact === 'pq_safe' ? 'var(--safe)' : 'var(--t3)',
                    }}>{IMPACT_LABEL[c.impact] ?? c.impact}</td>
                    <td className="num">{c.classical_bits}</td>
                    <td className="num" style={{ color: c.pq_bits === 0 ? 'var(--crit)' : 'var(--t2)' }}>
                      {c.pq_bits}
                    </td>
                    <td className="mono t3" style={{ fontSize: 11 }}>{c.nist_status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel" style={{ overflow: 'hidden' }}>
        <div className="row" style={{ padding: '13px 15px', gap: 10 }}>
          <input className="grow" value={q} onChange={e => setQ(e.target.value)}
                 placeholder="Filter by name, alias, primitive or NIST status — try “kyber” or “disallowed”" />
          <span className="mono t4">{fmt.n(rows.length)} shown</span>
        </div>
        <div style={{ maxHeight: '62vh', overflowY: 'auto' }}>
          <table>
            <thead>
              <tr>
                <th>Algorithm</th><th>Impact</th><th>Primitive</th>
                <th style={{ textAlign: 'right' }}>Classical</th>
                <th style={{ textAlign: 'right' }}>Post-quantum</th>
                <th style={{ textAlign: 'right' }}>NIST level</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(e => (
                <tr key={e.name}>
                  <td>
                    <div style={{ color: 'var(--t1)' }}>{e.name}</div>
                    {e.matched_aliases && (
                      <div className="mono t4" style={{ fontSize: 10, marginTop: 2 }}>
                        alias: {e.matched_aliases.slice(0, 3).join(' · ')}
                      </div>
                    )}
                    {e.matched_because && (
                      <div className="mono" style={{ fontSize: 10, marginTop: 2, color: 'var(--safe)' }}>
                        ↳ {e.matched_because}
                      </div>
                    )}
                    {e.note && <div className="t4" style={{ fontSize: 11 }}>{e.note}</div>}
                  </td>
                  <td className="mono" style={{
                    fontSize: 11,
                    color: e.impact === 'broken_classically' ? 'var(--crit)'
                      : e.impact === 'shor_broken' ? 'var(--high)'
                      : e.impact === 'pq_safe' ? 'var(--safe)' : 'var(--t3)',
                  }}>{IMPACT_LABEL[e.impact] ?? e.impact}</td>
                  <td className="mono t3" style={{ fontSize: 11 }}>{e.primitive}</td>
                  <td className="num" title={e.bits_basis ? `measured at ${e.bits_basis}` : undefined}>
                    {e.classical_bits}
                    {e.bits_basis && (
                      <div className="t4" style={{ fontSize: 9.5, fontWeight: 400 }}>
                        {e.bits_basis}
                      </div>
                    )}
                  </td>
                  <td className="num" style={{ color: e.pq_bits === 0 ? 'var(--crit)' : 'var(--t2)' }}>
                    {e.pq_bits}
                  </td>
                  <td className="num" title="NIST PQC category. Blank for algorithms that are not PQC.">
                    {e.nist_pq_level || <span className="t4">n/a</span>}
                  </td>
                  <td className="mono t3" style={{ fontSize: 11 }}>{e.nist_status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
