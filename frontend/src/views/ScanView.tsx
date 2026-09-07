/** Scan view: pick targets, run discovery, watch it stream.
 *
 * The live log is not decoration. Cryptographic discovery is the part reviewers
 * distrust most ("did it really read my repo?"), so the console shows each
 * artefact arriving with its file path as the walk proceeds.
 */
import { useEffect, useRef, useState } from 'react'
import { api, fmt } from '../api'
import type { Artifact, CorpusNode, ScanRow } from '../api'
import { StackBar } from '../components/Charts'

interface LogLine { level: string; message: string; ts: string }

export function ScanView({ onDone, onOpen }: {
  onDone: (id: string) => void
  onOpen: (id: string) => void
}) {
  const [corpus, setCorpus] = useState<CorpusNode[]>([])
  const [root, setRoot] = useState('')
  const [picked, setPicked] = useState<string[]>([])
  const [custom, setCustom] = useState('')
  const [endpoints, setEndpoints] = useState('')
  const [org, setOrg] = useState('Meridian Financial Services')
  const [crqc, setCrqc] = useState(2033)
  const [running, setRunning] = useState(false)
  const [job, setJob] = useState<string | null>(null)
  const [log, setLog] = useState<LogLine[]>([])
  const [found, setFound] = useState<Artifact[]>([])
  const [scans, setScans] = useState<ScanRow[]>([])
  const [failed, setFailed] = useState<string | null>(null)
  const es = useRef<EventSource | null>(null)
  const logEnd = useRef<HTMLDivElement | null>(null)

  const refresh = () => api.scans().then(r => setScans(r.scans)).catch(() => {})

  useEffect(() => {
    api.corpus().then(r => {
      setCorpus(r.targets)
      setRoot(r.root)
      const estate = r.targets.find(t => t.name === 'estate')
      if (estate) setPicked([estate.path])
    }).catch(() => {})
    refresh()
    return () => es.current?.close()
  }, [])

  useEffect(() => { logEnd.current?.scrollIntoView({ block: 'end' }) }, [log, found.length])

  const toggle = (p: string) =>
    setPicked(s => (s.includes(p) ? s.filter(x => x !== p) : [...s, p]))

  async function start() {
    const targets = [...picked, ...custom.split(',').map(s => s.trim()).filter(Boolean)]
      .map(p => ({ path: p, kind: 'source' }))
    if (!targets.length) return
    setLog([]); setFound([]); setRunning(true); setFailed(null)

    const eps = endpoints.split(',').map(s => s.trim()).filter(Boolean)
    let job_id: string, stream: string
    try {
      ({ job_id, stream } = await api.startScan({
        targets, crqc_year: crqc, organization: org, endpoints: eps,
      }))
    } catch (e) {
      // A rejected scan (bad path, unreachable API) must say so in the console
      // rather than leaving a spinner running forever.
      setFailed(e instanceof Error ? e.message : 'could not start the scan')
      setRunning(false)
      return
    }
    setJob(job_id)

    const src = new EventSource(stream)
    es.current = src
    // The server closes the stream after `done`. EventSource treats any close as
    // an error and retries, so completion is tracked explicitly and the socket
    // is shut down from this side before that can fire.
    let finished = false
    const finish = (id?: string) => {
      if (finished) return
      finished = true
      setRunning(false)
      src.close()
      es.current = null
      refresh()
      if (id) onDone(id)
    }

    src.onmessage = ev => {
      const m = JSON.parse(ev.data)
      if (m.type === 'log') setLog(l => [...l.slice(-260), m])
      else if (m.type === 'artifact') setFound(f => (f.length > 700 ? f : [...f, m.artifact]))
      else if (m.type === 'complete' || m.type === 'done') finish(m.scan_id)
      else if (m.type === 'error' || m.type === 'cancelled') {
        const msg = m.message ?? 'scan cancelled'
        setLog(l => [...l, { level: 'error', message: msg, ts: '' }])
        if (m.type === 'error') setFailed(msg)
        finish()
      }
    }
    src.onerror = () => {
      // Only a genuine transport failure: a close after `done` is handled above.
      if (finished) return
      setFailed('lost the event stream before the scan reported completion')
      finish()
    }
  }

  async function stop() {
    if (job) await api.cancel(job).catch(() => {})
    es.current?.close(); es.current = null; setRunning(false)
  }

  const sevCounts = (['critical', 'high', 'medium', 'low', 'info'] as const)
    .map(s => [s, found.filter(a => a.severity === s).length] as [string, number])

  return (
    <div className="page">
      <div className="head">
        <div>
          <h1>Cryptographic discovery</h1>
          <p>
            Point Atlas at source trees, certificate stores, container images, binaries or
            live TLS endpoints. Every finding carries the file and line it came from.
          </p>
        </div>
        <div className="row">
          {running
            ? <button className="danger" onClick={stop}>Cancel scan</button>
            : <button className="primary" onClick={start} disabled={!picked.length && !custom}>
                Run discovery
              </button>}
        </div>
      </div>

      <div className="grid g2" style={{ alignItems: 'start' }}>
        <div className="panel" style={{ padding: 15 }}>
          <div className="label" style={{ marginBottom: 9 }}>Targets</div>
          <div className="mono t4" style={{ marginBottom: 10, fontSize: 10.5 }}>{root}</div>
          <div className="col" style={{ gap: 12 }}>
            {corpus.map(t => (
              <div key={t.path}>
                <span className={`chip click ${picked.includes(t.path) ? 'on' : ''}`}
                      onClick={() => toggle(t.path)}>
                  {t.name}
                </span>
                {t.children && (
                  <div className="row wrap" style={{ gap: 4, marginTop: 6, paddingLeft: 10 }}>
                    {t.children.map(c => (
                      <span key={c.path}
                            className={`chip click ${picked.includes(c.path) ? 'on' : ''}`}
                            onClick={() => toggle(c.path)}>
                        {c.name}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="col" style={{ gap: 9, marginTop: 16 }}>
            <label className="col" style={{ gap: 4 }}>
              <span className="label">Additional paths (comma separated)</span>
              <input value={custom} onChange={e => setCustom(e.target.value)}
                     placeholder="/path/to/repo, /path/to/certs" />
            </label>
            <label className="col" style={{ gap: 4 }}>
              <span className="label">Live TLS endpoints (optional)</span>
              <input value={endpoints} onChange={e => setEndpoints(e.target.value)}
                     placeholder="cloudflare.com, api.example.com:8443" />
            </label>
            <div className="row" style={{ gap: 10 }}>
              <label className="col grow" style={{ gap: 4 }}>
                <span className="label">Organisation</span>
                <input value={org} onChange={e => setOrg(e.target.value)} />
              </label>
              <label className="col" style={{ gap: 4, width: 120 }}>
                <span className="label">CRQC year</span>
                <input type="number" min={2027} max={2060} value={crqc}
                       onChange={e => setCrqc(+e.target.value)} />
              </label>
            </div>
          </div>
        </div>

        <div className="panel" style={{ padding: 15 }}>
          <div className="row" style={{ justifyContent: 'space-between', marginBottom: 9 }}>
            <div className="label">Live discovery</div>
            <div className="row" style={{ gap: 8 }}>
              {running && <div className="spin" />}
              <span className="mono t3">{fmt.n(found.length)} artefacts</span>
            </div>
          </div>

          {found.length > 0 && (
            <div style={{ marginBottom: 10 }}>
              <StackBar data={sevCounts} total={found.length} />
            </div>
          )}

          {failed && (
            <div style={{
              marginBottom: 10, padding: '9px 11px', borderRadius: 6,
              border: '1px solid rgba(229,85,79,0.35)', background: 'rgba(229,85,79,0.06)',
              fontSize: 12.5, color: 'var(--crit)',
            }}>
              Scan failed — {failed}
            </div>
          )}

          <div className="console">
            {log.length === 0 && found.length === 0 && (
              <div className="t4">Idle. Select targets and run discovery.</div>
            )}
            {log.map((l, i) => (
              <div key={`l${i}`}>
                <span className="ts">{l.ts ? l.ts.slice(11, 19) : '        '} </span>
                <span className={l.level === 'error' ? 'err' : l.level === 'warn' ? 'warn' : 'info'}>
                  {l.message}
                </span>
              </div>
            ))}
            {found.slice(-90).map((a, i) => (
              <div key={`a${i}`}>
                <span className="ts">found </span>
                <span style={{ color: 'var(--t2)' }}>{a.name}</span>
                <span className="ts"> {fmt.file(a.evidence.file_path)}</span>
                {a.evidence.line ? <span className="ts">:{a.evidence.line}</span> : null}
              </div>
            ))}
            <div ref={logEnd} />
          </div>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 12, overflow: 'hidden' }}>
        <div className="row" style={{ justifyContent: 'space-between', padding: '12px 15px' }}>
          <div className="label">Scan history</div>
          <span className="mono t4">{scans.length} stored</span>
        </div>
        {scans.length === 0
          ? <div className="empty">No scans yet.</div>
          : <div style={{ maxHeight: 300, overflowY: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>Scan</th><th>Organisation</th><th>Targets</th>
                    <th style={{ textAlign: 'right' }}>Artefacts</th>
                    <th style={{ textAlign: 'right' }}>Vulnerable</th>
                    <th style={{ textAlign: 'right' }}>Mosca</th>
                    <th>Started</th><th />
                  </tr>
                </thead>
                <tbody>
                  {scans.map(s => (
                    <tr key={s.scan_id}>
                      <td className="mono" style={{ cursor: 'pointer' }} onClick={() => onOpen(s.scan_id)}>
                        {s.scan_id.slice(0, 8)}
                      </td>
                      <td>{s.organization}</td>
                      <td className="path" style={{ maxWidth: 260 }}>
                        {s.targets.map(t => fmt.file(t)).join(', ')}
                      </td>
                      <td className="num">{fmt.n(s.artifacts)}</td>
                      <td className="num">{fmt.pct(s.quantum_vulnerable_pct)}</td>
                      <td className="num" style={{ color: s.mosca_violations ? 'var(--crit)' : 'var(--t3)' }}>
                        {fmt.n(s.mosca_violations)}
                      </td>
                      <td className="mono t4">{fmt.time(s.started_at)}</td>
                      <td style={{ textAlign: 'right' }}>
                        <div className="row" style={{ gap: 5, justifyContent: 'flex-end' }}>
                          <button onClick={() => onOpen(s.scan_id)}>Open</button>
                          <button className="danger"
                                  onClick={() => api.del(s.scan_id).then(refresh)}>Delete</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>}
      </div>
    </div>
  )
}
