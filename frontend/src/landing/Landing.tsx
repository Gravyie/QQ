/** Quantum Atlas — Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
 *  Problem Statement 26164 · National Technical Research Organisation (NTRO)
 *  Theme: Cyber Security & Post-Quantum Cryptography
 */
import { useEffect, useRef, useState } from 'react'
import {
  ShieldCheck, ArrowRight, Code2, Box, Binary, Package, Radio
} from 'lucide-react'
import { api, fmt } from '../api'
import type { Artifact } from '../api'
import {
  PROOF, SCANNERS, SNAPSHOT, SNAPSHOT_FINDINGS, VIEWS,
  type Finding, type HeroStats,
} from './data'
import { QuantumCanvas } from '../components/QuantumCanvas'
import { GlitchText } from '../components/Motion'
import { Scanlines, GridPattern, ImageBackdrop } from '../components/CyberBackground'

const CONSOLE = '#/console'

const SCANNER_ICONS = [
  <Code2 key="src" size={18} className="text-accent" />,
  <ShieldCheck key="cert" size={18} className="text-safe" />,
  <Box key="box" size={18} className="text-high" />,
  <Binary key="bin" size={18} className="text-cyan" />,
  <Package key="pkg" size={18} className="text-accent" />,
  <Radio key="tls" size={18} className="text-crit" />,
]

function useReveal<T extends HTMLElement>() {
  const ref = useRef<T | null>(null)
  const [seen, setSeen] = useState(false)
  useEffect(() => {
    const el = ref.current
    if (!el || seen) return
    if (!('IntersectionObserver' in window)) { setSeen(true); return }
    const io = new IntersectionObserver(entries => {
      if (entries.some(e => e.isIntersecting)) { setSeen(true); io.disconnect() }
    }, { rootMargin: '-6% 0px -10% 0px' })
    io.observe(el)
    return () => io.disconnect()
  }, [seen])
  return { ref, seen }
}

function Section({
  children,
  id,
  className = '',
  backdrop,
}: {
  children: React.ReactNode
  id?: string
  className?: string
  backdrop?: React.ReactNode
}) {
  const { ref, seen } = useReveal<HTMLDivElement>()
  return (
    <section className={`lp-sec lp-rule ${className}`} id={id} style={{ position: 'relative', overflow: 'hidden' }}>
      {backdrop}
      <div className="lp-in lp-rev" data-in={seen} ref={ref}>{children}</div>
    </section>
  )
}

function useCountUp(target: number, run: boolean, ms = 950) {
  const [v, setV] = useState(0)
  useEffect(() => {
    if (!run) return
    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    if (reduced) { setV(target); return }
    let raf = 0
    const t0 = performance.now()
    const tick = (t: number) => {
      const p = Math.min(1, (t - t0) / ms)
      setV(target * (1 - Math.pow(1 - p, 3)))
      if (p < 1) raf = requestAnimationFrame(tick)
      else setV(target)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [target, run, ms])
  return v
}

const shortPath = (p: string, max = 46) => {
  const parts = p.split('/')
  const i = parts.findIndex(s => s === 'estate' || s === 'real')
  const rel = (i >= 0 ? parts.slice(i + 1) : parts.slice(-3)).join('/')
  if (rel.length <= max) return rel
  const seg = rel.split('/')
  const tail = seg.slice(-2).join('/')
  return `${seg[0]}/…/${tail.length > max - 4 ? tail.slice(-(max - 4)) : tail}`
}

function spread(rows: Artifact[], n: number): Artifact[] {
  const order: Artifact['severity'][] = ['critical', 'high', 'medium', 'low', 'info']
  const buckets = order.map(s => rows.filter(r => r.severity === s))
  const out: Artifact[] = []
  for (let i = 0; out.length < n; i++) {
    let progressed = false
    for (const b of buckets) {
      if (b[i]) { out.push(b[i]); progressed = true }
      if (out.length >= n) break
    }
    if (!progressed) break
  }
  return out
}

export function Landing() {
  const [stats, setStats] = useState<HeroStats>(SNAPSHOT)
  const [findings, setFindings] = useState<Finding[]>(SNAPSHOT_FINDINGS)
  const [algorithms, setAlgorithms] = useState(PROOF.algorithms)
  const [stuck, setStuck] = useState(false)

  useEffect(() => {
    const onScroll = () => setStuck(window.scrollY > 8)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  useEffect(() => {
    let dead = false
    ;(async () => {
      try {
        const [h, list] = await Promise.all([api.health(), api.scans()])
        if (dead) return
        setAlgorithms(h.algorithms)
        const row = list.scans[0]
        if (!row) return
        const d = await api.scan(row.scan_id)
        if (dead) return
        setStats({
          artifacts: d.summary.artifacts_found,
          files: d.summary.files_scanned,
          seconds: d.summary.duration_seconds,
          mosca: d.summary.mosca_violations,
          effortDays: d.summary.migration_effort_days,
          vulnerablePct: d.summary.quantum_vulnerable_pct,
          scanId: d.scan_id,
          org: d.config.organization,
          live: true,
        })
        const a = await api.artifacts(row.scan_id, { limit: '260' })
        if (dead || !a.artifacts.length) return
        setFindings(spread(a.artifacts, 12).map((x: Artifact) => ({
          name: x.name,
          path: shortPath(x.evidence.file_path),
          line: x.evidence.line ?? undefined,
          severity: x.severity,
          impact: x.quantum_impact,
        })))
      } catch {
        /* snapshot fallback */
      }
    })()
    return () => { dead = true }
  }, [])

  return (
    <div className="lp">
      <Nav stuck={stuck} />
      <Hero stats={stats} findings={findings} />
      <Stats stats={stats} algorithms={algorithms} />
      <Why />
      <Scanners />
      <Evidence />
      <Console />
      <Outputs />
      <Closing />
      <Foot />
    </div>
  )
}

function Nav({ stuck }: { stuck: boolean }) {
  return (
    <nav className="lp-nav" data-stuck={stuck}>
      <div className="lp-nav-left">
        <a className="lp-mark" href="#top">
          <Glyph />
          <b>Quantum Atlas</b>
          <span>ECDAT 26164</span>
        </a>
      </div>
      <div className="lp-navlinks">
        <a href="#problem">The Threat</a>
        <a href="#discovery">Discovery Engines</a>
        <a href="#evidence">Evidence Dossier</a>
        <a href="#console">Console Matrix</a>
        <a href="#outputs">CBOM & SARIF</a>
      </div>
      <div className="lp-nav-right">
        <a className="lp-cta" href={CONSOLE}>
          <span>Launch ECDAT Console</span>
          <ArrowRight size={14} />
        </a>
      </div>
    </nav>
  )
}

function Glyph() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <path d="M10 1.6 18 6v8l-8 4.4L2 14V6l8-4.4Z" stroke="var(--cyan)" strokeWidth="1.2" opacity="0.9" />
      <path d="M10 6.2 14 8.4v4.2L10 14.8 6 12.6V8.4l4-2.2Z" stroke="var(--accent)" strokeWidth="1" opacity="0.75" />
      <circle cx="10" cy="10.5" r="1.8" fill="var(--cyan)" />
    </svg>
  )
}

function Hero({ stats, findings }: { stats: HeroStats; findings: Finding[] }) {
  return (
    <header className="lp-hero" id="top">
      {/* Background Quantum lattice canvas */}
      <QuantumCanvas nodeCount={48} connectDistance={135} />

      {/* Cyber ambient artwork from user uploaded assets */}
      <ImageBackdrop
        src="/images/ascii-face-dark.jpg"
        opacity={0.35}
        position="right 3% center"
        size="contain"
      />
      <GridPattern opacity={0.035} />

      <div className="lp-hero-grid">
        <div>
          <div className="lp-eyebrow">
            <i />
            <span>NTRO · PS 26164 · ENTERPRISE CRYPTOGRAPHIC DISCOVERY</span>
          </div>

          <h1 className="lp-h1">
            <span>Every </span>
            <GlitchText text="cryptographic" />
            <br />
            <span>artefact you own.</span>
            <em>Ranked by when quantum breaks it.</em>
          </h1>

          <p className="lp-sub">
            Continuous deep-inspection across source repositories, container layers,
            binaries, certificates, and <b>live TLS endpoints</b>. Calculates exact
            <b> Mosca inequality margins</b> and generates actionable, costed
            <b> PQC migration roadmaps</b> exported in spec-compliant <b>CycloneDX 1.6 CBOM</b> and <b>SARIF</b>.
          </p>

          <div className="lp-actions">
            <a className="lp-cta lg" href={CONSOLE}>
              <span>Open Analyst Console</span>
              <ArrowRight size={15} />
            </a>
            <a className="lp-cta ghost lg" href="#problem">
              <span>Interactive Mosca Simulator ↓</span>
            </a>
          </div>

          <div className="lp-metastrip">
            <span>Deterministic Provenance (file:line)</span>
            <span>CycloneDX 1.6 CBOM + SARIF 2.1.0</span>
            <span>Mosca Dynamic Horizon Slider</span>
            <span>Agentless & Air-Gap Ready</span>
          </div>
        </div>

        <Stream stats={stats} findings={findings} />
      </div>
    </header>
  )
}

function Stream({ stats, findings }: { stats: HeroStats; findings: Finding[] }) {
  const [n, setN] = useState(0)

  useEffect(() => {
    setN(0)
    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    if (reduced || !findings.length) { setN(findings.length); return }
    const id = setInterval(() => {
      setN(v => (v >= findings.length ? v : v + 1))
    }, 180)
    return () => clearInterval(id)
  }, [findings])

  const shown = findings.slice(0, n)
  const done = n >= findings.length

  return (
    <div className="lp-term">
      <Scanlines />
      <div className="lp-term-bar">
        <div className="lp-dots"><i /><i /><i /></div>
        <span className="t mono">atlas scan estate/meridian --crqc 2033</span>
        <span className="grow" />
        <span className={`lp-live ${stats.live ? '' : 'off'}`}>
          <i />{stats.live ? 'LIVE API ENGINE' : 'SAMPLE REPLAY'}
        </span>
      </div>

      <div className="lp-term-body">
        <div className="cmd" style={{ marginBottom: 6 }}>
          <b>$</b> atlas scan corpus/estate --depth recursive
        </div>
        {shown.map((f, i) => (
          <div className="lp-line" key={`${f.path}-${i}`}>
            <span className="g">DETECT</span>
            <span className="n">{f.name}</span>
            <span className="p">{f.path}{f.line ? `:${f.line}` : ''}</span>
            <span className={`s sev-${f.severity}`}>{f.severity}</span>
          </div>
        ))}
        {done && (
          <div className="lp-line" style={{ marginTop: 8, borderTop: '1px dashed rgba(255,255,255,0.1)', paddingTop: 6 }}>
            <span className="g" style={{ color: 'var(--safe)' }}>DONE</span>
            <span className="n" style={{ color: 'var(--cyan)' }}>{fmt.n(stats.artifacts)} artefacts indexed</span>
            <span className="p">
              {fmt.n(stats.files)} files analyzed · {stats.seconds.toFixed(2)}s
            </span>
          </div>
        )}
      </div>

      <div className="lp-term-foot">
        <span style={{ color: 'var(--t2)' }}>{stats.org ?? 'Estate'}</span>
        <span>·</span>
        <span style={{ color: stats.mosca > 0 ? 'var(--crit)' : 'var(--safe)' }}>
          {fmt.n(stats.mosca)} Mosca Violations
        </span>
        <span>·</span>
        <span>{fmt.n(stats.effortDays)} Eng-Days</span>
        <span className="grow" />
        {stats.scanId && <span className="mono">ID: {stats.scanId.slice(0, 8)}</span>}
      </div>
    </div>
  )
}

function Stats({ stats, algorithms }: { stats: HeroStats; algorithms: number }) {
  const { ref, seen } = useReveal<HTMLDivElement>()
  const artifacts = useCountUp(stats.artifacts, seen)
  const real = useCountUp(PROOF.realRepoArtifacts, seen)

  const cells = [
    {
      v: fmt.n(Math.round(artifacts)),
      k: stats.live ? 'Artefacts Discovered' : 'Demo Estate Artefacts',
      d: `${stats.org ?? 'Enterprise'} — ${fmt.n(stats.files)} files processed in ${stats.seconds.toFixed(2)}s with exact line provenance`,
    },
    {
      v: fmt.n(Math.round(real)),
      k: 'Production Open-Source Audited',
      d: `paramiko, pyca/cryptography & pyjwt — ${fmt.n(PROOF.realRepoFiles)} files in ${PROOF.realRepoSeconds}s, ${fmt.n(PROOF.realRepoMosca)} Mosca breaches`,
    },
    {
      v: String(algorithms),
      k: 'Classified Algorithms',
      d: 'Comprehensive knowledge base: NIST status, Shor/Grover risk, OIDs, and wire/CPU costs',
    },
    {
      v: PROOF.probeGroup,
      k: 'Wire Handshake Probed',
      d: `${PROOF.probeHost} negotiates hybrid PQC key exchange over ${PROOF.probeVersion} with ${PROOF.probeCertAlgo}`,
      mono: true,
    },
  ]

  return (
    <div className="lp-stats lp-rev" data-in={seen} ref={ref}>
      {cells.map(c => (
        <div className="lp-stat" key={c.k}>
          <div className="v" style={c.mono ? { fontFamily: 'var(--mono)', fontSize: 18, letterSpacing: 0, color: 'var(--cyan)' } : undefined}>
            {c.v}
          </div>
          <div className="k">{c.k}</div>
          <div className="d">{c.d}</div>
        </div>
      ))}
    </div>
  )
}

function Why() {
  return (
    <Section
      id="problem"
      backdrop={
        <ImageBackdrop
          src="/images/mandelbrot-sphere.jpg"
          opacity={0.07}
          position="center right"
          size="contain"
        />
      }
    >
      <div className="lp-sechead">
        <div>
          <div className="lp-eyebrow"><i />HNDL THREAT HORIZON</div>
          <h2 className="lp-h2">Data recorded today is decrypted in 2033.</h2>
        </div>
        <p className="lp-lede">
          <b>Harvest Now, Decrypt Later (HNDL)</b> does not require a quantum computer to exist today.
          Adversaries record encrypted traffic now and decrypt it the moment a Cryptographically
          Relevant Quantum Computer (CRQC) becomes operational.
        </p>
      </div>

      <div className="lp-hndl" style={{ marginTop: 42 }}>
        <InteractiveHndl />
        <div>
          <h3 style={{ fontSize: 18, fontWeight: 500, letterSpacing: '-0.3px', margin: 0, color: 'var(--t1)' }}>
            Mosca's Inequality is the Deterministic Risk Metric
          </h3>
          <p className="lp-lede" style={{ fontSize: 14.5, marginTop: 12 }}>
            If data shelf-life <b>X</b> plus enterprise migration duration <b>Y</b> exceeds
            the years left before CRQC arrival <b>Z</b>, your cryptographic data is already compromised.
          </p>
          <p className="lp-lede" style={{ fontSize: 14.5, marginTop: 12 }}>
            Because the exact arrival year of CRQC is an industry estimate, Quantum Atlas treats
            <b> Z as a real-time slider control</b>, instantly recalculating vulnerability across the
            entire estate in milliseconds without requiring rescans.
          </p>

          <div className="lp-eq">
            <span className="term"><b>X</b><u>shelf-life</u></span>
            <span className="op">+</span>
            <span className="term"><b>Y</b><u>migration</u></span>
            <span className="op">&gt;</span>
            <span className="term"><b>Z</b><u>years to CRQC</u></span>
            <span className="verdict chip warn">IMMEDIATE EXPOSURE</span>
          </div>
        </div>
      </div>
    </Section>
  )
}

function InteractiveHndl() {
  const START = 2026
  const END = 2056
  const span = END - START
  const at = (y: number) => Math.max(0, Math.min(100, ((y - START) / span) * 100))

  const [crqcYear, setCrqcYear] = useState(2033)
  const SHELF_LIFE = 25
  const MIGRATION_YEARS = 1.5
  const SHELF_END = START + SHELF_LIFE
  const exposed = crqcYear < SHELF_END
  const exposureYears = Math.max(0, SHELF_END - crqcYear)
  const margin = (crqcYear - START) - (SHELF_LIFE + MIGRATION_YEARS)

  const nodes = [
    { y: START, label: 'Recorded 2026', color: 'var(--accent)', top: 'Recorded' },
    { y: crqcYear, label: `CRQC ${crqcYear}`, color: 'var(--crit)', top: 'Decrypted' },
    { y: SHELF_END, label: `Year ${SHELF_END}`, color: 'var(--t3)', top: 'Sensitive Until' },
  ]

  return (
    <div className="lp-tl">
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
        <div className="label">treasury-archive/src/archive.py:15 · X25519 (25-yr shelf-life)</div>
        <span className="chip warn">Mosca Margin: {margin.toFixed(1)}y</span>
      </div>

      <div className="lp-tl-track">
        <div className="lp-tl-axis" />
        {exposed && (
          <div
            className="lp-tl-fill"
            style={{
              left: `${at(crqcYear)}%`,
              width: `${Math.max(2, at(SHELF_END) - at(crqcYear))}%`,
            }}
          />
        )}
        {nodes.map(n => (
          <div className="lp-tl-node" key={n.y} style={{ left: `${at(n.y)}%` }}>
            <b style={{ color: n.color }}>{n.top}</b>
            <i style={{ background: n.color }} />
            <span>{n.label}</span>
          </div>
        ))}
      </div>

      <div style={{ marginTop: 22, paddingTop: 14, borderTop: '1px solid var(--line)' }}>
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 6 }}>
          <span className="label">Interactive Quantum Arrival Horizon (CRQC):</span>
          <span className="mono" style={{ color: 'var(--cyan)', fontWeight: 600 }}>Year {crqcYear}</span>
        </div>
        <input
          type="range"
          min={2029}
          max={2040}
          step={1}
          value={crqcYear}
          onChange={e => setCrqcYear(Number(e.target.value))}
          className="slider"
        />
      </div>

      <div className="t3" style={{ fontSize: 12.5, marginTop: 14, lineHeight: 1.55 }}>
        At CRQC {crqcYear}, the statutory data is exposed for{' '}
        <b style={{ color: 'var(--crit)', fontWeight: 500 }}>{exposureYears} years</b> before confidentiality expires.
        Atlas scores this finding at <span className="mono">9.9 Critical</span> and generates a 2-step patch to ML-KEM.
      </div>
    </div>
  )
}

function Scanners() {
  return (
    <Section
      id="discovery"
      backdrop={
        <ImageBackdrop
          src="/images/ascii-eye.jpg"
          opacity={0.06}
          position="right 5% top"
          size="contain"
        />
      }
    >
      <div className="lp-sechead">
        <div>
          <div className="lp-eyebrow"><i />DISCOVERY SURFACES</div>
          <h2 className="lp-h2">Six inspection engines. One unified inventory.</h2>
        </div>
        <p className="lp-lede">
          Cryptography hides across compiled binaries, container layers, static configs,
          and network handshakes. Atlas extracts every cryptographic primitive into the standard CBOM schema.
        </p>
      </div>

      <div className="lp-cards" style={{ marginTop: 38 }}>
        {SCANNERS.map((s, idx) => (
          <div className="lp-card" key={s.ix}>
            <h4>
              <span className="ix">{s.ix}</span>
              {SCANNER_ICONS[idx]}
              <span>{s.title}</span>
            </h4>
            <p>{s.body}</p>
            <ul>{s.tags.map(t => <li key={t}>{t}</li>)}</ul>
          </div>
        ))}
      </div>
    </Section>
  )
}

function Evidence() {
  return (
    <Section
      id="evidence"
      backdrop={
        <ImageBackdrop
          src="/images/glitch-hands.jpg"
          opacity={0.14}
          position="center"
          size="cover"
        />
      }
    >
      <div className="lp-sechead">
        <div>
          <div className="lp-eyebrow"><i />PROVENANCE & AUDIT</div>
          <h2 className="lp-h2">Every finding backed by verifiable evidence.</h2>
        </div>
        <p className="lp-lede">
          No vague alerts. Each discovered artefact is mapped to exact line numbers, source snippets,
          container layer SHA256 hashes, or TLS wire handshakes.
        </p>
      </div>

      <div className="lp-ev" style={{ marginTop: 38 }}>
        <div className="lp-code">
          <div className="lp-code-head">
            <span className="mono">treasury-archive/src/archive.py</span>
            <span className="mono text-cyan">PYTHON · LINE 15</span>
          </div>
          <pre>{`  12  `}<span className="c">{`# 25-year statutory retention`}</span>{`
  13  `}<span className="k">def</span>{` `}<span className="n">seal_record</span>{`(payload: bytes):
  14      `}<span className="c">{`# ephemeral key per record`}</span>{`
`}<span className="hl">{`  15      private = x25519.X25519PrivateKey.generate()`}</span>{`
  16      shared  = private.exchange(peer_public)
  17      `}<span className="k">return</span>{` AESGCM(shared[:32]).encrypt(...)`}</pre>
        </div>

        <div className="panel glow-crit" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="lp-code-head" style={{ borderRadius: 0, borderBottom: '1px solid rgba(255,77,77,0.2)' }}>
            <span className="mono" style={{ color: 'var(--t1)' }}>Cryptographic Audit Record</span>
            <span className="sev sev-critical">CRITICAL · RISK 9.9</span>
          </div>
          <table className="lp-table">
            <tbody>
              <tr><td>Quantum Impact</td><td className="q"><b>Shor-broken</b> — Elliptic Curve DH, 0 bits quantum security</td></tr>
              <tr><td>Data Shelf-Life</td><td className="q">25 years (inferred from archive/ retention context)</td></tr>
              <tr><td>Mosca Margin</td><td className="q"><span className="mono" style={{ color: 'var(--crit)' }}>−18.67y</span> (HNDL breach)</td></tr>
              <tr><td>Target Replacement</td><td className="q"><span className="mono" style={{ color: 'var(--safe)' }}>ML-KEM-768</span> or <span className="mono">X25519MLKEM768</span> Hybrid</td></tr>
              <tr><td>Overhead Impact</td><td className="q">+2,240 bytes wire delta · 2 extra TCP MSS frames</td></tr>
              <tr><td>Migration Effort</td><td className="q">3 Engineer-Days · Wave 4 Priority</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </Section>
  )
}

function Console() {
  return (
    <Section id="console">
      <div className="lp-sechead">
        <div>
          <div className="lp-eyebrow"><i />ANALYST CONSOLE MATRIX</div>
          <h2 className="lp-h2">Ten specialised views. Complete lifecycle control.</h2>
        </div>
        <p className="lp-lede">
          From estate-wide discovery to per-algorithm wire analysis and live TLS wire probing,
          every view delivers answers for security architects and leadership.
        </p>
      </div>

      <div className="panel" style={{ marginTop: 36, padding: '20px 10px 10px', overflowX: 'auto' }}>
        <table className="lp-table">
          <thead>
            <tr>
              <th style={{ width: 160 }}>Console View</th>
              <th style={{ width: 290 }}>Analytical Question</th>
              <th>System Capability</th>
            </tr>
          </thead>
          <tbody>
            {VIEWS.map(([name, q, body]) => (
              <tr key={name}>
                <td>
                  <span className="mono" style={{ color: 'var(--t1)', fontWeight: 500 }}>
                    {name}
                  </span>
                </td>
                <td className="q" style={{ color: 'var(--accent)' }}>{q}</td>
                <td>{body}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  )
}

function Outputs() {
  const rows = [
    ['CycloneDX 1.6 CBOM', 'results/<id>.cbom.json',
     'Standardised Cryptographic Bill of Materials with cryptoProperties, OIDs, and provenance.'],
    ['SARIF 2.1.0', 'results/<id>.sarif.json',
     'CI/CD code scanning integration natively ingested by GitHub, GitLab, and enterprise IDEs.'],
    ['Executive Markdown', 'results/<id>.report.md',
     'Full stakeholder report detailing posture, Mosca inequality deadlines, and phased wave timelines.'],
    ['Raw JSON Graph', 'results/<id>.json',
     'Complete artefact set enabling real-time re-simulation without rescanning.'],
  ]

  return (
    <Section id="outputs">
      <div className="lp-sechead">
        <div>
          <div className="lp-eyebrow"><i />STANDARDISED DELIVERABLES</div>
          <h2 className="lp-h2">Machine-readable CBOMs and CI pipeline gating.</h2>
        </div>
        <p className="lp-lede">
          Integrates directly into DevSecOps pipelines with native CI failure gates that block
          pull requests introducing Shor-broken cryptography.
        </p>
      </div>

      <div className="panel" style={{ marginTop: 36, padding: '20px 10px 10px', overflowX: 'auto' }}>
        <table className="lp-table">
          <thead>
            <tr><th style={{ width: 210 }}>Output Format</th><th style={{ width: 230 }}>Filesystem Path</th><th>Purpose</th></tr>
          </thead>
          <tbody>
            {rows.map(([f, p, d]) => (
              <tr key={f}>
                <td style={{ color: 'var(--t1)', fontWeight: 500 }}>{f}</td>
                <td className="mono text-cyan" style={{ fontSize: 11.5 }}>{p}</td>
                <td>{d}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="lp-code" style={{ marginTop: 18 }}>
        <div className="lp-code-head">
          <span className="mono">DevSecOps Pipeline Quality Gate</span>
          <span className="mono" style={{ color: 'var(--crit)' }}>NON-ZERO EXIT GATE</span>
        </div>
        <pre>{`$ atlas ci corpus/estate `}<span className="k">--fail-on</span>{` high `}<span className="k">--max-mosca</span>{` 0

  `}<span className="r">FAIL</span>{`  50 findings at or above high · 10 past the Mosca deadline
        Generated results/<id>.cbom.json (CycloneDX 1.6)
        Generated results/<id>.sarif.json (SARIF 2.1.0)
  `}<span className="c">{`# Exit 1 — Pull Request blocked by Quantum Quality Gate`}</span></pre>
      </div>
    </Section>
  )
}

function Closing() {
  const cmds = [
    'atlas scan corpus/estate',
    'atlas probe cloudflare.com',
    'atlas simulate <id> --crqc 2030',
    'atlas plan <id>',
    'atlas export <id> cbom',
  ]

  return (
    <section className="lp-sec">
      <div className="lp-in">
        <div className="lp-close">
          <ImageBackdrop
            src="/images/matrix-eye.jpg"
            opacity={0.08}
            position="center right"
            size="contain"
          />
          <div style={{ position: 'relative', zIndex: 2 }}>
            <h2 className="lp-h2" style={{ maxWidth: '24ch' }}>
              Transition to Post-Quantum Cryptography starts with Discovery.
            </h2>
            <p className="lp-lede" style={{ marginTop: 16, maxWidth: '54ch' }}>
              Run full discovery on your source code, container images, or remote endpoints now.
              The console opens automatically on the latest scan.
            </p>
            <div className="lp-actions">
              <a className="lp-cta lg" href={CONSOLE}>
                <span>Launch ECDAT Console →</span>
              </a>
              <a className="lp-cta ghost lg" href="#top">
                <span>Back to Top ↑</span>
              </a>
            </div>
          </div>
          <div className="lp-code" style={{ minWidth: 320, flex: '1 1 320px', position: 'relative', zIndex: 2 }}>
            <div className="lp-code-head"><span>CLI Workflows</span><span>Ready</span></div>
            <pre>{cmds.map(c => `$ ${c}`).join('\n')}</pre>
          </div>
        </div>
      </div>
    </section>
  )
}

function Foot() {
  return (
    <footer className="lp-foot">
      <span>Quantum Atlas · ECDAT · Problem Statement 26164 · National Technical Research Organisation (NTRO)</span>
      <span className="row" style={{ gap: 18 }}>
        <a href={CONSOLE}>Console</a>
        <a href="#problem">Threat Model</a>
        <a href="#discovery">Scanners</a>
        <a href="#outputs">CycloneDX CBOM</a>
      </span>
    </footer>
  )
}
