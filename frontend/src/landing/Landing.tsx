/** Landing page.
 *
 *  Purpose: a reviewer who has never seen this tool should understand, in under
 *  a minute, what the problem is, why it is hard, and what Atlas actually does
 *  about it — and every number they read should be one they can reproduce.
 *
 *  So the page reads the live API. The hero stream replays real artefacts from
 *  the most recent stored scan, with their real file paths and line numbers. The
 *  stat strip is that scan's real summary. When the API is unreachable the page
 *  falls back to a stored snapshot and says so in the label rather than
 *  pretending the numbers are live.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import { api, fmt } from '../api'
import type { Artifact } from '../api'
import {
  PROOF, SCANNERS, SNAPSHOT, SNAPSHOT_FINDINGS, VIEWS,
  type Finding, type HeroStats,
} from './data'

const CONSOLE = '#/console'

/* ------------------------------------------------------------------ helpers */

/** Fade a section in the first time it enters the viewport. One observer per
 *  element, disconnected after firing, so scrolling stays cheap. */
function useReveal<T extends HTMLElement>() {
  const ref = useRef<T | null>(null)
  const [seen, setSeen] = useState(false)
  useEffect(() => {
    const el = ref.current
    if (!el || seen) return
    if (!('IntersectionObserver' in window)) { setSeen(true); return }
    const io = new IntersectionObserver(entries => {
      if (entries.some(e => e.isIntersecting)) { setSeen(true); io.disconnect() }
    }, { rootMargin: '-8% 0px -12% 0px' })
    io.observe(el)
    return () => io.disconnect()
  }, [seen])
  return { ref, seen }
}

function Section({ children, id }: { children: React.ReactNode; id?: string }) {
  const { ref, seen } = useReveal<HTMLDivElement>()
  return (
    <section className="lp-sec lp-rule" id={id}>
      <div className="lp-in lp-rev" data-in={seen} ref={ref}>{children}</div>
    </section>
  )
}

/** Count up to a number once, on reveal. Skipped under reduced-motion. */
function useCountUp(target: number, run: boolean, ms = 900) {
  const [v, setV] = useState(0)
  useEffect(() => {
    if (!run) return
    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    if (reduced) { setV(target); return }
    let raf = 0
    const t0 = performance.now()
    const tick = (t: number) => {
      const p = Math.min(1, (t - t0) / ms)
      // ease-out cubic: fast start, settles precisely on the real value
      setV(target * (1 - Math.pow(1 - p, 3)))
      if (p < 1) raf = requestAnimationFrame(tick)
      else setV(target)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [target, run, ms])
  return v
}

/** Path shown in the stream: drop the corpus prefix, then elide the middle if
 *  it is still long. Truncating the tail would hide the filename, which is the
 *  only part that distinguishes one row from the next. */
const shortPath = (p: string, max = 46) => {
  const parts = p.split('/')
  const i = parts.findIndex(s => s === 'estate' || s === 'real')
  const rel = (i >= 0 ? parts.slice(i + 1) : parts.slice(-3)).join('/')
  if (rel.length <= max) return rel
  const seg = rel.split('/')
  const tail = seg.slice(-2).join('/')
  return `${seg[0]}/…/${tail.length > max - 4 ? tail.slice(-(max - 4)) : tail}`
}

/** Pick a spread of severities for the stream.
 *
 *  A stream of twelve consecutive criticals from one vendored test-vector
 *  directory looks like a stuck loop, not an inventory. Round-robin across
 *  severity buckets so the severity column carries information, keeping the
 *  highest-risk finding first because that is the one worth reading.
 */
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

/* --------------------------------------------------------------------- page */

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

  // Read the live API. Any failure leaves the snapshot in place, and `live`
  // stays false so the label tells the truth.
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
        /* snapshot stays; `live` stays false */
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

/* ---------------------------------------------------------------------- nav */

function Nav({ stuck }: { stuck: boolean }) {
  return (
    <nav className="lp-nav" data-stuck={stuck}>
      <a className="lp-mark" href="#top">
        <Glyph />
        <b>Quantum Atlas</b>
        <span>ECDAT</span>
      </a>
      <div className="lp-navlinks">
        <a href="#problem">The problem</a>
        <a href="#discovery">Discovery</a>
        <a href="#evidence">Evidence</a>
        <a href="#console">Console</a>
        <a href="#outputs">Outputs</a>
      </div>
      <div className="row grow" style={{ justifyContent: 'flex-end', gap: 8 }}>
        <a className="lp-cta ghost" href="#outputs">See the output</a>
        <a className="lp-cta" href={CONSOLE}>Open the console →</a>
      </div>
    </nav>
  )
}

/** Wordmark glyph: a lattice, because every NIST-selected PQC algorithm in the
 *  knowledge base except SLH-DSA is lattice-based. */
function Glyph() {
  return (
    <svg width="17" height="17" viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <path d="M10 1.6 18 6v8l-8 4.4L2 14V6l8-4.4Z" stroke="var(--accent)" strokeWidth="1.1" opacity="0.85" />
      <path d="M10 6.2 14 8.4v4.2L10 14.8 6 12.6V8.4l4-2.2Z" stroke="var(--t3)" strokeWidth="0.9" opacity="0.7" />
      <circle cx="10" cy="10.5" r="1.5" fill="var(--accent)" />
    </svg>
  )
}

/* --------------------------------------------------------------------- hero */

function Hero({ stats, findings }: { stats: HeroStats; findings: Finding[] }) {
  return (
    <header className="lp-hero" id="top">
      <div className="lp-hero-grid">
        <div>
          <div className="lp-eyebrow">
            <i />
            Smart India Hackathon · PS 26164 · NTRO
          </div>
          <h1 className="lp-h1">
            Every cryptographic
            <br />artefact you own.
            <em>Ranked by when quantum breaks it.</em>
          </h1>
          <p className="lp-sub">
            Atlas scans source trees, certificates, container images, binaries and{' '}
            <b>live TLS endpoints</b>, then decides which findings a quantum computer
            actually breaks — and turns that into a costed migration programme you can
            argue with. Output is spec-correct <b>CycloneDX 1.6 CBOM</b> and SARIF.
          </p>
          <div className="lp-actions">
            <a className="lp-cta lg" href={CONSOLE}>Open the console →</a>
            <a className="lp-cta ghost lg" href="#problem">Why this is hard</a>
          </div>
          <div className="lp-metastrip">
            <span>evidence at file:line</span>
            <span>CycloneDX 1.6 + SARIF</span>
            <span>Mosca as a control, not a constant</span>
            <span>no agent, no daemon</span>
          </div>
        </div>

        <Stream stats={stats} findings={findings} />
      </div>
    </header>
  )
}

/** Replays real findings from the most recent scan as a discovery stream.
 *
 *  This is the first thing a reviewer sees, and the question they arrive with is
 *  "did it really read my repo?" — so the stream shows paths and line numbers,
 *  which is the only answer that means anything.
 */
function Stream({ stats, findings }: { stats: HeroStats; findings: Finding[] }) {
  const [n, setN] = useState(0)

  useEffect(() => {
    setN(0)
    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    if (reduced || !findings.length) { setN(findings.length); return }
    const id = setInterval(() => {
      setN(v => (v >= findings.length ? v : v + 1))
    }, 190)
    return () => clearInterval(id)
  }, [findings])

  const shown = findings.slice(0, n)
  const done = n >= findings.length

  return (
    <div className="lp-term">
      <div className="lp-term-bar">
        <div className="lp-dots"><i /><i /><i /></div>
        <span className="t">atlas scan corpus/estate --crqc 2033</span>
        <span className="grow" />
        <span className={`lp-live ${stats.live ? '' : 'off'}`}>
          <i />{stats.live ? 'live api' : 'sample scan'}
        </span>
      </div>

      <div className="lp-term-body">
        <div className="cmd" style={{ marginBottom: 6 }}>
          <b>$</b> atlas scan corpus/estate
        </div>
        {shown.map((f, i) => (
          <div className="lp-line" key={`${f.path}-${i}`}>
            <span className="g">found</span>
            <span className="n">{f.name}</span>
            <span className="p">{f.path}{f.line ? `:${f.line}` : ''}</span>
            <span className={`s sev-${f.severity}`}>{f.severity}</span>
          </div>
        ))}
        {done && (
          <div className="lp-line" style={{ marginTop: 6 }}>
            <span className="g">done</span>
            <span className="n">{fmt.n(stats.artifacts)} artefacts</span>
            <span className="p">
              {fmt.n(stats.files)} files · {stats.seconds.toFixed(2)}s
            </span>
          </div>
        )}
      </div>

      <div className="lp-term-foot">
        <span>{stats.org ?? 'estate'}</span>
        <span>·</span>
        <span>{fmt.n(stats.mosca)} past the Mosca deadline</span>
        <span>·</span>
        <span>{fmt.n(stats.effortDays)} engineer-days</span>
        <span className="grow" />
        {stats.scanId && <span>scan {stats.scanId.slice(0, 8)}</span>}
      </div>
    </div>
  )
}

/* ---------------------------------------------------------------- stat strip */

function Stats({ stats, algorithms }: { stats: HeroStats; algorithms: number }) {
  const { ref, seen } = useReveal<HTMLDivElement>()
  const artifacts = useCountUp(stats.artifacts, seen)
  const real = useCountUp(PROOF.realRepoArtifacts, seen)

  // The first cell describes whatever scan the API actually returned, so its
  // label has to be derived rather than written. Claiming "the demo estate"
  // while showing a real-repository scan's numbers would be exactly the kind of
  // unlabelled substitution this tool exists to catch.
  const scope = stats.live
    ? `artefacts in the latest scan`
    : `artefacts in the demo estate`

  const cells = [
    {
      v: fmt.n(Math.round(artifacts)),
      k: scope,
      d: `${stats.org ?? 'estate'} — ${fmt.n(stats.files)} files in ${stats.seconds.toFixed(2)}s, every finding with a file and line`,
    },
    {
      v: fmt.n(Math.round(real)),
      k: 'artefacts in real open-source repos',
      d: `paramiko, pyca/cryptography and pyjwt — ${fmt.n(PROOF.realRepoFiles)} files in ${PROOF.realRepoSeconds}s, ${fmt.n(PROOF.realRepoMosca)} past the Mosca deadline`,
    },
    {
      v: String(algorithms),
      k: 'algorithms classified',
      d: 'NIST status, classical and post-quantum strength, OID, wire and CPU cost',
    },
    {
      v: PROOF.probeGroup,
      k: 'measured on the wire',
      d: `${PROOF.probeHost} negotiates hybrid PQC key exchange over ${PROOF.probeVersion} — with a classical ${PROOF.probeCertAlgo} certificate`,
      mono: true,
    },
  ]

  return (
    <div className="lp-stats lp-rev" data-in={seen} ref={ref}>
      {cells.map(c => (
        <div className="lp-stat" key={c.k}>
          <div className="v" style={c.mono ? { fontFamily: 'var(--mono)', fontSize: 17, letterSpacing: 0 } : undefined}>
            {c.v}
          </div>
          <div className="k">{c.k}</div>
          <div className="d">{c.d}</div>
        </div>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------------ problem */

function Why() {
  return (
    <Section id="problem">
      <div className="lp-sechead">
        <div>
          <div className="lp-eyebrow"><i />The problem</div>
          <h2 className="lp-h2">Data recorded today is decrypted in 2033.</h2>
        </div>
        <p className="lp-lede" style={{ maxWidth: '46ch' }}>
          Harvest-now-decrypt-later does not need a quantum computer to exist yet.
          It needs one to exist <b>before your data stops being sensitive</b>. That
          makes the deadline a property of your data, not of the hardware.
        </p>
      </div>

      <div className="lp-hndl" style={{ marginTop: 40 }}>
        <Hndl />
        <div>
          <h3 style={{ fontSize: 17, fontWeight: 450, letterSpacing: '-0.3px', margin: 0, color: 'var(--t1)' }}>
            Mosca's inequality is the whole assessment
          </h3>
          <p className="lp-lede" style={{ fontSize: 14.5, marginTop: 12 }}>
            If data shelf-life <b>X</b> plus migration time <b>Y</b> exceeds the years
            left before a cryptographically relevant quantum computer <b>Z</b>, that
            data is already exposed. An adversary recording ciphertext today decrypts
            it before you finish migrating.
          </p>
          <p className="lp-lede" style={{ fontSize: 14.5, marginTop: 12 }}>
            Nobody knows Z. Hard-coding 2033 and presenting the result as fact is
            dishonest — so Atlas makes Z, X, Y and headcount into sliders, recomputes
            the inequality across the whole inventory in milliseconds, and draws the
            violations-versus-Z curve so you can see how much of the answer is
            assumption. Re-simulation never rescans; it re-runs the pure risk model
            over stored artefacts.
          </p>

          <div className="lp-eq">
            <span className="term"><b>X</b><u>shelf-life</u></span>
            <span className="op">+</span>
            <span className="term"><b>Y</b><u>migration</u></span>
            <span className="op">&gt;</span>
            <span className="term"><b>Z</b><u>years to CRQC</u></span>
            <span className="verdict chip warn">already exposed</span>
          </div>
        </div>
      </div>
    </Section>
  )
}

/** The HNDL timeline: a real artefact from the demo estate, drawn to scale.
 *
 *  treasury-archive/src/archive.py:15 uses X25519 on records with a 25-year
 *  shelf-life, so its Mosca margin is -18.67 years against a 2033 CRQC. That is
 *  the single clearest thing in the whole inventory, so it is what the landing
 *  page argues with.
 */
function Hndl() {
  const START = 2026
  const END = 2054
  const span = END - START
  const at = (y: number) => ((y - START) / span) * 100
  const CRQC = 2033
  const SHELF_END = START + 25

  const nodes = [
    { y: START, label: 'today', color: 'var(--accent)', top: 'recorded' },
    { y: CRQC, label: `CRQC ${CRQC}`, color: 'var(--crit)', top: 'decrypted' },
    { y: SHELF_END, label: `${SHELF_END}`, color: 'var(--t4)', top: 'still sensitive' },
  ]

  return (
    <div className="lp-tl">
      <div className="label">treasury-archive/src/archive.py:15 · X25519 · 25-year records</div>
      <div className="lp-tl-track">
        <div className="lp-tl-axis" />
        <div className="lp-tl-fill" style={{ left: `${at(CRQC)}%`, right: `${100 - at(SHELF_END)}%` }} />
        {nodes.map(n => (
          <div className="lp-tl-node" key={n.y} style={{ left: `${at(n.y)}%` }}>
            <b style={{ color: n.color }}>{n.top}</b>
            <i style={{ background: n.color }} />
            <span>{n.label}</span>
          </div>
        ))}
      </div>
      <div className="t3" style={{ fontSize: 12.5, marginTop: 18, lineHeight: 1.55 }}>
        The red span is the exposure window: <b style={{ color: 'var(--crit)', fontWeight: 450 }}>21 years</b>{' '}
        in which the data is readable by whoever recorded it and still commercially
        sensitive. Atlas scores this artefact at <span className="mono">9.9</span>{' '}
        with a Mosca margin of <span className="mono" style={{ color: 'var(--crit)' }}>−18.67y</span> —
        the worst in the estate, and it is a two-line config change to fix.
      </div>
    </div>
  )
}

/* ---------------------------------------------------------------- discovery */

function Scanners() {
  return (
    <Section id="discovery">
      <div className="lp-sechead">
        <div>
          <div className="lp-eyebrow"><i />Discovery</div>
          <h2 className="lp-h2">Six surfaces, one inventory.</h2>
        </div>
        <p className="lp-lede" style={{ maxWidth: '48ch' }}>
          Cryptography hides in places a source grep never reaches: a statically
          linked library, a base image layer, a certificate with a 30-year validity,
          a cipher suite negotiated at runtime. Atlas reads all of them and
          normalises the result into one artefact model.
        </p>
      </div>

      <div className="lp-cards" style={{ marginTop: 36 }}>
        {SCANNERS.map(s => (
          <div className="lp-card" key={s.ix}>
            <h4><span className="ix">{s.ix}</span>{s.title}</h4>
            <p>{s.body}</p>
            <ul>{s.tags.map(t => <li key={t}>{t}</li>)}</ul>
          </div>
        ))}
      </div>
    </Section>
  )
}

/* ----------------------------------------------------------------- evidence */

function Evidence() {
  return (
    <Section id="evidence">
      <div className="lp-sechead">
        <div>
          <div className="lp-eyebrow"><i />Evidence</div>
          <h2 className="lp-h2">Nothing in the inventory exists without provenance.</h2>
        </div>
        <p className="lp-lede" style={{ maxWidth: '48ch' }}>
          A finding you cannot trace is a finding a reviewer will not act on. Every
          artefact carries the file, the line, the source snippet, and — for images
          and binaries — the layer or section it came from.
        </p>
      </div>

      <div className="lp-ev" style={{ marginTop: 36 }}>
        <div className="lp-code">
          <div className="lp-code-head">
            <span>treasury-archive/src/archive.py</span>
            <span>python</span>
          </div>
          <pre>{`  12  `}<span className="c">{`# 25-year statutory retention`}</span>{`
  13  `}<span className="k">def</span>{` `}<span className="n">seal_record</span>{`(payload: bytes):
  14      `}<span className="c">{`# ephemeral key per record`}</span>{`
`}<span className="hl">{`  15      private = x25519.X25519PrivateKey.generate()`}</span>{`
  16      shared  = private.exchange(peer_public)
  17      `}<span className="k">return</span>{` AESGCM(shared[:32]).encrypt(...)`}</pre>
        </div>

        <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="lp-code-head" style={{ borderRadius: 0 }}>
            <span>what Atlas records for line 15</span>
            <span className="sev sev-critical">critical · 9.9</span>
          </div>
          <table className="lp-table">
            <tbody>
              <tr><td>Impact</td><td className="q">Shor-broken — elliptic-curve Diffie–Hellman, 0 bits post-quantum</td></tr>
              <tr><td>Shelf-life</td><td className="q">25 years, inferred from the <span className="mono">archive/</span> path signal</td></tr>
              <tr><td>Mosca</td><td className="q"><span className="mono" style={{ color: 'var(--crit)' }}>−18.67y</span> — 25 + 1.5 &gt; 7 against a 2033 CRQC</td></tr>
              <tr><td>Criticality</td><td className="q">critical, inferred from treasury path and record retention</td></tr>
              <tr><td>Replace with</td><td className="q"><span className="mono">X25519MLKEM768</span> hybrid, or <span className="mono">ML-KEM-768</span> internally</td></tr>
              <tr><td>Wire cost</td><td className="q">+2,240 bytes per handshake — two extra TCP segments at a 1,460-byte MSS</td></tr>
              <tr><td>Effort</td><td className="q">3 engineer-days · wave 4, harvest-now-decrypt-later</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </Section>
  )
}

/* ------------------------------------------------------------------ console */

function Console() {
  return (
    <Section id="console">
      <div className="lp-sechead">
        <div>
          <div className="lp-eyebrow"><i />The console</div>
          <h2 className="lp-h2">Ten views. Each answers one question.</h2>
        </div>
        <p className="lp-lede" style={{ maxWidth: '46ch' }}>
          A dashboard that shows everything answers nothing. Each view here exists
          because an analyst asks that question out loud, in that order.
        </p>
      </div>

      <div className="panel" style={{ marginTop: 34, padding: '18px 8px 8px', overflowX: 'auto' }}>
        <table className="lp-table">
          <thead>
            <tr><th style={{ width: 150 }}>View</th><th style={{ width: 280 }}>Question</th><th>What it shows</th></tr>
          </thead>
          <tbody>
            {VIEWS.map(([name, q, body]) => (
              <tr key={name}>
                <td>{name}</td>
                <td className="q">{q}</td>
                <td>{body}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  )
}

/* ------------------------------------------------------------------ outputs */

function Outputs() {
  const rows = [
    ['CycloneDX 1.6 CBOM', 'results/<id>.cbom.json',
     'The standardised deliverable. cryptoProperties with primitive, security level, crypto functions and OID; evidence.occurrences with file and line. Schema-validated in the test suite.'],
    ['SARIF 2.1.0', 'results/<id>.sarif.json',
     'CI and code-scanning integration. GitHub picks findings up automatically and annotates the diff.'],
    ['Markdown report', 'results/<id>.report.md',
     'The human assessment: posture, worst findings, waves, schedule against the horizon.'],
    ['Raw scan JSON', 'results/<id>.json',
     'The full artefact set, which is what re-simulation replays — so changing an assumption never means rescanning.'],
  ]

  return (
    <Section id="outputs">
      <div className="lp-sechead">
        <div>
          <div className="lp-eyebrow"><i />Outputs</div>
          <h2 className="lp-h2">Standard formats, and a CI gate that exits non-zero.</h2>
        </div>
        <p className="lp-lede" style={{ maxWidth: '46ch' }}>
          A report nobody can machine-read is a PDF nobody opens twice. Atlas emits
          the two formats the rest of the toolchain already speaks.
        </p>
      </div>

      <div className="panel" style={{ marginTop: 34, padding: '18px 8px 8px', overflowX: 'auto' }}>
        <table className="lp-table">
          <thead>
            <tr><th style={{ width: 190 }}>Format</th><th style={{ width: 220 }}>Path</th><th>Purpose</th></tr>
          </thead>
          <tbody>
            {rows.map(([f, p, d]) => (
              <tr key={f}>
                <td>{f}</td>
                <td className="mono">{p}</td>
                <td>{d}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="lp-code" style={{ marginTop: 14 }}>
        <div className="lp-code-head">
          <span>fail a pull request that adds Shor-broken cryptography</span>
          <span>exit 1</span>
        </div>
        <pre>{`$ atlas ci corpus/estate `}<span className="k">--fail-on</span>{` high `}<span className="k">--max-mosca</span>{` 0

  `}<span className="r">FAIL</span>{`  50 findings at or above high · 10 past the Mosca deadline
        wrote results/<id>.sarif.json for code scanning
  `}<span className="c">{`# exit 1 — the pipeline stops here`}</span></pre>
      </div>
    </Section>
  )
}

/* ------------------------------------------------------------------ closing */

function Closing() {
  const cmds = useMemo(() => [
    'atlas scan corpus/estate',
    'atlas probe cloudflare.com',
    'atlas simulate <id> --crqc 2030',
    'atlas plan <id>',
    'atlas export <id> cbom',
  ], [])

  return (
    <section className="lp-sec">
      <div className="lp-in">
        <div className="lp-close">
          <div>
            <h2 className="lp-h2" style={{ maxWidth: '20ch' }}>
              Point it at a repository and see for yourself.
            </h2>
            <p className="lp-lede" style={{ marginTop: 14, maxWidth: '52ch' }}>
              The console opens on the most recent scan, so it is never an empty
              shell. Discovery on the demo estate takes about three hundredths of a
              second; the vendored real repositories take under seven.
            </p>
            <div className="lp-actions">
              <a className="lp-cta lg" href={CONSOLE}>Open the console →</a>
              <a className="lp-cta ghost lg" href="#discovery">What it scans</a>
            </div>
          </div>
          <div className="lp-code" style={{ minWidth: 320, flex: '1 1 320px' }}>
            <div className="lp-code-head"><span>command line</span><span>10 subcommands</span></div>
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
      <span>Quantum Atlas · ECDAT · Problem statement 26164 · National Technical Research Organisation</span>
      <span className="row" style={{ gap: 16 }}>
        <a href={CONSOLE}>console</a>
        <a href="#problem">the problem</a>
        <a href="#outputs">outputs</a>
      </span>
    </footer>
  )
}
