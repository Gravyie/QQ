# Quantum Atlas

**Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)**
Smart India Hackathon problem statement **26164** — National Technical Research Organisation (NTRO)

Atlas finds every cryptographic artefact in an estate, decides which ones a quantum
computer breaks and when, and turns that into a costed migration programme you can
argue with.

It scans source trees, certificate stores, container images, compiled binaries and
**live TLS endpoints**. Every finding carries the file and line it came from. Output is
spec-correct CycloneDX 1.6 CBOM plus SARIF for CI gating.

---

## Why this is not a regex grepper

Four things carry the weight:

**1. Evidence, not assertions.** Every artefact records `file:line`, the source snippet,
the container layer or binary section it came from. Nothing in the inventory exists
without provenance you can click through to. A reviewer's first question is "did it
really read my repo?" — the console answers it by streaming findings with paths as the
walk proceeds.

**2. The Mosca assumption is a control, not a constant.** Nobody knows when a
cryptographically relevant quantum computer arrives. Hard-coding 2033 and presenting the
result as fact is dishonest. Atlas makes CRQC year, data shelf-life, migration time and
team size into sliders, recomputes `X + Y > Z` across the whole inventory instantly, and
draws the violations-vs-CRQC-year curve so you can see how sensitive the answer is to the
assumption. Re-simulation never rescans — it re-runs the pure risk model over stored
artefacts, which is why it feels instant.

**3. Real network evidence.** `atlas probe` performs actual TLS handshakes: negotiated
version, cipher, key-exchange group, whether legacy protocol versions are still accepted,
and the served certificate chain. Probing cloudflare.com returns `X25519MLKEM768` — real
hybrid PQC on the wire, with a classical ECDSA P-256 certificate, so confidentiality is
protected and authentication is not. That distinction is the entire migration argument,
and it is measured rather than assumed.

**4. A programme, not a list.** Findings are grouped into dependency-ordered waves:
providers before protocols, protocols before key agreement, key agreement before
signatures. Migrating in severity order stalls because the library underneath cannot do
the new algorithm yet. Each wave carries effort in engineer-days, and the schedule states
plainly whether you finish before the horizon.

---

## Quick start

```bash
cd ~/Documents/Projects/quantum-atlas

# backend
.venv/bin/pip install -r backend/requirements.txt      # first time only
cd backend && ../.venv/bin/python -m uvicorn server:app --port 8000
```

Open **http://localhost:8000** — the built console is served from the same origin as the
API, so there is nothing else to start.

For frontend development with hot reload:

```bash
cd frontend && npm install && npm run dev     # http://localhost:5173, proxies /api to :8000
```

Rebuild the production bundle after frontend changes:

```bash
cd frontend && npm run build                  # writes frontend/dist, picked up by the server
```

---

## The console

Seven views, each answering one question.

| View | Question it answers |
|---|---|
| **Discovery** | What is in the estate? Pick targets, watch findings stream in with file paths. |
| **Overview** | How bad is it? KPIs, severity and impact distribution, and the criticality × impact heatmap. Click any heatmap cell to open exactly those artefacts. |
| **Inventory** | Where precisely? Every artefact, filterable by severity, impact, criticality and class, with an evidence drawer showing file, line, snippet, risk derivation and the specific replacement. |
| **Mosca simulator** | How much does the answer depend on assumptions? Move CRQC year, shelf-life, migration time and headcount; watch findings flip. |
| **Roadmap** | What do we actually do, in what order, at what cost? Dependency-ordered waves with a year axis against the CRQC horizon. |
| **Live probe** | What is really on the wire? Real TLS handshakes against real hosts. |
| **Knowledge base** | Why did Atlas classify it that way? 112 algorithms with NIST status, classical and post-quantum strength, OIDs — plus a resolver that decomposes any cipher-suite string and shows which component the risk model scored. |

---

## CLI

```bash
ATLAS=".venv/bin/python backend/atlas_cli.py"

$ATLAS scan corpus/estate                      # discover and report
$ATLAS scan container:image.tar binary:./app   # kind-prefixed targets
$ATLAS probe cloudflare.com github.com         # live TLS handshakes
$ATLAS simulate <scan-id> --crqc 2030          # re-run Mosca, no rescan
$ATLAS plan <scan-id>                          # migration waves
$ATLAS kb --resolve TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
$ATLAS list                                    # stored scans
$ATLAS export <scan-id> cbom                   # cbom | sarif | report
```

### CI gate

```bash
$ATLAS ci corpus/estate --fail-on high --max-mosca 0
```

Exits non-zero when any finding is at or above the given severity, or when Mosca
violations exceed the cap. Writes SARIF alongside, so GitHub code scanning picks findings
up automatically. Verified: `--fail-on high` on the demo estate exits **1**;
`--fail-on none` exits **0**; the PQC pilot service passes `--fail-on critical`.

---

## Outputs

| Format | Path | Purpose |
|---|---|---|
| **CycloneDX 1.6 CBOM** | `results/<id>.cbom.json` | Standardised inventory. `cryptoProperties` with primitive, security level, crypto functions, OID; `evidence.occurrences` with file and line. Schema-validated in tests. |
| **SARIF 2.1.0** | `results/<id>.sarif.json` | CI and code-scanning integration. |
| **Markdown report** | `results/<id>.report.md` | Human-readable assessment. |
| **Raw scan JSON** | `results/<id>.json` | Full artefact set, for re-simulation. |

---

## How the risk model works

**Quantum impact** is derived from the knowledge base, not guessed:

| Class | Meaning | Post-quantum strength |
|---|---|---|
| `broken_classically` | Already exploitable today (MD5, SHA-1, RC4, DES) | — |
| `shor_broken` | Asymmetric, falls entirely to Shor (RSA, ECDSA, ECDH, Ed25519) | 0 bits |
| `grover` | Symmetric, Grover halves the key (AES-128, 3DES) | half classical |
| `classical_ok` | Adequate margin under Grover (AES-256, SHA-384) | ≥128 bits |
| `pq_safe` | Post-quantum (ML-KEM, ML-DSA, SLH-DSA, hybrids) | ≥128 bits |

**Mosca's inequality** — `X + Y > Z` where X is data shelf-life, Y is migration time and
Z is years until the CRQC. When true, that data is already exposed: an adversary
harvesting ciphertext today can decrypt it before you finish migrating.

**Shelf-life (X)** comes from certificate validity windows where available, then path
signals (`archive/` → 25y, `treasury/` → 20y, `root-ca/` → 15y), then per-class defaults.
Root CAs inherit at least 15 years because they sign material outliving the CA itself.
Values above 30 years are capped for scoring — a 1000-year `notAfter` (routine in crypto
library test corpora) would otherwise produce a Mosca margin near −1000 and outrank every
genuine finding. The cap is disclosed on the artefact, never silent.

**Effort** is costed at 18 engineer-days per person-month, not 22. Nobody migrates
cryptography full time; assuming otherwise produces a plan that misses.

---

## Layout

```
backend/
  atlas/
    knowledge_base.py    112 algorithms, alias resolution, cipher-suite decomposition
    scanners.py          source, certificate, key, config, manifest scanners
    scanners2.py         container image (no daemon needed), binary, config
    network.py           live TLS probing
    risk.py              impact classification, Mosca, severity, recommendations
    planner.py           migration waves, schedule, simulation, rollups
    cbom.py              CycloneDX 1.6 + SARIF emitters
    engine.py            orchestration, event streaming
  server.py              FastAPI: 17 endpoints, SSE scan streaming
  atlas_cli.py           10-subcommand CLI
  tests/                 249 tests, including CycloneDX/SARIF schema conformance
frontend/                React 19 + Vite, hand-rolled SVG charts, no chart library
corpus/
  estate/                synthetic multi-language bank estate (the demo)
  real/                  paramiko, pyca/cryptography, pyjwt (real open-source repos)
results/                 scan outputs
docs/                    demo script, handoff notes
```

---

## Verified state

```
backend tests      249 passed
frontend typecheck tsc -b clean
production build   vite build clean, 250 kB / 74 kB gzipped
demo estate        101 artefacts, 34 files, 0.04s
real repos         2,597 artefacts across paramiko + pyca/cryptography + pyjwt, 6.8s
live probe         cloudflare.com → TLSv1.3, X25519MLKEM768 hybrid PQC confirmed
CBOM               CycloneDX 1.6, schema-validated
CI gate            exits 1 on --fail-on high, 0 on --fail-on none
```

## Security note

The API binds to `127.0.0.1` and has **no authentication**. It is a local analyst tool.
`/api/scan` reads arbitrary filesystem paths and `/api/probe` makes outbound TLS
connections from the host — both are intended, both are why this must not be exposed to a
network without putting authentication and path allow-listing in front of it first. See
`docs/NEXT-STEPS.md`.
