# Demo Script — "From Red to Green": a before/after quantum-migration story

**Duration:** 6–8 minutes · **Cast:** one legacy service, one migrated pilot, the console
**Prereqs:** backend on `http://localhost:8000`, console open, terminal open.
If a live command stumbles on stage, fall back to the stored scan IDs below
(`atlas list` always shows the latest).

| Role | Target | Stored scan (fallback) |
|---|---|---|
| ❌ BEFORE — legacy risk | `corpus/estate/payments-service` | `6def8958-b75c-44c8-a1ea-5227d5d86fc9` |
| ✅ AFTER — migrated pilot | `corpus/estate/interbank-pqc-pilot` | `2fc4bcb8-e3e2-463b-90e9-e5cdad16a7ad` |

## Act 1 — Reveal the risk (2 min, terminal)

Narrate: *"This is our payments service. Let's see what quantum breaks in it."*

```bash
./.venv/bin/python backend/atlas_cli.py scan corpus/estate/payments-service
```

Point at the output as it streams — findings arrive **with file paths**, not bare names:

- `SHA-1  settlement.py:15 → SHA-384`, `MD5  tokenisation.py:50` — broken today (9.0, critical)
- `TLSv1.0 / TLSv1.1  nginx.conf:17`, `ECDH  nginx.conf:18 → ML-KEM-768` — Shor-broken key agreement
- Summary: **30 artefacts, 40% quantum-vulnerable, 1 Mosca violation, 360 engineer-days over 7 waves**

Land the line: *"Every finding names the file, the line, and its replacement."*

## Act 2 — The standardised report (1.5 min, terminal + editor)

Narrate: *"The PS asks for all assets including versions and modes in standardised formats.
Same scan, three artefacts:"*

```bash
ls results/6def8958*                       # .json .cbom.json .sarif.json .report.md
head -60 results/6def8958*.report.md       # executive summary → Mosca → waves
```

Open the CBOM and show one component: `cryptoProperties` (algorithm, mode, key size),
`evidence.occurrences` (file + line), OID — then note the SARIF feeds GitHub code
scanning unchanged. Key sentence: *"CycloneDX 1.6 for machines, Markdown for humans,
SARIF for the pipeline — one engine produces all three, so they can never disagree."*

## Act 3 — The interactive GUI (2 min, browser at http://localhost:8000)

| Click | Show |
|---|---|
| Discovery | corpus picker; re-run the payments scan, watch findings stream with paths |
| Overview | KPIs + severity bars + **criticality × impact heatmap — click a cell** to open exactly those artefacts |
| Inventory | filter to `critical`, open a finding → evidence drawer: snippet, Mosca margin, **recommended replacement + wire delta** |
| Mosca simulator | drag the **CRQC slider 2033 → 2030**, watch violations jump; *"nobody knows the year, so the curve is the deliverable"* |
| Roadmap | 7 waves on a year axis vs the CRQC horizon with effort per wave |
| Live probe | `atlas probe cloudflare.com` equivalent in one click: **X25519MLKEM768** negotiated, classical ECDSA P-256 cert — *"confidentiality protected, authentication not; measured, not assumed"* |

## Act 4 — The migration payoff (1.5 min, terminal)

Narrate: *"Same tool, against the interbank channel we already migrated to ML-KEM-768 + ML-DSA-65:"*

```bash
./.venv/bin/python backend/atlas_cli.py scan corpus/estate/interbank-pqc-pilot
# → 5 artefacts, highest risk 2.2, pq_safe, 15 engineer-days, "what done looks like"
```

Then the finale — the policy gate both services must pass:

```bash
./.venv/bin/python backend/atlas_cli.py ci corpus/estate/payments-service --fail-on high
# → FAIL, exit 1: 7 critical + 7 high findings listed with file:line
./.venv/bin/python backend/atlas_cli.py ci corpus/estate/interbank-pqc-pilot --fail-on critical
# → PASS, exit 0: estate within policy
```

Closing line: *"Red blocks the pipeline, green ships it. That is the whole migration,
visible in one demo: discover → assess → plan → prove."*

## Stage notes

- Timings are instant (legacy 0.01s, pilot sub-second) — no awkward waits; re-run freely.
- Every number above was measured on 2026-09-07; fresh scans print fresh IDs but identical findings.
- If the projector has no network, skip the Live-probe click — everything else is offline.
- Q&A ammunition: simulator presets (CNSA 2033 / Aggressive 2030), `atlas kb --resolve
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` to show the weakest-link resolver, `atlas export
  <id> cbom` for the machine-readable handoff.
