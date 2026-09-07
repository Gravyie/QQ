# PS 26164 — Clause-by-Clause Achievement Assessment

**Project:** Quantum Atlas (ECDAT) · **PS:** 26164, NTRO · **Date:** 2026-09-07
**Method:** every claim below is traced to code (`backend/atlas/…`, `frontend/src/…`) or to
measured scan outputs in `results/`. Status levels: **Achieved** · **Substantially achieved
(known limits)** · **Partial**.

## Bottom line

| PS clause | Status | One-line verdict |
|---|---|---|
| i. Catalogue all artefact classes across the estate | **Substantially achieved** | All 7 classes detected; hardware/cloud via static markers, not live inventory |
| ii. Quantum risk assessment, attack-prone systems, sensitive-data risk | **Substantially achieved** | Full assessment + HNDL exposure; "sensitive data" is inferred from path/criticality signals, not DLP |
| iii. Classify by type, lifetime, criticality + Mosca | **Achieved** | Complete: 11 types, disclosed lifetime rules, Mosca per artefact + curve |
| iv. Recommend PQC/hybrid alternatives on risk, latency, cost | **Substantially achieved** | Latency/bandwidth + effort cost modelled; financial (currency) cost not modelled; full advisor comparison is API-only, no console tab |
| Deliverable: standardised CBOM report w/ versions+modes | **Achieved** | CycloneDX 1.6 CBOM + SARIF 2.1.0 + Markdown, schema-validated in tests |
| Deliverable: interactive GUI for scan, risks, results | **Substantially achieved** | 7 working views cover the core loop; 3 backend capabilities lack UI |

## i. Catalogue artefacts — Substantially achieved

**What works.** Six discovery scanners plus the network prober cover every named class:

- *Algorithms / protocols / libraries* — `scanners.py` (`SourceScanner`, ~90 regexes over 16
  languages; `LibraryScanner` over requirements/package.json/pom.xml/go.mod/Cargo/composer).
- *Keys / certificates* — `KeyScanner` (6 PEM markers, encryption state, size);
  `CertificateScanner` (multi-cert PEM + DER, subject/issuer/validity/expiry, curve, sig-alg;
  expired certs flagged; GOST and unknown OIDs preserved by OID, never dropped).
- *Hardware modules* — `engine.py:24-40` marker set (PKCS#11, AWS CloudHSM, Thales Luna,
  Entrust nShield, YubiHSM, SoftHSM) typed as `hardware` artefacts; capability notes in
  `crypto_services.py:49-59`; planned in wave W6 (`planner.py:85-88`).
- *Cloud services* — KMS key-spec and LB-policy config expansion (`scanners.py`
  `CONFIG_PATTERNS`, `KMS_KEY_SPECS`), typed as `cloud-service`, costed at 9-month
  migration blocks (`risk.py:57`).
- *Estate coverage* — source trees, container tarballs without a daemon (`scanners2.py`
  `ContainerScanner`), ELF/PE/Mach-O binaries with 12 library markers, live TLS endpoints
  (`network.py`), and per-service ownership rollups (`services.py`).

**What is missing, and why.** Detection of hardware/cloud is **static-marker based**: the tool
finds references to an HSM/KMS in code and config; it does not call cloud inventory APIs
(AWS Config, Azure Resource Graph) or interrogate HSMs over PKCS#11, because that requires
tenant credentials and network access the local-analyst design deliberately avoids (see
Security note in README). Likewise "internal vs external facing" is inferred from path and
config signals, not from network topology mapping. Closing this means credentialed
connectors per cloud/HSM vendor — an integration project, not a detection-algorithm gap.

## ii. Quantum risk assessment — Substantially achieved

**What works.** `risk.py` (pure, no I/O) derives, per artefact: quantum impact from the
112-algorithm knowledge base (not guessed), business criticality, Mosca violation + margin,
quantum-year, HNDL exposure class, 0–10 severity/score. Aggregation answers "which systems
are prone": severity/impact distributions, the criticality×impact heatmap (click-to-inventory),
per-service risk rollups, and probe artefacts that distinguish "the code says" from "the wire
says" (`network.py:311`). Measured: demo estate 10 Mosca violations; real repos 1,195.

**What is missing, and why.** "Risks to sensitive data" is addressed through **proxies**:
path signals (`treasury/`, `archive/`), certificate lifetimes, and criticality heuristics
(`risk.py:32`). Atlas never opens datastores or classifies PII/financial records — it is a
cryptography scanner, not a DLP tool, and reading customer data would exceed its stated
evidence model (file:line provenance of crypto material). A data-catalogue join (e.g. import
sensitivity tags per service) is the honest extension point; the `service_rollup` already
accepts per-service grouping to hang those tags on.

## iii. Classification + Mosca — Achieved

**What works.** The full clause is implemented: 11 artefact types (`models.py`), lifetime
estimation preferring certificate windows (roots floored at 15y), then path signals, then
per-class defaults — capped at 30 years with the cap disclosed on the artefact rather than
silent; business criticality inference; Mosca `X+Y>Z` evaluated per artefact with margins,
swept across 2028–2050 by `risk_curve`, and re-simulated instantly by `simulate()` without
rescanning. The console's Simulator exposes all four controls plus four presets.

**Nothing material missing.** Remaining polish would be per-artefact lifetime audit trails in
the UI (the data exists on the artefact; the drawer shows the value, not the derivation chain).

## iv. PQC/hybrid recommendations — Substantially achieved

**What works.** Two layers, both risk-profile driven:

- *Per finding* (`risk.py:359-411`): every artefact gets a KB-keyed replacement target plus
  hybrid transitional option with real wire-delta bytes and CPU-cost figures — rendered in
  the Inventory evidence drawer (`Detail.tsx:11,72-81`: target, hybrid, effort days, wire delta).
- *Per workload* (`advisor.py`): 8 profiles (tls-frontend, internal-mtls, firmware-signing,
  code-signing, document-archive, iot-constrained, national-security, payments-hsm). Hard
  constraints (NIST floor from shelf-life, wire-byte and CPU-ms budgets, stateful/hardware
  rules) reject with named blockers; survivors score 40/25/20/15 on standardisation, margin,
  wire and CPU. "Latency" is reference `ops_ms` + wire bytes translated to TCP segments;
  "cost" is bandwidth/CPU/effort (engineer-days), all sourced from `ALGORITHMS[…]['perf']`
  with explicit non-benchmark disclaimers (`advisor.py:460-465`).

**What is missing, and why.** (a) **Financial cost is not modelled** — no licence fees, HSM
procurement, or vendor pricing in currency; the PS's "cost" is currently engineering cost.
Money-cost needs a vendor price book that does not exist in the open and varies per buyer,
so it was scoped out deliberately. (b) The full **advisor comparison UI is API-only**
(`/api/advise`, `/api/scans/{id}/alternatives` + client methods exist; no console tab), so
analysts see the chosen replacement per finding but cannot browse rejected candidates in the
GUI. Wiring those two tabs is small, well-defined frontend work.

## UI ↔ workflow sync audit

Core loop is in sync — each view calls its matching endpoint over the same `ScanEngine`
the CLI uses, and cross-navigation works (heatmap → filtered inventory, roadmap/algorithm →
inventory, scan history open/delete):

| Workflow step | Backend | Console view | Sync? |
|---|---|---|---|
| Run discovery, stream findings | `POST /api/scan`, SSE stream, cancel | Discovery (`ScanView`) | Yes |
| Assess posture, KPIs, heatmap | `GET /api/scans/{id}` + plan/matrices | Overview | Yes |
| Inspect evidence + replacement | `GET …/artifacts` (composable filters) | Inventory + drawer | Yes |
| Re-run assumptions | `POST /api/simulate`, `GET …/risk-curve` | Mosca simulator | Yes |
| Execute programme | plan in `GET /api/scans/{id}` | Roadmap | Yes, base-config plan (simulator assumptions do not carry over — by design, one line the UI could state) |
| Verify the wire | `POST /api/probe` | Live probe | Yes |
| Understand classification | `/api/knowledge-base`, `/resolve` | Knowledge base | Yes |
| Per-team ownership | `GET …/services` | **none — `Services.tsx` built but not imported in `App.tsx`** | **No (dead code)** |
| Mandate deadlines | `GET …/compliance…`, `/api/standards` | **none** | **No (API-only)** |
| Compare replacements | `/api/advise`, `GET …/alternatives`, `/api/workload-profiles` | **none** | **No (API-only)** |

The landing page additionally advertises Compliance and Alternatives views that do not exist
yet — copy should be corrected or the tabs built. Nothing in the UI contradicts backend
results; the gaps are missing tabs, not divergent logic.

## Closing the gaps (ordered by value)

1. **Wire Services + Compliance + Alternatives tabs** (frontend only; endpoints, types and
   client methods already exist) — completes clause iv visibility and the ownership story.
2. **Credentialed cloud/HSM connectors** (AWS/Azure/GCP inventory, PKCS#11 interrogation) —
   upgrades clause i from marker evidence to live inventory; needs tenant credentials by design.
3. **Data-sensitivity join** (import tags per service into `service_rollup`) — hardens the
   "sensitive data" half of clause ii without turning Atlas into a DLP tool.
4. **Vendor price book + currency costing** — only if NTRO wants procurement-grade estimates;
   otherwise the current engineer-day model is the defensible choice, stated as such.
5. **Auth + path allow-listing** — prerequisite before any network exposure (README Security note).
