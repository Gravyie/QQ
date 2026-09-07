/** Landing-page data.
 *
 *  Everything on the landing page is read from the live API when the console is
 *  being served by the Atlas backend, which is the normal case. `SNAPSHOT` is
 *  the fallback for when the page is opened without a reachable API (static
 *  hosting, a screenshot rig, a judge opening the bundle from disk).
 *
 *  The distinction is surfaced in the UI rather than hidden: the hero labels
 *  itself `live · scan <id>` when it is reading the API and `sample scan` when
 *  it is replaying this snapshot. A number on a marketing page that silently
 *  falls back to a hardcoded value is a lie, and the whole point of this tool is
 *  that its numbers are traceable.
 *
 *  The snapshot values below are the real output of the scans stored in
 *  results/: the synthetic bank estate (101 artefacts) and the vendored
 *  open-source repositories paramiko + pyca/cryptography + pyjwt (2,597
 *  artefacts), plus real TLS handshakes against cloudflare.com and github.com.
 */

export interface Finding {
  name: string
  path: string
  line?: number
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  impact: string
}

export interface HeroStats {
  artifacts: number
  files: number
  seconds: number
  mosca: number
  effortDays: number
  vulnerablePct: number
  scanId?: string
  live: boolean
  org?: string
}

/** Real findings from the stored estate scan, used only when the API is down. */
export const SNAPSHOT_FINDINGS: Finding[] = [
  { name: 'RSA private key', path: 'payments-service/config/secrets/jwt-signing.key', line: 1, severity: 'critical', impact: 'shor_broken' },
  { name: 'X25519', path: 'treasury-archive/src/archive.py', line: 15, severity: 'critical', impact: 'shor_broken' },
  { name: 'RSA certificate', path: 'infra/pki/ca/root-ca.pem', severity: 'critical', impact: 'shor_broken' },
  { name: 'ECDSA', path: 'core-banking-adapter/AccountProtection.cs', line: 11, severity: 'critical', impact: 'shor_broken' },
  { name: 'Ed25519', path: 'edge-api/src/signing.ts', line: 16, severity: 'critical', impact: 'shor_broken' },
  { name: 'MD5', path: 'document-store/src/dedupe.go', line: 22, severity: 'critical', impact: 'broken_classically' },
  { name: 'TLS 1.0', path: 'infra/openssl/openssl.cnf', line: 8, severity: 'high', impact: 'unknown' },
  { name: 'AES-128-CBC', path: 'auth-service/src/main/java/Vault.java', line: 41, severity: 'medium', impact: 'grover' },
  { name: 'ML-KEM-768', path: 'interbank-pqc-pilot/src/kem.py', line: 9, severity: 'info', impact: 'pq_safe' },
  { name: 'SHA-1', path: 'branch-hsm-bridge/src/pkcs11.c', line: 63, severity: 'critical', impact: 'broken_classically' },
  { name: '3DES', path: 'service-mesh/mesh.go', line: 31, severity: 'critical', impact: 'broken_classically' },
  { name: 'AES-256-GCM', path: 'payments-service/src/tokens.py', line: 58, severity: 'info', impact: 'classical_ok' },
]

export const SNAPSHOT: HeroStats = {
  artifacts: 101,
  files: 34,
  seconds: 0.03,
  mosca: 10,
  effortDays: 1443,
  vulnerablePct: 43.6,
  live: false,
  org: 'Meridian Financial Services',
}

/** Verified figures quoted elsewhere on the page. Each one is reproducible by
 *  running the command named beside it — see README "Verified state". */
export const PROOF = {
  algorithms: 112,
  realRepoArtifacts: 2597,
  realRepoFiles: 1412,
  realRepoSeconds: 6.83,
  realRepoMosca: 1195,
  probeHost: 'cloudflare.com',
  probeGroup: 'X25519MLKEM768',
  probeVersion: 'TLSv1.3',
  probeCipher: 'TLS_AES_256_GCM_SHA384',
  probeCertAlgo: 'ECDSA P-256',
}

export const SCANNERS = [
  {
    ix: '01',
    title: 'Source trees',
    body: 'AST-aware pattern matching across Python, Java, C#, Go, TypeScript, Rust, C and shell. Records the call site, not the file.',
    tags: ['python', 'java', 'c#', 'go', 'ts', 'rust', 'c'],
  },
  {
    ix: '02',
    title: 'Certificates & keys',
    body: 'Parses X.509 and PEM key material: algorithm, key size, signature algorithm, validity window. Shelf-life comes from notAfter where it exists.',
    tags: ['x.509', 'pkcs#8', 'pem', 'ssh', 'jwks'],
  },
  {
    ix: '03',
    title: 'Container images',
    body: 'Reads OCI and Docker save tarballs layer by layer without a daemon. Attributes each finding to the layer that introduced it.',
    tags: ['oci', 'docker save', 'per-layer'],
  },
  {
    ix: '04',
    title: 'Compiled binaries',
    body: 'Symbol and string extraction over ELF, Mach-O and PE. Finds the crypto a dependency statically linked in when the manifest does not mention it.',
    tags: ['elf', 'mach-o', 'pe', 'symbols'],
  },
  {
    ix: '05',
    title: 'Dependency manifests',
    body: 'requirements.txt, package.json, pom.xml, go.mod, Cargo.toml. Version-aware: BouncyCastle 1.79 is flagged, 1.80 is not.',
    tags: ['pip', 'npm', 'maven', 'go', 'cargo'],
  },
  {
    ix: '06',
    title: 'Live TLS endpoints',
    body: 'Real handshakes. Negotiated version, cipher suite, key-exchange group, whether legacy versions are still accepted, and the served chain.',
    tags: ['tls 1.0–1.3', 'kex group', 'chain'],
  },
]

/** Console views, described by the question each one answers. Order matches the
 *  nav in App.tsx. */
export const VIEWS = [
  ['Discovery', 'What is in the estate?', 'Pick targets, watch findings stream in with file paths as the walk proceeds.'],
  ['Overview', 'How bad is it?', 'Severity, quantum impact, and the business-criticality heatmap. Click a cell to open exactly those artefacts.'],
  ['Services', 'Which application is worst?', 'Per-service rollup: risk, effort, worst finding, whether any PQC is present at all.'],
  ['Inventory', 'Where precisely?', 'Every artefact, filterable, with an evidence drawer showing file, line, snippet and risk derivation.'],
  ['Compliance', 'Are we within mandate?', 'Each artefact against NIST IR 8547, CNSA 2.0 and SP 800-131A, with the year each one falls foul.'],
  ['Alternatives', 'What do we replace it with?', 'Candidate PQC algorithms scored per workload, with wire cost, CPU cost and the reason each loser lost.'],
  ['Mosca', 'How much rests on assumptions?', 'Move the CRQC year, shelf-life, migration time and headcount; watch findings flip in milliseconds.'],
  ['Roadmap', 'In what order, at what cost?', 'Dependency-ordered waves against the horizon, costed in engineer-days.'],
  ['Live probe', 'What is really on the wire?', 'Actual TLS handshakes against real hosts, not an assumption about them.'],
  ['Knowledge base', 'Why that classification?', `${PROOF.algorithms} algorithms with NIST status, strengths and OIDs, plus a cipher-suite resolver.`],
] as const
