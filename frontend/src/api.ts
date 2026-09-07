/** Thin API client. Every call the console makes lives here so the surface the
 *  frontend depends on is auditable in one file. */

export type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Evidence {
  file_path: string
  line?: number | null
  snippet?: string | null
  container_layer?: string | null
}

export interface Recommendation {
  target: string
  hybrid?: string | null
  action: string
  standard?: string
  effort_days?: number
  wire_delta_bytes?: number
  target_perf?: Record<string, number>
  note?: string
}

export interface Artifact {
  id: string
  artifact_type: string
  name: string
  category: string
  source: string
  evidence: Evidence
  properties: Record<string, unknown>
  quantum_impact: string
  quantum_year?: number | null
  severity: Sev
  risk_score: number
  mosca_violated?: boolean | null
  mosca_margin_years?: number | null
  migration_months?: number | null
  hndl_exposure?: number | null
  recommendation?: Recommendation | null
  business_criticality: string
  lifetime_years?: number | null
}

export interface Summary {
  scan_id: string
  started_at: string
  finished_at?: string | null
  targets: number
  files_scanned: number
  artifacts_found: number
  by_severity: Record<string, number>
  by_type: Record<string, number>
  by_impact: Record<string, number>
  quantum_vulnerable_pct: number
  mosca_violations: number
  migration_effort_days: number
  duration_seconds: number
  status: string
}

export interface Wave {
  wave: number
  title: string
  rationale: string
  artifact_count: number
  work_units: number
  effort_days: number
  mosca_violations: number
  critical_or_high: number
  targets: string[]
  artifact_ids: string[]
  top_findings: {
    id: string; name: string; severity: Sev; risk_score: number
    location: string; line?: number | null; target?: string | null; hybrid?: string | null
  }[]
  start_month?: number
  end_month?: number
}

export interface Schedule {
  engineers: number
  days_per_engineer_month?: number
  total_days: number
  total_months: number
  finish_year: number
  finish_label: string
  crqc_year: number
  meets_deadline: boolean
  slack_years: number
}

export interface Plan {
  waves: Wave[]
  total_effort_days: number
  total_work_units: number
  nothing_to_do: number
  schedule: Schedule
}

export interface ScanDetail {
  scan_id: string
  config: { targets: { path: string; kind: string }[]; crqc_year: number; organization: string }
  summary: Summary
  plan: Plan
  exposure_matrix: { criticality: string; impact: string; count: number; max_risk: number }[]
  algorithms: { name: string; count: number; impact: string; max_risk: number; target?: string | null }[]
  probes: unknown[]
  artifact_count: number
  exports: { cbom: string; sarif: string; report: string }
}

export interface ScanRow {
  scan_id: string
  organization: string
  started_at: string
  artifacts: number
  quantum_vulnerable_pct: number
  mosca_violations: number
  crqc_year: number
  targets: string[]
  status: string
}

export interface CorpusNode { path: string; name: string; kind: string; children?: CorpusNode[] }

export interface SimResult {
  assumptions: { crqc_year: number; data_lifetime_years: number; migration_months: number; years_until_crqc: number }
  summary: {
    artifacts: number
    by_severity: Record<string, number>
    by_impact: Record<string, number>
    mosca_violations: number
    mosca_violation_pct: number
    quantum_vulnerable_pct: number
    migration_effort_days: number
    top_risks: { id: string; name: string; risk_score: number; location: string; severity: Sev }[]
  }
  plan: Plan
}

export interface CurvePoint {
  crqc_year: number
  mosca_violations: number
  mosca_violation_pct: number
  critical: number
  high: number
  total_effort_days: number
  meets_deadline: boolean
}

export interface ProbeResult {
  probe: {
    host: string; port: number; sni: string; reachable: boolean
    accepted_versions: string[]; rejected_versions: string[]
    negotiated_version?: string | null; cipher?: string | null
    default_group?: string | null; pqc_group?: string | null
    pqc_hybrid_supported?: boolean | null; pqc_probe_supported: boolean
    certificate?: Record<string, unknown> | null
    error?: string | null; probe_notes?: string[]
  }
  artifacts: Artifact[]
}

/* -------------------------------------------------------------- services */

export interface ServiceRow {
  service: string
  kind: string
  artifacts: number
  files: number
  by_severity: Record<string, number>
  by_impact: Record<string, number>
  worst_severity: Sev
  max_risk: number
  mean_risk: number
  mosca_violations: number
  effort_days: number
  work_units: number
  business_criticality: string
  top_algorithms: { name: string; count: number; impact: string }[]
  pqc_present: boolean
  languages: string[]
  risk_rank: number
  worst_finding?: {
    id: string; name: string; severity: Sev; risk_score: number
    location: string; line?: number | null; target?: string | null
  } | null
}

export interface ServicesResponse {
  scan_id: string
  services: ServiceRow[]
  totals: {
    services: number; artifacts: number; effort_days: number
    unattributed: number; with_pqc: number
  }
}

/* ------------------------------------------------------------ compliance */

export type ComplianceStatus =
  'disallowed' | 'deprecated' | 'action_required' | 'compliant' | 'not_applicable'

export interface Verdict {
  standard: string
  standard_short: string
  control: string
  status: ComplianceStatus
  deadline_year?: number | null
  years_remaining?: number | null
  note: string
  confidence: 'published' | 'draft' | 'reported'
}

export interface StandardBlock {
  standard: string
  standard_short: string
  url_or_ref: string
  document_status: string
  summary: string
  counts_by_status: Record<ComplianceStatus, number>
  assessed: number
  compliant_pct: number | null
  failing: number
  offenders: {
    id: string; name: string; severity: Sev; risk_score: number
    location: string; line?: number | null; status: ComplianceStatus
    control: string; note: string; deadline_year?: number | null
    confidence: string
  }[]
}

export interface ComplianceReport {
  as_of_year: number
  artifacts_assessed: number
  standards: StandardBlock[]
  deadline_buckets: {
    year: number; standard_short: string
    artifacts_falling_foul: number; cumulative: number
  }[]
  posture: {
    score: number
    band: 'critical' | 'weak' | 'partial' | 'strong'
    headline: string
    basis: string
    failing_artifacts: number
    disallowed_artifacts: number
  }
  worst_first: {
    id: string; name: string; severity: Sev; risk_score: number
    location: string; line?: number | null; status: ComplianceStatus
    deadline_year?: number | null; criticality: string
    mosca_violated?: boolean | null
  }[]
}

/* ----------------------------------------------------------- alternatives */

export interface WorkloadProfile {
  key: string
  label: string
  description: string
  wire_budget_bytes: number | null
  cpu_budget_ms: number | null
  min_nist_level: number
  hybrid_required: boolean | null
  stateful_ok: boolean
  notes: string
  mandated?: string[]
  prefer?: string[]
}

export interface Candidate {
  rank: number
  name: string
  verdict: 'recommended' | 'viable' | 'rejected'
  score: number
  nist_level: number
  nist_status: string
  hybrid: boolean
  stateful: boolean
  wire_bytes: number | null
  wire_delta_bytes: number | null
  ops_ms: number | null
  ops_delta_ratio: number | null
  handshake_delta_note: string
  reasons: string[]
  blockers: string[]
  interop_note: string
  standard_ref: string
}

export interface Advice {
  input: {
    algorithm: string; canonical: string; recognised: boolean
    profile: string; shelf_life_years: number | null
    min_nist_level_applied: number
  }
  current: {
    name: string; impact: string; classical_bits: number; pq_bits: number
    nist_status: string; primitive: string
    perf?: Record<string, number> | null; wire_bytes: number | null
  } | null
  profile: WorkloadProfile
  role: string
  candidates: Candidate[]
  decision: {
    choose: string | null; because: string
    runner_up: string | null; tradeoff: string | null
  }
  assumptions: string[]
}

export interface AlternativesRollup {
  scan_id: string
  by_algorithm: {
    current: string; uses: number; files: number; impact: string
    profile_used: string; profile_label: string; choose: string | null
    wire_delta_bytes: number | null; total_wire_delta_bytes: number
    effort_days: number; runner_up: string | null
    because: string; tradeoff: string | null; rejected_count: number
  }[]
  wire_impact: {
    total_added_bytes_per_op: number
    worst_offender: string | null
    note: string
  }
  profile_inference: { inferred_profile: string; why: string }[]
  coverage: {
    algorithms_seen: number; advised: number; unadvised: number
    unadvised_names: string[]; note: string
  }
}

async function j<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init)
  if (!r.ok) throw new Error(`${r.status} ${r.statusText} — ${url}`)
  return r.json() as Promise<T>
}

const post = (body: unknown): RequestInit =>
  ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })

export const api = {
  health: () => j<{ status: string; current_year: number; algorithms: number; scans_stored: number }>('/api/health'),
  corpus: () => j<{ root: string; targets: CorpusNode[] }>('/api/corpus'),
  scans: () => j<{ scans: ScanRow[] }>('/api/scans?limit=40'),
  scan: (id: string) => j<ScanDetail>(`/api/scans/${id}`),
  artifacts: (id: string, params: Record<string, string>) =>
    j<{ total: number; offset: number; artifacts: Artifact[] }>(
      `/api/scans/${id}/artifacts?${new URLSearchParams(params)}`),
  report: (id: string) => fetch(`/api/scans/${id}/report`).then(r => r.text()),
  del: (id: string) => j<{ removed: string[] }>(`/api/scans/${id}`, { method: 'DELETE' }),

  startScan: (body: {
    targets: { path: string; kind: string }[]; crqc_year: number; organization: string
    endpoints?: string[]
  }) => j<{ job_id: string; stream: string }>('/api/scan', post(body)),
  cancel: (job: string) => j<unknown>(`/api/scan/${job}/cancel`, { method: 'POST' }),

  simulate: (body: {
    scan_id: string; crqc_year: number; data_lifetime_years?: number
    migration_months?: number; engineers?: number
  }) => j<SimResult>('/api/simulate', post(body)),

  curve: (id: string, from: number, to: number) =>
    j<{ curve: CurvePoint[] }>(`/api/scans/${id}/risk-curve?from_year=${from}&to_year=${to}`),

  kb: (q?: string) => j<{
    stats: { algorithms: number; aliases: number; by_impact: Record<string, number>; by_primitive: Record<string, number> }
    algorithms: { name: string; impact: string; family: string; primitive: string; classical_bits: number
      pq_bits: number; nist_pq_level: number; nist_status: string; note?: string; oid?: string }[]
  }>(`/api/knowledge-base${q ? `?q=${encodeURIComponent(q)}` : ''}`),

  resolve: (name: string) => j<{ input: string; canonical: string; recognised: boolean; entry: Record<string, unknown> | null }>(
    `/api/knowledge-base/resolve?name=${encodeURIComponent(name)}`),

  probe: (endpoints: string[]) =>
    j<{ results: ProbeResult[] }>('/api/probe', post({ endpoints, timeout: 6 })),

  services: (id: string) => j<ServicesResponse>(`/api/scans/${id}/services`),

  compliance: (id: string, year?: number) =>
    j<ComplianceReport>(`/api/scans/${id}/compliance${year ? `?year=${year}` : ''}`),

  artifactCompliance: (id: string, artifactId: string) =>
    j<{ artifact: Artifact; verdicts: Verdict[] }>(
      `/api/scans/${id}/compliance/${artifactId}`),

  profiles: () => j<{ default: string; profiles: WorkloadProfile[] }>(
    '/api/workload-profiles'),

  advise: (algorithm: string, profile: string, shelfLife?: number) =>
    j<Advice>(`/api/advise?algorithm=${encodeURIComponent(algorithm)}` +
              `&profile=${encodeURIComponent(profile)}` +
              (shelfLife ? `&shelf_life_years=${shelfLife}` : '')),

  alternatives: (id: string) =>
    j<AlternativesRollup>(`/api/scans/${id}/alternatives`),
}

export const SEVS: Sev[] = ['critical', 'high', 'medium', 'low', 'info']

export const IMPACT_LABEL: Record<string, string> = {
  shor_broken: 'Shor-broken',
  grover: 'Grover-weakened',
  broken_classically: 'Already broken',
  classical_ok: 'Quantum-adequate',
  pq_safe: 'PQC',
  unknown: 'Unclassified',
}

/** Compliance status labels. Written out because "action_required" is a wire
 *  value, not a sentence a reviewer should have to read. */
export const STATUS_LABEL: Record<string, string> = {
  disallowed: 'Disallowed',
  deprecated: 'Deprecated',
  action_required: 'Action required',
  compliant: 'Compliant',
  not_applicable: 'Not applicable',
}

/** Status to token colour. Disallowed shares the alert colour with critical
 *  severity deliberately: both mean "this is broken now, not later". */
export const STATUS_COLOR: Record<string, string> = {
  disallowed: 'var(--crit)',
  deprecated: 'var(--high)',
  action_required: 'var(--med)',
  compliant: 'var(--safe)',
  not_applicable: 'var(--t4)',
}

export const fmt = {
  n: (v: number) => v.toLocaleString('en-US'),
  d: (v: number) => (v >= 1000 ? `${(v / 1000).toFixed(1)}k` : String(Math.round(v))),
  pct: (v: number) => `${v.toFixed(1)}%`,
  file: (p: string) => p.split('/').slice(-1)[0],
  dir: (p: string) => p.split('/').slice(0, -1).join('/'),
  time: (iso: string) => new Date(iso).toLocaleString(undefined,
    { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }),
  months: (m: number) => (m >= 12 ? `${(m / 12).toFixed(1)}y` : `${m.toFixed(0)}mo`),
  bytes: (v: number | null | undefined) =>
    v == null ? '—' : v >= 10000 ? `${(v / 1024).toFixed(1)} KiB` : `${v.toLocaleString('en-US')} B`,
  delta: (v: number | null | undefined) =>
    v == null ? '—' : `${v > 0 ? '+' : ''}${v.toLocaleString('en-US')}`,
}
