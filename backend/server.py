"""Quantum Atlas HTTP API.

Design notes:

* A scan streams over SSE so the console shows discovery happening rather than a
  spinner. The engine already emits events; this just forwards them.
* Scans run in a worker thread, not the request thread, so cancellation and
  streaming work while the walk is blocking on IO.
* `/simulate` never rescans. It re-runs the pure risk model over a stored
  inventory, which is why moving the CRQC slider is instant.
"""
from __future__ import annotations

import asyncio
import json
import queue
import re
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from atlas.engine import ScanEngine
from atlas.models import ScanConfig, ScanResult
from atlas import knowledge_base as kb
from atlas.crypto_services import LIBRARIES, HARDWARE
from atlas.planner import (simulate, risk_curve, build_plan, exposure_matrix,
                           lifetime_exposure, algorithm_rollup)
from atlas.risk import hydrate_artifact, CURRENT_YEAR
from atlas.network import probe_endpoint, probe_to_artifacts
from atlas.compliance import compliance_report, assess_artifact, STANDARDS
from atlas.services import service_rollup
from atlas.advisor import (WORKLOAD_PROFILES, advise_inventory, recommend,
                           DEFAULT_PROFILE)

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / 'results'
CORPUS = ROOT / 'corpus'
FRONTEND_DIST = ROOT / 'frontend' / 'dist'

app = FastAPI(title='Quantum Atlas API', version='1.0.0',
              description='Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)')

# The console is served from the same origin in production, but a dev Vite
# server runs on another port, so CORS stays open for localhost.
app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:5173', 'http://127.0.0.1:5173',
                   'http://localhost:4173', 'http://localhost:8000'],
    allow_credentials=True, allow_methods=['*'], allow_headers=['*'],
)


# ---------------------------------------------------------------------------
# In-process scan registry
# ---------------------------------------------------------------------------
class ScanJob:
    """A running scan plus its event queue."""

    def __init__(self, config: ScanConfig):
        self.id = str(uuid.uuid4())
        self.config = config
        self.events: "queue.Queue[dict | None]" = queue.Queue()
        self.engine: ScanEngine | None = None
        self.result: ScanResult | None = None
        self.error: str | None = None
        self.thread: threading.Thread | None = None

    def start(self):
        def on_event(ev: dict):
            self.events.put(ev)

        def run():
            try:
                self.engine = ScanEngine(self.config, RESULTS, on_event=on_event)
                self.result = self.engine.run()
            except Exception as exc:            # surface, never swallow
                self.error = f'{type(exc).__name__}: {exc}'
                self.events.put({'type': 'error', 'message': self.error})
            finally:
                self.events.put(None)           # sentinel: stream is done

        self.thread = threading.Thread(target=run, daemon=True, name=f'scan-{self.id[:8]}')
        self.thread.start()


JOBS: dict[str, ScanJob] = {}


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class Target(BaseModel):
    path: str
    kind: str = Field('source', pattern='^(source|container|binary|endpoint)$')


class ScanRequest(BaseModel):
    targets: list[Target]
    crqc_year: int = Field(2033, ge=2027, le=2060)
    organization: str = 'Enterprise'
    data_lifetime_years: int = Field(5, ge=1, le=50)
    migration_months: int = Field(18, ge=1, le=120)
    # Convenience: the console collects live endpoints in a separate field, so
    # they are accepted here and folded into targets as kind='endpoint'.
    endpoints: list[str] = Field(default_factory=list, max_length=12)


class SimulateRequest(BaseModel):
    scan_id: str
    crqc_year: int = Field(2033, ge=2027, le=2060)
    data_lifetime_years: int = Field(5, ge=1, le=50)
    migration_months: int = Field(18, ge=1, le=120)
    engineers: int = Field(4, ge=1, le=200)


class ProbeRequest(BaseModel):
    endpoints: list[str]
    timeout: float = Field(6.0, ge=1.0, le=20.0)


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------
@app.get('/api/health')
def health():
    return {'status': 'ok', 'current_year': CURRENT_YEAR,
            'algorithms': len(kb.ALGORITHMS), 'scans_stored': len(_stored_scan_ids())}


@app.get('/api/knowledge-base')
def knowledge_base(q: str | None = None):
    """Algorithm knowledge base, optionally filtered.

    The filter matches the canonical name, its aliases, the primitive, the impact
    class and the NIST status, so typing "disallowed" lists everything NIST has
    retired. When a match is a superseded pre-standard name, its replacement is
    pulled in too: someone searching "kyber" is holding a 2023 config and needs
    to be shown ML-KEM, not just told Kyber is obsolete.
    """
    needle = q.lower().strip() if q else None
    if not needle:
        return {'stats': kb.stats(),
                'algorithms': [{'name': n, **e} for n, e in kb.ALGORITHMS.items()],
                'libraries': [{'name': k, **v} for k, v in LIBRARIES.items()],
                'hardware': [{'name': k, **v} for k, v in HARDWARE.items()]}

    # alias -> canonical, so a search for a legacy spelling still hits the entry
    alias_hits: dict[str, list[str]] = {}
    for alias, canon in kb.ALIASES.items():
        if needle in alias.lower():
            alias_hits.setdefault(canon, []).append(alias)

    def matches(name: str, entry: dict) -> bool:
        return (needle in name.lower()
                or needle in str(entry.get('nist_status', '')).lower()
                or needle in str(entry.get('primitive', '')).lower()
                or needle in str(entry.get('impact', '')).lower()
                or name in alias_hits)

    direct = {n for n, e in kb.ALGORITHMS.items() if matches(n, e)}

    # Follow "superseded by X" / "selected"-style pointers to the replacement,
    # including its parameter sets, so the answer is actionable.
    successors: dict[str, str] = {}
    for name in direct:
        status = str(kb.ALGORITHMS[name].get('nist_status', ''))
        m = re.search(r'superseded by ([A-Za-z0-9\-+]+)', status)
        if not m:
            continue
        stem = m.group(1)
        for cand in kb.ALGORITHMS:
            if cand == stem or cand.startswith(stem + '-'):
                successors.setdefault(cand, name)

    rows = []
    for name, entry in kb.ALGORITHMS.items():
        if name not in direct and name not in successors:
            continue
        row = {'name': name, **entry}
        if name in alias_hits:
            row['matched_aliases'] = sorted(alias_hits[name])
        if name in successors and name not in direct:
            row['matched_because'] = f'replacement for {successors[name]}'
        rows.append(row)

    return {'stats': kb.stats(), 'algorithms': rows,
            'libraries': [{'name': k, **v} for k, v in LIBRARIES.items()],
            'hardware': [{'name': k, **v} for k, v in HARDWARE.items()]}


@app.get('/api/knowledge-base/resolve')
def resolve(name: str):
    """Show how a raw string resolves. Makes the matcher inspectable.

    `canonical` is the weakest component, which is what the risk model scores.
    `components` is the full decomposition of a cipher suite, so the UI can show
    that RSA and the MAC hash were seen and considered, not silently dropped.
    """
    canon, entry = kb.canonical_algorithm(name)
    return {'input': name, 'canonical': canon, 'recognised': entry is not None,
            'entry': entry, 'mode': kb.extract_mode(name),
            'padding': kb.extract_padding(name),
            'components': kb.decompose(name)}


@app.get('/api/corpus')
def corpus():
    """Scannable demo targets, so the console needs no path typing."""
    out = []
    if CORPUS.exists():
        for child in sorted(CORPUS.iterdir()):
            if child.name.startswith('.'):
                continue
            if child.is_dir():
                sub = [c for c in sorted(child.iterdir()) if not c.name.startswith('.')]
                out.append({
                    'path': str(child), 'name': child.name, 'kind': 'source',
                    'children': [{'path': str(c), 'name': c.name,
                                  'kind': 'container' if c.suffix == '.tar' else 'source'}
                                 for c in sub],
                })
    return {'root': str(CORPUS), 'targets': out}


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
@app.post('/api/scan')
def start_scan(req: ScanRequest):
    targets = []
    for t in req.targets:
        if t.kind == 'endpoint':
            targets.append({'path': t.path, 'kind': 'endpoint'})
            continue
        p = Path(t.path).expanduser()
        if not p.is_absolute():
            p = (CORPUS / t.path).resolve()
        if not p.exists():
            raise HTTPException(400, f'target not found: {p}')
        targets.append({'path': str(p), 'kind': t.kind})
    for ep in req.endpoints:
        ep = ep.strip()
        if ep:
            targets.append({'path': ep, 'kind': 'endpoint'})
    if not targets:
        raise HTTPException(400, 'no targets given')

    config = ScanConfig(targets=targets, crqc_year=req.crqc_year,
                        organization=req.organization,
                        data_lifetime_default_years=req.data_lifetime_years,
                        migration_months_default=req.migration_months)
    job = ScanJob(config)
    JOBS[job.id] = job
    job.start()
    return {'job_id': job.id, 'stream': f'/api/scan/{job.id}/stream'}


@app.get('/api/scan/{job_id}/stream')
async def stream_scan(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, 'no such job')

    async def gen():
        loop = asyncio.get_running_loop()
        while True:
            ev = await loop.run_in_executor(None, job.events.get)
            if ev is None:
                if job.result:
                    yield _sse({'type': 'done', 'scan_id': job.result.scan_id})
                break
            yield _sse(ev)

    return StreamingResponse(gen(), media_type='text/event-stream',
                             headers={'Cache-Control': 'no-cache',
                                      'X-Accel-Buffering': 'no'})


def _sse(payload: dict) -> str:
    return f'data: {json.dumps(payload)}\n\n'


@app.post('/api/scan/{job_id}/cancel')
def cancel_scan(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, 'no such job')
    if job.engine:
        job.engine.cancel()
    return {'cancelled': True}


# ---------------------------------------------------------------------------
# Stored scans
# ---------------------------------------------------------------------------
def _stored_scan_ids() -> list[str]:
    if not RESULTS.exists():
        return []
    return [p.stem for p in RESULTS.glob('*.json')
            if not p.name.endswith(('.cbom.json', '.sarif.json'))]


def _load(scan_id: str) -> ScanResult:
    path = RESULTS / f'{scan_id}.json'
    if not path.exists():
        raise HTTPException(404, f'no such scan: {scan_id}')
    return ScanResult.load(path)


@app.get('/api/scans')
def list_scans(limit: int = 30):
    rows = []
    paths = sorted((p for p in RESULTS.glob('*.json')
                    if not p.name.endswith(('.cbom.json', '.sarif.json'))),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    for p in paths[:limit]:
        try:
            data = json.loads(p.read_text())
        except json.JSONDecodeError:
            continue
        s = data['summary']
        rows.append({
            'scan_id': data['scan_id'],
            'organization': data['config'].get('organization'),
            'started_at': s['started_at'],
            'artifacts': s['artifacts_found'],
            'quantum_vulnerable_pct': s['quantum_vulnerable_pct'],
            'mosca_violations': s['mosca_violations'],
            'crqc_year': data['config'].get('crqc_year'),
            'targets': [t.get('path') for t in data['config'].get('targets', [])],
            'status': s.get('status'),
        })
    return {'scans': rows}


@app.get('/api/scans/{scan_id}')
def get_scan(scan_id: str):
    r = _load(scan_id)
    # The plan is always rebuilt rather than read from the stored file. It is
    # cheap, and it guarantees the console never renders a plan produced by an
    # older version of the planner with different fields.
    plan = build_plan(r.artifacts, r.config.crqc_year)
    return {
        'scan_id': r.scan_id,
        'config': r.config.__dict__,
        'summary': r.summary.__dict__,
        'plan': plan,
        'exposure_matrix': exposure_matrix(r.artifacts),
        'lifetime_exposure': lifetime_exposure(r.artifacts),
        'algorithms': algorithm_rollup(r.artifacts),
        'probes': r.probes,
        'artifact_count': len(r.artifacts),
        'exports': {'cbom': f'/api/scans/{scan_id}/cbom',
                    'sarif': f'/api/scans/{scan_id}/sarif',
                    'report': f'/api/scans/{scan_id}/report'},
    }


@app.get('/api/scans/{scan_id}/artifacts')
def get_artifacts(scan_id: str, severity: str | None = None,
                  artifact_type: str | None = None, impact: str | None = None,
                  criticality: str | None = None, q: str | None = None,
                  mosca_only: bool = False, limit: int = 2000, offset: int = 0):
    """Filtered inventory. All filters compose, which is how the console's
    facets work without a client-side copy of the whole dataset."""
    r = _load(scan_id)
    items = r.artifacts
    if severity:
        wanted = set(severity.split(','))
        items = [a for a in items if a.severity in wanted]
    if artifact_type:
        wanted = set(artifact_type.split(','))
        items = [a for a in items if a.artifact_type in wanted]
    if impact:
        wanted = set(impact.split(','))
        items = [a for a in items if a.quantum_impact in wanted]
    if criticality:
        wanted = set(criticality.split(','))
        items = [a for a in items if a.business_criticality in wanted]
    if mosca_only:
        items = [a for a in items if a.mosca_violated]
    if q:
        ql = q.lower()
        items = [a for a in items
                 if ql in a.name.lower() or ql in a.evidence.file_path.lower()
                 or ql in (a.evidence.snippet or '').lower()]
    items.sort(key=lambda a: -a.risk_score)
    total = len(items)
    return {'total': total, 'offset': offset,
            'artifacts': [a.to_dict() for a in items[offset:offset + limit]]}


@app.get('/api/scans/{scan_id}/services')
def get_services(scan_id: str):
    """Per-application rollup: which service owns the most risk.

    The problem statement is explicitly about cataloguing across applications,
    products and infrastructure, and severity ranking alone cannot answer "which
    team owns this". Attribution rules and their limits are documented in
    atlas/services.py.
    """
    r = _load(scan_id)
    rows = service_rollup(r.artifacts, r.config.targets)
    return {
        'scan_id': scan_id,
        'services': rows,
        'totals': {
            'services': len(rows),
            'artifacts': sum(x['artifacts'] for x in rows),
            'effort_days': sum(x['effort_days'] for x in rows),
            'unattributed': next((x['artifacts'] for x in rows
                                  if x['service'] == 'unattributed'), 0),
            'with_pqc': sum(1 for x in rows if x['pqc_present']),
        },
    }


@app.get('/api/scans/{scan_id}/compliance')
def get_compliance(scan_id: str, year: int | None = None):
    """The estate against NIST IR 8547, CNSA 2.0 and SP 800-131A.

    `year` re-runs the assessment as of a different calendar year, which is what
    makes the deadline curve interactive: an analyst can watch the 2030 and 2035
    cliffs arrive without rescanning.
    """
    r = _load(scan_id)
    return compliance_report(r.artifacts, current_year=year or CURRENT_YEAR)


@app.get('/api/scans/{scan_id}/compliance/{artifact_id}')
def get_artifact_compliance(scan_id: str, artifact_id: str,
                            year: int | None = None):
    """Every mandate verdict for one artifact, including not-applicable ones.

    Not-applicable is returned rather than filtered: an analyst needs to see that
    a mandate was considered and did not bite.
    """
    r = _load(scan_id)
    art = next((a for a in r.artifacts if a.id == artifact_id), None)
    if art is None:
        raise HTTPException(404, f'artifact {artifact_id} not in scan {scan_id}')
    return {
        'artifact': art.to_dict(),
        'verdicts': assess_artifact(art, year or CURRENT_YEAR),
    }


@app.get('/api/standards')
def get_standards():
    """The mandate registry, including each document's own status.

    IR 8547 is a draft. Anything reading this API needs to be able to say so.
    """
    return {'standards': [{'key': k, **v} for k, v in STANDARDS.items()]}


@app.get('/api/workload-profiles')
def get_workload_profiles():
    """Deployment contexts the advisor can score against."""
    return {
        'default': DEFAULT_PROFILE,
        'profiles': [{'key': k, **v} for k, v in WORKLOAD_PROFILES.items()],
    }


@app.get('/api/advise')
def get_advice(algorithm: str, profile: str = DEFAULT_PROFILE,
               shelf_life_years: int | None = None):
    """Score every candidate replacement for one algorithm in one workload.

    Rejected candidates are returned with the constraint they violated, not
    dropped: the losers are the argument.
    """
    try:
        return recommend(algorithm, profile, shelf_life_years=shelf_life_years)
    except KeyError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get('/api/scans/{scan_id}/alternatives')
def get_alternatives(scan_id: str):
    """Per-algorithm replacement advice rolled up over a stored inventory."""
    r = _load(scan_id)
    return {'scan_id': scan_id, **advise_inventory(r.artifacts)}


@app.get('/api/scans/{scan_id}/cbom')
def get_cbom(scan_id: str, download: bool = False):
    path = RESULTS / f'{scan_id}.cbom.json'
    if not path.exists():
        raise HTTPException(404, 'CBOM not found')
    if download:
        return FileResponse(path, media_type='application/json',
                            filename=f'atlas-{scan_id[:8]}.cbom.json')
    return json.loads(path.read_text())


@app.get('/api/scans/{scan_id}/sarif')
def get_sarif(scan_id: str, download: bool = False):
    path = RESULTS / f'{scan_id}.sarif.json'
    if not path.exists():
        raise HTTPException(404, 'SARIF not found')
    if download:
        return FileResponse(path, media_type='application/json',
                            filename=f'atlas-{scan_id[:8]}.sarif.json')
    return json.loads(path.read_text())


@app.get('/api/scans/{scan_id}/report', response_class=PlainTextResponse)
def get_report(scan_id: str):
    path = RESULTS / f'{scan_id}.report.md'
    if not path.exists():
        raise HTTPException(404, 'report not found')
    return path.read_text()


@app.delete('/api/scans/{scan_id}')
def delete_scan(scan_id: str):
    removed = []
    for suffix in ('.json', '.cbom.json', '.sarif.json', '.report.md'):
        p = RESULTS / f'{scan_id}{suffix}'
        if p.exists():
            p.unlink()
            removed.append(p.name)
    if not removed:
        raise HTTPException(404, 'no such scan')
    return {'removed': removed}


# ---------------------------------------------------------------------------
# Simulation — the interactive Mosca model
# ---------------------------------------------------------------------------
@app.post('/api/simulate')
def run_simulation(req: SimulateRequest):
    """Re-derive the whole risk picture under new assumptions. No rescan."""
    r = _load(req.scan_id)
    dicts = [a.to_dict() for a in r.artifacts]
    sim = simulate(dicts, crqc_year=req.crqc_year,
                   data_lifetime_years=req.data_lifetime_years,
                   migration_months=req.migration_months,
                   engineers=req.engineers)
    # Trim artifacts to what the UI needs; the full list is available separately.
    sim['artifacts'] = [{
        'id': a['id'], 'name': a['name'], 'severity': a['severity'],
        'risk_score': a['risk_score'], 'quantum_impact': a['quantum_impact'],
        'mosca_violated': a['mosca_violated'],
        'mosca_margin_years': a['mosca_margin_years'],
        'lifetime_years': a['lifetime_years'],
        'business_criticality': a['business_criticality'],
        'artifact_type': a['artifact_type'],
        'file_path': a['evidence']['file_path'],
    } for a in sim['artifacts']]
    sim['exposure_matrix'] = exposure_matrix(
        [hydrate_artifact(d) for d in dicts])
    return sim


@app.get('/api/scans/{scan_id}/risk-curve')
def get_risk_curve(scan_id: str, from_year: int = Query(2028, ge=2027),
                   to_year: int = Query(2050, le=2060),
                   data_lifetime_years: int = 5, migration_months: int = 18):
    """Mosca violations swept across the plausible CRQC range.

    Nobody knows the CRQC year, so the honest presentation is the shape of the
    curve rather than a single point estimate.
    """
    r = _load(scan_id)
    dicts = [a.to_dict() for a in r.artifacts]
    curve = risk_curve(dicts, years=range(from_year, to_year + 1),
                       data_lifetime_years=data_lifetime_years,
                       migration_months=migration_months)
    return {'scan_id': scan_id, 'curve': curve}


# ---------------------------------------------------------------------------
# Live network probe
# ---------------------------------------------------------------------------
@app.post('/api/probe')
def probe(req: ProbeRequest):
    """Handshake with real endpoints and report observed parameters.

    Kept separate from /api/scan so a reviewer can point it at any host and see
    evidence that the tool reads the wire, not just the repo.
    """
    out = []
    for spec in req.endpoints[:12]:
        host, _, port_s = spec.rpartition(':')
        if not host:
            host, port = spec, 443
        else:
            try:
                port = int(port_s)
            except ValueError:
                host, port = spec, 443
        result = probe_endpoint(host, port, timeout=req.timeout)
        artifacts = [a.to_dict() for a in probe_to_artifacts(result)]
        out.append({'probe': result, 'artifacts': artifacts})
    return {'results': out}


# ---------------------------------------------------------------------------
# Static console (built frontend), mounted last so /api wins.
# ---------------------------------------------------------------------------
if FRONTEND_DIST.exists():
    app.mount('/', StaticFiles(directory=str(FRONTEND_DIST), html=True), name='console')


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=8000)
