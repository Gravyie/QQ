"""API contract tests against the real FastAPI app.

These exercise the same endpoints the console calls, using a temporary results
directory so the tests never touch the developer's stored scans. If a field the
frontend reads disappears, this suite fails rather than the UI silently
rendering `undefined`.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

pytest.importorskip('fastapi')
from fastapi.testclient import TestClient

import server
from atlas.models import ScanConfig
from atlas.engine import ScanEngine

CORPUS = Path(__file__).resolve().parents[2] / 'corpus' / 'estate'


@pytest.fixture(scope='module')
def client(tmp_path_factory):
    """A client backed by an isolated results directory holding one real scan."""
    results = tmp_path_factory.mktemp('results')
    server.RESULTS = results
    cfg = ScanConfig(targets=[{'path': str(CORPUS), 'kind': 'source'}],
                     crqc_year=2033, organization='API Test Bank')
    ScanEngine(cfg, results).run()
    with TestClient(server.app) as c:
        yield c


@pytest.fixture(scope='module')
def scan_id(client) -> str:
    rows = client.get('/api/scans').json()['scans']
    assert rows, 'fixture scan was not stored'
    return rows[0]['scan_id']


def test_health(client):
    d = client.get('/api/health').json()
    assert d['status'] == 'ok'
    assert d['algorithms'] > 100
    assert d['current_year'] >= 2026


def test_corpus_lists_targets(client):
    d = client.get('/api/corpus').json()
    assert d['targets'], 'no scan targets advertised'
    for t in d['targets']:
        assert Path(t['path']).exists()


def test_scan_produced_real_findings(client, scan_id):
    d = client.get(f'/api/scans/{scan_id}').json()
    s = d['summary']
    assert s['artifacts_found'] > 50
    assert s['files_scanned'] > 10
    assert sum(s['by_severity'].values()) == s['artifacts_found']
    assert sum(s['by_impact'].values()) == s['artifacts_found']
    assert sum(s['by_type'].values()) == s['artifacts_found']
    assert s['status'] == 'complete'


def test_scan_detail_carries_every_field_the_console_reads(client, scan_id):
    d = client.get(f'/api/scans/{scan_id}').json()
    assert {'scan_id', 'config', 'summary', 'plan', 'exposure_matrix',
            'algorithms', 'exports'} <= d.keys()
    sched = d['plan']['schedule']
    # These exact keys are read by the Overview, Simulator and Roadmap views.
    for k in ('engineers', 'total_months', 'finish_year', 'finish_label',
              'crqc_year', 'meets_deadline', 'slack_years'):
        assert k in sched, f'schedule is missing {k}'
    assert 'total_work_units' in d['plan']
    for w in d['plan']['waves']:
        assert 'start_month' in w and 'end_month' in w, 'timeline needs wave months'


def test_no_null_leaks_into_schedule(client, scan_id):
    """Regression: the console rendered "undefined engineers" when the planner
    exposed engineers_assumed but the UI read engineers."""
    sched = client.get(f'/api/scans/{scan_id}').json()['plan']['schedule']
    assert isinstance(sched['engineers'], int) and sched['engineers'] > 0
    assert isinstance(sched['finish_label'], str) and sched['finish_label']


def test_artifact_filters_compose(client, scan_id):
    all_n = client.get(f'/api/scans/{scan_id}/artifacts').json()['total']
    crit = client.get(f'/api/scans/{scan_id}/artifacts?severity=critical').json()
    assert 0 < crit['total'] < all_n
    assert all(a['severity'] == 'critical' for a in crit['artifacts'])

    mosca = client.get(f'/api/scans/{scan_id}/artifacts?mosca_only=true').json()
    assert all(a['mosca_violated'] for a in mosca['artifacts'])

    both = client.get(
        f'/api/scans/{scan_id}/artifacts?severity=critical&mosca_only=true').json()
    assert both['total'] <= min(crit['total'], mosca['total'])

    q = client.get(f'/api/scans/{scan_id}/artifacts?q=rsa').json()
    assert q['total'] > 0
    for a in q['artifacts']:
        blob = f"{a['name']}{a['evidence']['file_path']}{a['evidence'].get('snippet') or ''}".lower()
        assert 'rsa' in blob


def test_artifacts_sorted_by_risk(client, scan_id):
    arts = client.get(f'/api/scans/{scan_id}/artifacts?limit=60').json()['artifacts']
    scores = [a['risk_score'] for a in arts]
    assert scores == sorted(scores, reverse=True)


def test_every_artifact_has_evidence(client, scan_id):
    arts = client.get(f'/api/scans/{scan_id}/artifacts?limit=500').json()['artifacts']
    for a in arts:
        assert a['evidence']['file_path'], f'{a["name"]} has no evidence path'
        assert a['id'].startswith('ecdat-')


def test_exports_are_served(client, scan_id):
    cbom = client.get(f'/api/scans/{scan_id}/cbom').json()
    assert cbom['bomFormat'] == 'CycloneDX' and cbom['specVersion'] == '1.6'
    assert cbom['components']

    sarif = client.get(f'/api/scans/{scan_id}/sarif').json()
    assert sarif['version'] == '2.1.0'
    assert sarif['runs'][0]['results']

    report = client.get(f'/api/scans/{scan_id}/report')
    assert report.status_code == 200
    assert 'Quantum Atlas' in report.text


def test_simulate_responds_to_assumptions(client, scan_id):
    near = client.post('/api/simulate', json={
        'scan_id': scan_id, 'crqc_year': 2028, 'data_lifetime_years': 20,
        'migration_months': 36, 'engineers': 2}).json()
    far = client.post('/api/simulate', json={
        'scan_id': scan_id, 'crqc_year': 2050, 'data_lifetime_years': 1,
        'migration_months': 1, 'engineers': 20}).json()
    assert near['summary']['mosca_violations'] > far['summary']['mosca_violations']
    assert near['plan']['schedule']['total_months'] > far['plan']['schedule']['total_months']
    assert near['summary']['top_risks'], 'simulator needs top_risks for the UI table'
    assert 'migration_effort_days' in near['summary']


def test_simulate_does_not_mutate_the_stored_scan(client, scan_id):
    before = client.get(f'/api/scans/{scan_id}').json()['summary']
    client.post('/api/simulate', json={'scan_id': scan_id, 'crqc_year': 2027})
    after = client.get(f'/api/scans/{scan_id}').json()['summary']
    assert before == after


def test_simulate_rejects_out_of_range_assumptions(client, scan_id):
    r = client.post('/api/simulate', json={'scan_id': scan_id, 'crqc_year': 1999})
    assert r.status_code == 422


def test_risk_curve_is_monotonic(client, scan_id):
    curve = client.get(
        f'/api/scans/{scan_id}/risk-curve?from_year=2028&to_year=2044').json()['curve']
    v = [p['mosca_violations'] for p in curve]
    assert v == sorted(v, reverse=True)
    assert [p['crqc_year'] for p in curve] == list(range(2028, 2045))


def test_knowledge_base_and_resolver(client):
    kb = client.get('/api/knowledge-base?q=kyber').json()
    assert kb['stats']['algorithms'] > 100
    assert kb['algorithms']

    r = client.get('/api/knowledge-base/resolve?name=ECDHE-RSA-AES128-SHA256').json()
    assert r['recognised'] and r['canonical'] == 'ECDH'

    bad = client.get('/api/knowledge-base/resolve?name=not-a-real-cipher').json()
    assert bad['recognised'] is False, 'resolver must not invent a match'


def test_knowledge_base_filter_matches_aliases_and_status(client):
    """A search for a legacy spelling must find the standardised entry.

    An analyst reading a 2023 config types "kyber", not "ML-KEM-768". If the
    filter only matched canonical names, the KB would look like it had no entry
    for the thing they are holding.
    """
    kyber = client.get('/api/knowledge-base?q=kyber').json()['algorithms']
    names = {a['name'] for a in kyber}
    assert 'Kyber' in names, 'the searched-for name itself must be present'
    assert 'ML-KEM-768' in names, f'alias search missed ML-KEM-768, got {sorted(names)}'
    hit = next(a for a in kyber if a['name'] == 'ML-KEM-768')
    assert hit.get('matched_because') or hit.get('matched_aliases'), (
        'a row the user did not literally search for must say why it is here')
    assert 'Kyber' in (hit.get('matched_because') or ''), (
        f'ML-KEM-768 should be labelled as the Kyber replacement, got {hit.get("matched_because")}')

    disallowed = client.get('/api/knowledge-base?q=disallowed').json()['algorithms']
    assert {'MD5', 'SHA-1', '3DES', 'RC4'} <= {a['name'] for a in disallowed}

    empty = client.get('/api/knowledge-base?q=zzzznotathing').json()['algorithms']
    assert empty == [], 'filter must return nothing rather than falling back to all'


def test_resolver_exposes_full_suite_decomposition(client):
    """The API must show every component of a suite, flagging the scored one."""
    r = client.get(
        '/api/knowledge-base/resolve?name=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA').json()
    comps = r['components']
    assert {c['role'] for c in comps} == {
        'key exchange', 'authentication', 'bulk cipher', 'mac'}
    scored = [c['name'] for c in comps if c['weakest']]
    assert scored == [r['canonical']] == ['ECDH']
    assert 'RSA' in {c['name'] for c in comps}, 'RSA must not vanish from the suite'

    # A bare primitive is not a suite: no decomposition table.
    assert client.get('/api/knowledge-base/resolve?name=AES-256-GCM').json()['components'] == []


def test_unknown_scan_returns_404(client):
    assert client.get('/api/scans/does-not-exist').status_code == 404
    assert client.get('/api/scans/does-not-exist/cbom').status_code == 404


def test_scan_stream_completes(client):
    """Drive a real scan through the SSE endpoint and assert it terminates with
    a complete event carrying a summary."""
    started = client.post('/api/scan', json={
        'targets': [{'path': str(CORPUS / 'payments-service'), 'kind': 'source'}],
        'crqc_year': 2033, 'organization': 'Stream Test'}).json()
    job = started['job_id']

    saw_artifact = False
    complete = None
    with client.stream('GET', f'/api/scan/{job}/stream') as r:
        for line in r.iter_lines():
            if not line or not line.startswith('data: '):
                continue
            msg = json.loads(line[6:])
            if msg['type'] == 'artifact':
                saw_artifact = True
            elif msg['type'] == 'complete':
                complete = msg
                break
            elif msg['type'] == 'error':
                pytest.fail(f'scan errored: {msg}')

    assert saw_artifact, 'stream produced no artifact events'
    assert complete and complete['summary']['artifacts_found'] > 0
    assert complete['plan']['waves']


def test_delete_removes_every_export(client):
    started = client.post('/api/scan', json={
        'targets': [{'path': str(CORPUS / 'edge-api'), 'kind': 'source'}],
        'crqc_year': 2033, 'organization': 'Delete Test'}).json()
    with client.stream('GET', f'/api/scan/{started["job_id"]}/stream') as r:
        sid = None
        for line in r.iter_lines():
            if line.startswith('data: '):
                m = json.loads(line[6:])
                if m['type'] == 'complete':
                    sid = m['scan_id']
                    break
    assert sid
    removed = client.delete(f'/api/scans/{sid}').json()['removed']
    assert any(n.endswith('.cbom.json') for n in removed)
    assert any(n.endswith('.sarif.json') for n in removed)
    assert client.get(f'/api/scans/{sid}').status_code == 404


# ---------------------------------------------------------------- services

def test_services_endpoint_accounts_for_every_artifact(client, scan_id):
    d = client.get(f'/api/scans/{scan_id}/services').json()
    total = client.get(f'/api/scans/{scan_id}').json()['summary']['artifacts_found']
    assert d['services']
    assert d['totals']['artifacts'] == total
    assert sum(s['artifacts'] for s in d['services']) == total
    # Fields the Services view reads. A missing one renders as `undefined`.
    for s in d['services']:
        for k in ('service', 'kind', 'artifacts', 'files', 'by_severity',
                  'worst_severity', 'max_risk', 'mean_risk', 'mosca_violations',
                  'effort_days', 'business_criticality', 'top_algorithms',
                  'pqc_present', 'languages', 'risk_rank'):
            assert k in s, f'service row missing {k}'


def test_services_are_ranked_by_risk(client, scan_id):
    rows = client.get(f'/api/scans/{scan_id}/services').json()['services']
    assert [r['risk_rank'] for r in rows] == list(range(1, len(rows) + 1))
    assert rows == sorted(rows, key=lambda r: (-r['max_risk'], -r['artifacts'],
                                               r['service']))


def test_services_404_on_unknown_scan(client):
    assert client.get('/api/scans/nope/services').status_code == 404


# -------------------------------------------------------------- compliance

def test_compliance_endpoint_shape(client, scan_id):
    d = client.get(f'/api/scans/{scan_id}/compliance').json()
    assert d['artifacts_assessed'] > 50
    assert len(d['standards']) >= 3
    assert d['posture']['band'] in ('critical', 'weak', 'partial', 'strong')
    assert 0 <= d['posture']['score'] <= 100
    assert d['posture']['basis'], 'a score with no stated basis is unauditable'
    for s in d['standards']:
        for k in ('standard', 'standard_short', 'document_status', 'summary',
                  'counts_by_status', 'compliant_pct', 'failing', 'offenders'):
            assert k in s, f'standard row missing {k}'


def test_compliance_year_parameter_moves_the_cliff(client, scan_id):
    now = client.get(f'/api/scans/{scan_id}/compliance?year=2026').json()
    later = client.get(f'/api/scans/{scan_id}/compliance?year=2036').json()
    def disallowed(rep):
        return sum(s['counts_by_status']['disallowed'] for s in rep['standards'])
    assert disallowed(later) > disallowed(now)


def test_per_artifact_compliance_includes_not_applicable(client, scan_id):
    arts = client.get(f'/api/scans/{scan_id}/artifacts?limit=1').json()['artifacts']
    aid = arts[0]['id']
    d = client.get(f'/api/scans/{scan_id}/compliance/{aid}').json()
    assert d['artifact']['id'] == aid
    assert d['verdicts']
    shorts = {v['standard_short'] for v in d['verdicts']}
    assert len(shorts) >= 3, 'every modelled mandate should render a verdict'
    for v in d['verdicts']:
        assert v['confidence'] in ('published', 'draft', 'reported')


def test_per_artifact_compliance_404s_on_unknown_artifact(client, scan_id):
    assert client.get(f'/api/scans/{scan_id}/compliance/nope').status_code == 404


def test_standards_registry_declares_draft_status(client):
    d = client.get('/api/standards').json()['standards']
    ir = next(s for s in d if s['standard_short'] == 'NIST IR 8547')
    assert ir['status'] == 'draft', 'IR 8547 must never be presented as final'


# -------------------------------------------------------------- alternatives

def test_workload_profiles_endpoint(client):
    d = client.get('/api/workload-profiles').json()
    keys = {p['key'] for p in d['profiles']}
    assert {'tls-frontend', 'firmware-signing', 'national-security'} <= keys
    assert d['default'] in keys
    for p in d['profiles']:
        for k in ('label', 'description', 'min_nist_level', 'stateful_ok', 'notes'):
            assert k in p


def test_advise_endpoint_returns_scored_candidates(client):
    d = client.get('/api/advise?algorithm=X25519&profile=tls-frontend').json()
    assert d['role'] == 'kem'
    assert d['decision']['choose'] == 'X25519MLKEM768'
    assert d['assumptions']
    for c in d['candidates']:
        assert c['verdict'] in ('recommended', 'viable', 'rejected')
        if c['verdict'] == 'rejected':
            assert c['blockers'], f'{c["name"]} rejected without a stated reason'


def test_advise_rejects_an_unknown_profile_with_400(client):
    r = client.get('/api/advise?algorithm=RSA&profile=not-real')
    assert r.status_code == 400


def test_alternatives_rollup_reports_coverage_honestly(client, scan_id):
    d = client.get(f'/api/scans/{scan_id}/alternatives').json()
    cov = d['coverage']
    assert cov['advised'] + cov['unadvised'] == cov['algorithms_seen']
    assert len(cov['unadvised_names']) == cov['unadvised']
    assert d['by_algorithm']
    for row in d['by_algorithm']:
        assert row['profile_used'] and row['because']
    assert 'note' in d['wire_impact']
