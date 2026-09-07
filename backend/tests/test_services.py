"""Service attribution tests.

Attribution is the part most likely to silently degrade: a path-prefix rule that
stops matching produces plausible-looking rows that are all wrong. So these tests
pin the rules explicitly and assert that nothing is dropped.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from atlas.models import Artifact, Evidence, ScanResult
from atlas.planner import build_plan, work_unit_effort
from atlas.services import attribute, service_rollup

RESULTS = Path(__file__).resolve().parent.parent.parent / 'results'
ESTATE_SCAN = '9a839012-dceb-48f3-b964-a4859d14f580'
ROOT = '/repo/corpus/estate'
TARGETS = [{'path': ROOT, 'kind': 'source'}]


def art(path, name='RSA', *, artifact_type='algorithm-use', category='signature',
        risk=7.0, severity='high', props=None, rec=None,
        impact='shor_broken', criticality='high', mosca=False) -> Artifact:
    return Artifact(
        artifact_type=artifact_type, name=name, category=category,
        source='source-code', evidence=Evidence(file_path=path, line=1),
        properties=props or {}, quantum_impact=impact, severity=severity,
        risk_score=risk, business_criticality=criticality,
        mosca_violated=mosca, recommendation=rec,
    )


# -------------------------------------------------------------- attribution

def test_nested_path_attributes_to_the_first_segment():
    a = art(f'{ROOT}/payments-service/src/tokens.py')
    assert attribute(a, [ROOT]) == ('payments-service', 'source')


def test_deeply_nested_path_still_attributes_to_one_segment():
    a = art(f'{ROOT}/auth-service/src/main/java/com/meridian/Vault.java')
    assert attribute(a, [ROOT])[0] == 'auth-service'


def test_root_level_file_attributes_to_the_target_itself():
    a = art(f'{ROOT}/README.md')
    assert attribute(a, [ROOT]) == ('estate', 'source')


def test_infrastructure_directories_keep_two_levels():
    """`infra` alone would collapse the PKI, the TLS config and the bastion into
    one row and hide the distinction an operator needs."""
    pki = art(f'{ROOT}/infra/pki/ca/root-ca.pem')
    ssl = art(f'{ROOT}/infra/openssl/openssl.cnf')
    assert attribute(pki, [ROOT]) == ('infra/pki', 'infrastructure')
    assert attribute(ssl, [ROOT]) == ('infra/openssl', 'infrastructure')


def test_tls_endpoint_attributes_to_the_host():
    a = art('tls://cloudflare.com:443', 'TLSv1.3', artifact_type='tls-endpoint',
            category='protocol', props={'endpoint': 'cloudflare.com:443'})
    assert attribute(a, [ROOT]) == ('cloudflare.com', 'endpoint')


def test_tls_endpoint_falls_back_to_the_evidence_path():
    a = art('tls://github.com:443', 'TLSv1.3', artifact_type='tls-endpoint',
            category='protocol')
    assert attribute(a, [ROOT]) == ('github.com', 'endpoint')


def test_container_image_attributes_to_the_image_name():
    a = art(f'{ROOT}/images/payments-gateway-3.4.1.tar', 'openssl',
            artifact_type='container-image', category='library')
    assert attribute(a, [ROOT]) == ('payments-gateway-3.4.1', 'container')


def test_binary_attributes_to_its_own_filename():
    a = art(f'{ROOT}/binaries/settlement-daemon', 'libcrypto',
            artifact_type='binary', category='library-binary')
    assert attribute(a, [ROOT]) == ('settlement-daemon', 'binary')


def test_unattributable_artifact_is_bucketed_not_dropped():
    a = art('/somewhere/else/entirely/app.py')
    assert attribute(a, [ROOT]) == ('unattributed', 'unknown')


def test_cloud_and_hardware_are_grouped_by_kind():
    kms = art('terraform/main.tf', 'AWS KMS', artifact_type='cloud-service',
              category='service')
    hsm = art('config/hsm.cfg', 'PKCS#11 HSM interface',
              artifact_type='hardware', category='hardware')
    assert attribute(kms, [ROOT]) == ('cloud services', 'cloud')
    assert attribute(hsm, [ROOT]) == ('hardware modules', 'hardware')


# ------------------------------------------------------------------- rollup

def test_rollup_never_drops_an_artifact():
    arts = [
        art(f'{ROOT}/payments-service/src/a.py'),
        art(f'{ROOT}/payments-service/src/b.py'),
        art(f'{ROOT}/infra/pki/ca/root.pem'),
        art('/elsewhere/x.py'),
    ]
    rows = service_rollup(arts, TARGETS)
    assert sum(r['artifacts'] for r in rows) == len(arts)
    assert 'unattributed' in {r['service'] for r in rows}


def test_effort_is_deduplicated_by_file_and_target():
    """Two findings on one line of one file are one edit, not two."""
    rec = {'target': 'ML-KEM-768', 'effort_days': 15}
    same_file = [
        art(f'{ROOT}/svc/src/a.py', 'AES-128', rec=rec),
        art(f'{ROOT}/svc/src/a.py', 'AES-CBC', rec=rec),
    ]
    two_files = [
        art(f'{ROOT}/svc/src/a.py', 'AES-128', rec=rec),
        art(f'{ROOT}/svc/src/b.py', 'AES-128', rec=rec),
    ]
    assert service_rollup(same_file, TARGETS)[0]['effort_days'] == 15
    assert service_rollup(same_file, TARGETS)[0]['work_units'] == 1
    assert service_rollup(two_files, TARGETS)[0]['effort_days'] == 30
    assert service_rollup(two_files, TARGETS)[0]['work_units'] == 2


def test_rollup_is_sorted_worst_first_and_ranked():
    arts = [
        art(f'{ROOT}/low/a.py', risk=2.0, severity='low'),
        art(f'{ROOT}/high/a.py', risk=9.5, severity='critical'),
        art(f'{ROOT}/mid/a.py', risk=6.0, severity='medium'),
    ]
    rows = service_rollup(arts, TARGETS)
    assert [r['service'] for r in rows] == ['high', 'mid', 'low']
    assert [r['risk_rank'] for r in rows] == [1, 2, 3]


def test_pqc_presence_and_language_detection():
    arts = [
        art(f'{ROOT}/pilot/src/kem.py', 'ML-KEM-768', category='kem',
            impact='pq_safe', severity='info', risk=0.8),
        art(f'{ROOT}/pilot/src/Legacy.java', 'RSA'),
    ]
    row = service_rollup(arts, TARGETS)[0]
    assert row['pqc_present'] is True
    assert set(row['languages']) == {'python', 'java'}


def test_worst_severity_and_criticality_take_the_highest_seen():
    arts = [
        art(f'{ROOT}/svc/a.py', severity='low', risk=2.0, criticality='low'),
        art(f'{ROOT}/svc/b.py', severity='critical', risk=9.0, criticality='critical'),
    ]
    row = service_rollup(arts, TARGETS)[0]
    assert row['worst_severity'] == 'critical'
    assert row['business_criticality'] == 'critical'
    assert row['max_risk'] == 9.0
    assert row['mean_risk'] == 5.5


def test_rollup_works_without_a_target_list():
    """A stored scan opened directly has no target list; attribution must still
    produce one row per service rather than one per absolute path."""
    arts = [
        art(f'{ROOT}/payments-service/src/a.py'),
        art(f'{ROOT}/auth-service/src/b.java'),
    ]
    rows = service_rollup(arts, None)
    assert {r['service'] for r in rows} == {'payments-service', 'auth-service'}


# --------------------------------------------------------- against real data

@pytest.fixture(scope='module')
def estate() -> ScanResult:
    return ScanResult.load(RESULTS / f'{ESTATE_SCAN}.json')


def test_real_estate_rolls_up_to_named_services(estate):
    rows = service_rollup(estate.artifacts, estate.config.targets)
    names = {r['service'] for r in rows}
    assert 'payments-service' in names
    assert 'treasury-archive' in names
    assert 'infra/pki' in names
    assert sum(r['artifacts'] for r in rows) == len(estate.artifacts)


def test_service_effort_reconciles_with_the_wave_plan(estate):
    """The per-service total and the wave total are the same money. If these two
    ever disagree, one of them is lying to a programme manager."""
    rows = service_rollup(estate.artifacts, estate.config.targets)
    plan = build_plan(estate.artifacts, estate.config.crqc_year)
    assert sum(r['effort_days'] for r in rows) == plan['total_effort_days']


def test_work_unit_effort_is_the_shared_implementation():
    rec = {'target': 'ML-DSA-65', 'effort_days': 45}
    arts = [art(f'{ROOT}/a/x.py', 'RSA', rec=rec),
            art(f'{ROOT}/a/x.py', 'RSA-PSS', rec=rec),
            art(f'{ROOT}/a/y.py', 'RSA', rec=rec)]
    assert work_unit_effort(arts) == (90, 2)
