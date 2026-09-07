"""Risk model tests: Mosca, impact resolution, severity, recommendations.

These are the numbers a reviewer will challenge, so each test pins a specific
claim rather than asserting the code merely runs.
"""
from __future__ import annotations

import pytest

from atlas.models import Artifact, Evidence, ArtifactType, DiscoverySource
from atlas.risk import (analyze, mosca_check, resolve_impact, estimate_lifetime,
                        estimate_migration_months, infer_criticality,
                        build_recommendation, hndl_exposure, CURRENT_YEAR,
                        _version_at_least)


def make(name, category='signature', atype='algorithm-use', path='/estate/app/src/x.py',
         line=1, props=None, source=DiscoverySource.SOURCE_CODE.value) -> Artifact:
    return Artifact(artifact_type=atype, name=name, category=category, source=source,
                    evidence=Evidence(file_path=path, line=line, snippet=name),
                    properties=props or {})


# ---------------------------------------------------------------------------
# Mosca's inequality
# ---------------------------------------------------------------------------
def test_mosca_violation_when_lifetime_plus_migration_exceeds_horizon():
    # 10y shelf-life + 2y migration = 12 > 7 years to CRQC. Must violate.
    violated, margin = mosca_check(crqc_year=CURRENT_YEAR + 7, lifetime_years=10,
                                   migration_months=24)
    assert violated is True
    assert margin == pytest.approx(-5.0)


def test_mosca_satisfied_with_comfortable_margin():
    violated, margin = mosca_check(crqc_year=CURRENT_YEAR + 20, lifetime_years=3,
                                   migration_months=12)
    assert violated is False
    assert margin == pytest.approx(16.0)


def test_mosca_boundary_is_strict_inequality():
    """X + Y exactly equal to Z is not a violation; only greater-than is."""
    violated, margin = mosca_check(crqc_year=CURRENT_YEAR + 6, lifetime_years=5,
                                   migration_months=12)
    assert margin == pytest.approx(0.0)
    assert violated is False


def test_earlier_crqc_creates_more_violations():
    """Pulling the CRQC year in must monotonically increase violations.

    This is the property the interactive simulator depends on: if it did not
    hold, moving the slider would produce noise instead of signal.
    """
    artifacts_2045 = [make('RSA', 'asymmetric-encryption') for _ in range(5)]
    for i, a in enumerate(artifacts_2045):
        a.evidence.line = i
    analyze(artifacts_2045, crqc_year=2045)
    late = sum(1 for a in artifacts_2045 if a.mosca_violated)

    artifacts_2030 = [make('RSA', 'asymmetric-encryption') for _ in range(5)]
    for i, a in enumerate(artifacts_2030):
        a.evidence.line = i
    analyze(artifacts_2030, crqc_year=2030)
    early = sum(1 for a in artifacts_2030 if a.mosca_violated)

    assert early >= late
    assert early == 5


def test_mosca_only_flags_quantum_vulnerable_material():
    """AES-256 has no quantum deadline, so it must never be a Mosca violation."""
    a = make('AES-256', 'symmetric-cipher')
    analyze([a], crqc_year=2028)
    assert a.quantum_impact == 'classical_ok'
    assert a.mosca_violated is False


# ---------------------------------------------------------------------------
# Impact resolution across every artifact type
# ---------------------------------------------------------------------------
@pytest.mark.parametrize('name,category,atype,expected', [
    ('RSA', 'asymmetric-encryption', 'algorithm-use', 'shor_broken'),
    ('AES-128', 'symmetric-cipher', 'algorithm-use', 'grover'),
    ('AES-256', 'symmetric-cipher', 'algorithm-use', 'classical_ok'),
    ('MD5', 'hash', 'algorithm-use', 'broken_classically'),
    ('ML-KEM-768', 'kem', 'algorithm-use', 'pq_safe'),
    ('TLSv1.0', 'protocol', 'protocol', 'broken_classically'),
    ('TLSv1.2', 'protocol', 'protocol', 'shor_broken'),
    ('ECDH', 'cipher-suite', 'protocol', 'shor_broken'),
    ('RSA certificate', 'certificate', 'certificate', 'shor_broken'),
    ('RSA private key', 'private-key', 'key', 'shor_broken'),
    ('ED25519 private key', 'private-key', 'key', 'shor_broken'),
])
def test_impact_resolution(name, category, atype, expected):
    a = make(name, category, atype)
    assert resolve_impact(a) == expected


def test_configuration_findings_get_impact():
    """Regression: config artifacts used to fall through as 'unknown'."""
    a = make('RSA-1024', 'asymmetric-encryption', 'configuration',
             props={'setting': 'key-size', 'key_size': 1024})
    assert resolve_impact(a) == 'shor_broken'


def test_tls_endpoint_findings_get_impact():
    a = make('TLSv1.0', 'protocol', 'tls-endpoint', path='tls://host:443')
    assert resolve_impact(a) == 'broken_classically'


def test_old_openssl_is_not_claimed_pq_safe():
    """A library with PQC in newer versions is not safe at an old version."""
    old = make('openssl', 'library', 'library', props={'version': '1.1.1f'})
    new = make('openssl', 'library', 'library', props={'version': '3.6.1'})
    assert resolve_impact(old) == 'unknown'
    assert resolve_impact(new) == 'pq_safe'


def test_bouncycastle_min_version_respected():
    old = make('bouncycastle', 'library', 'library', props={'version': '1.70'})
    new = make('bouncycastle', 'library', 'library', props={'version': '1.81'})
    assert resolve_impact(old) == 'unknown'
    assert resolve_impact(new) == 'pq_safe'


@pytest.mark.parametrize('have,need,expected', [
    ('3.6.1', '3.5', True), ('3.4.0', '3.5', False), ('1.1.1f', '3.5', False),
    ('1.80', '1.80', True), ('1.79', '1.80', False), ('41.0.7', '46.0', False),
])
def test_version_comparison(have, need, expected):
    assert _version_at_least(have, need) is expected


# ---------------------------------------------------------------------------
# Lifetime, migration effort, criticality
# ---------------------------------------------------------------------------
def test_root_ca_gets_long_lifetime_not_its_own_validity():
    """A root CA signs material outliving the CA certificate itself."""
    a = make('RSA certificate', 'certificate', 'certificate',
             path='/estate/infra/pki/ca/root-ca.pem',
             props={'lifetime_days': 3650, 'self_signed': True})
    assert estimate_lifetime(a) >= 15


def test_archive_paths_get_decades_of_shelf_life():
    a = make('X25519', 'key-agreement', path='/estate/treasury-archive/src/archive.py')
    assert estimate_lifetime(a) >= 20


def test_critical_systems_take_longer_to_migrate():
    low = make('RSA', 'asymmetric-encryption', path='/estate/tests/fixture.py')
    high = make('RSA', 'asymmetric-encryption', path='/estate/payments-service/src/x.py')
    low.business_criticality = infer_criticality(low.evidence.file_path)
    high.business_criticality = infer_criticality(high.evidence.file_path)
    assert low.business_criticality == 'low'
    assert high.business_criticality == 'critical'
    assert estimate_migration_months(high) > estimate_migration_months(low)


def test_hardware_migration_is_slowest():
    hw = make('Thales Luna HSM', 'hardware', 'hardware')
    lib = make('openssl', 'library', 'library')
    assert estimate_migration_months(hw) > estimate_migration_months(lib)


@pytest.mark.parametrize('path,expected', [
    ('/estate/payments-service/src/settlement.py', 'critical'),
    ('/estate/auth-service/src/SessionTokenService.java', 'high'),
    ('/estate/tests/test_thing.py', 'low'),
    ('/estate/misc/thing.py', 'medium'),
])
def test_criticality_inference(path, expected):
    assert infer_criticality(path) == expected


# ---------------------------------------------------------------------------
# HNDL exposure
# ---------------------------------------------------------------------------
def test_hndl_only_applies_to_asymmetric():
    """Symmetric traffic is not retroactively readable, so exposure is None."""
    sym = make('AES-256', 'symmetric-cipher')
    analyze([sym], crqc_year=2033)
    assert sym.hndl_exposure is None

    asym = make('ECDH', 'key-agreement')
    analyze([asym], crqc_year=2033)
    assert asym.hndl_exposure is not None and asym.hndl_exposure > 0


def test_external_facing_raises_hndl_exposure():
    internal = make('ECDH', 'key-agreement', path='/estate/internal/service.py')
    external = make('ECDH', 'key-agreement', path='/estate/edge-api/gateway.py')
    for a in (internal, external):
        a.business_criticality = infer_criticality(a.evidence.file_path)
        a.quantum_impact = 'shor_broken'
    assert hndl_exposure(external) > hndl_exposure(internal)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------
def test_classically_broken_outranks_quantum_vulnerable():
    """MD5 today is worse than RSA in 2033. Severity must reflect that."""
    md5 = make('MD5', 'hash')
    rsa = make('RSA', 'asymmetric-encryption')
    analyze([md5, rsa], crqc_year=2040)
    assert md5.risk_score > rsa.risk_score


def test_pq_safe_scores_near_zero():
    a = make('ML-KEM-768', 'kem')
    analyze([a], crqc_year=2030)
    assert a.risk_score < 2.0
    assert a.severity in ('low', 'info')


def test_undersized_rsa_key_escalates():
    strong = make('RSA certificate', 'certificate', 'certificate',
                  props={'key_size': 4096, 'lifetime_days': 365})
    weak = make('RSA certificate', 'certificate', 'certificate',
                props={'key_size': 1024, 'lifetime_days': 365})
    analyze([strong, weak], crqc_year=2033)
    assert weak.risk_score > strong.risk_score


def test_expired_certificate_escalates():
    ok = make('RSA certificate', 'certificate', 'certificate',
              props={'expired': False, 'lifetime_days': 365})
    dead = make('RSA certificate', 'certificate', 'certificate',
                props={'expired': True, 'lifetime_days': 365})
    analyze([ok, dead], crqc_year=2033)
    assert dead.risk_score > ok.risk_score


def test_risk_score_stays_in_range():
    names = ['RSA', 'MD5', 'AES-128', 'ML-KEM-768', 'TLSv1.0', 'SIKE', 'DES']
    arts = [make(n, 'asymmetric-encryption', path=f'/estate/payments/{n}.py') for n in names]
    analyze(arts, crqc_year=2028)
    for a in arts:
        assert 0.0 <= a.risk_score <= 10.0


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------
def test_pq_safe_gets_no_recommendation():
    a = make('ML-KEM-768', 'kem')
    a.quantum_impact = 'pq_safe'
    assert build_recommendation(a) is None


@pytest.mark.parametrize('name,category,expected_target', [
    ('RSA', 'asymmetric-encryption', 'ML-KEM-768'),
    ('ECDSA', 'signature', 'ML-DSA-65'),
    ('Ed25519', 'signature', 'ML-DSA-65'),
    ('ECDH', 'key-agreement', 'ML-KEM-768'),
    ('AES-128', 'symmetric-cipher', 'AES-256'),
    ('MD5', 'hash', 'SHA-384'),
    ('TLSv1.0', 'protocol', 'TLSv1.3'),
    ('3DES', 'symmetric-cipher', 'AES-256'),
])
def test_recommendation_targets(name, category, expected_target):
    a = make(name, category)
    a.quantum_impact = resolve_impact(a)
    rec = build_recommendation(a)
    assert rec is not None
    assert rec['target'] == expected_target


def test_recommendation_carries_real_cost_figures():
    """The wire-size delta must come from the knowledge base, not be invented."""
    a = make('ECDSA', 'signature')
    a.quantum_impact = 'shor_broken'
    rec = build_recommendation(a)
    # ECDSA: 65 pub + 64 sig = 129 bytes. ML-DSA-65: 1952 + 3309 = 5261.
    assert rec['wire_delta_bytes'] == 5261 - 129
    assert rec['target_perf']['sig_bytes'] == 3309
    assert rec['effort_days'] > 0


def test_hybrid_offered_for_transitional_migration():
    a = make('X25519', 'key-agreement')
    a.quantum_impact = 'shor_broken'
    rec = build_recommendation(a)
    assert rec['hybrid'] == 'X25519MLKEM768'


def test_broken_pqc_candidates_are_not_recommended_as_targets():
    """SIKE and Rainbow were broken in 2022; nothing may point at them."""
    from atlas.risk import RECOMMENDATIONS, FAMILY_RECOMMENDATIONS
    forbidden = {'SIKE', 'Rainbow'}
    for key, rec in list(RECOMMENDATIONS.items()) + list(FAMILY_RECOMMENDATIONS.items()):
        assert rec.get('target') not in forbidden, f'{key} recommends a broken algorithm'
        assert rec.get('hybrid') not in forbidden


def test_every_vulnerable_artifact_gets_actionable_advice():
    """No quantum-vulnerable finding may be left without a recommendation."""
    names = [('RSA', 'asymmetric-encryption'), ('ECDSA', 'signature'),
             ('ECDH', 'key-agreement'), ('AES-128', 'symmetric-cipher'),
             ('SHA-1', 'hash'), ('TLSv1.1', 'protocol'), ('3DES', 'symmetric-cipher'),
             ('DES', 'symmetric-cipher'), ('MD5', 'hash'), ('Ed25519', 'signature')]
    arts = [make(n, c, path=f'/estate/x/{n}.py') for n, c in names]
    analyze(arts, crqc_year=2033)
    for a in arts:
        assert a.recommendation, f'{a.name} has no recommendation'
        assert a.recommendation.get('target'), f'{a.name} recommendation has no target'


# ---------------------------------------------------------------------------
# Analyse is idempotent (the simulator re-runs it repeatedly)
# ---------------------------------------------------------------------------
def test_analyze_is_idempotent():
    arts = [make('RSA', 'asymmetric-encryption'), make('AES-128', 'symmetric-cipher')]
    analyze(arts, crqc_year=2033)
    first = [(a.risk_score, a.severity, a.mosca_violated) for a in arts]
    analyze(arts, crqc_year=2033)
    second = [(a.risk_score, a.severity, a.mosca_violated) for a in arts]
    assert first == second
