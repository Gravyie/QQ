"""Compliance mapping tests.

The point of these is not that the numbers are stable — they change when the
corpus changes — but that the verdicts are the right shape: a Shor-broken
classical key is on the IR 8547 clock, an already-disallowed primitive fails
today, a post-quantum algorithm is not flagged for a mandate it satisfies, and
nothing is quietly dropped.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from atlas.compliance import (STANDARDS, STATUS_ORDER, assess_artifact,
                              compliance_report, governing_status,
                              IR8547_DEPRECATE_YEAR, IR8547_DISALLOW_YEAR)
from atlas.models import Artifact, Evidence, ScanResult

RESULTS = Path(__file__).resolve().parent.parent.parent / 'results'
ESTATE_SCAN = '9a839012-dceb-48f3-b964-a4859d14f580'


def art(name, *, artifact_type='algorithm-use', category='signature',
        path='/estate/svc/src/app.py', props=None, severity='high',
        risk=7.0, criticality='high', line=1) -> Artifact:
    return Artifact(
        artifact_type=artifact_type, name=name, category=category,
        source='source-code',
        evidence=Evidence(file_path=path, line=line),
        properties=props or {}, severity=severity, risk_score=risk,
        business_criticality=criticality,
    )


def by_std(verdicts, short):
    return [v for v in verdicts if v['standard_short'] == short]


# ---------------------------------------------------------------- IR 8547

def test_rsa2048_is_on_the_ir8547_clock():
    v = by_std(assess_artifact(art('RSA', category='asymmetric-encryption')),
               'NIST IR 8547')
    assert len(v) == 1
    assert v[0]['status'] == 'action_required'
    assert v[0]['deadline_year'] == IR8547_DEPRECATE_YEAR
    assert str(IR8547_DISALLOW_YEAR) in v[0]['note']


def test_ir8547_verdicts_are_labelled_draft():
    """The dates come from a draft document and must never read as settled law."""
    for a in (art('RSA'), art('ECDSA'), art('ML-KEM-768', category='kem')):
        for v in by_std(assess_artifact(a), 'NIST IR 8547'):
            assert v['confidence'] == 'draft'
    assert STANDARDS['nist-ir-8547']['status'] == 'draft'


def test_higher_strength_classical_escapes_2030_but_not_2035():
    v = by_std(assess_artifact(art('ECDSA-P384')), 'NIST IR 8547')[0]
    assert v['deadline_year'] == IR8547_DISALLOW_YEAR
    assert v['status'] == 'action_required'


def test_past_the_disallow_year_everything_classical_is_disallowed():
    v = by_std(assess_artifact(art('ECDSA-P384'), year=IR8547_DISALLOW_YEAR + 1),
               'NIST IR 8547')[0]
    assert v['status'] == 'disallowed'


def test_pq_safe_is_compliant_not_flagged():
    v = by_std(assess_artifact(art('ML-KEM-768', category='kem')), 'NIST IR 8547')[0]
    assert v['status'] == 'compliant'


def test_symmetric_is_not_applicable_to_the_public_key_transition():
    v = by_std(assess_artifact(art('AES-256', category='symmetric-cipher')),
               'NIST IR 8547')[0]
    assert v['status'] == 'not_applicable'


# ------------------------------------------------------------------ CNSA 2.0

def test_cnsa_approves_its_named_algorithms():
    for name in ('ML-KEM-1024', 'ML-DSA-87', 'AES-256', 'SHA-384'):
        v = by_std(assess_artifact(art(name, category='kem')), 'CNSA 2.0')[0]
        assert v['status'] == 'compliant', name


def test_cnsa_rejects_understrength_pqc_with_the_reason():
    v = by_std(assess_artifact(art('ML-KEM-768', category='kem')), 'CNSA 2.0')[0]
    assert v['status'] == 'action_required'
    assert 'ML-KEM-1024' in v['note']


def test_cnsa_signing_category_uses_the_2030_deadline():
    a = art('ECDSA', category='signature',
            path='/estate/branch-hsm-bridge/firmware/update-signing.c')
    v = by_std(assess_artifact(a), 'CNSA 2.0')[0]
    assert v['deadline_year'] == 2030
    assert 'signing' in v['control']


def test_cnsa_assesses_providers_on_capability_not_algorithm():
    old = art('bcprov-jdk18on', artifact_type='library', category='library',
              props={'version': '1.72'})
    new = art('bcprov-jdk18on', artifact_type='library', category='library',
              props={'version': '1.81'})
    v_old = by_std(assess_artifact(old), 'CNSA 2.0')[0]
    v_new = by_std(assess_artifact(new), 'CNSA 2.0')[0]
    assert v_old['status'] == 'action_required'
    assert '1.80' in v_old['note']
    assert v_new['status'] == 'compliant'


def test_provider_without_pqc_support_blocks_everything_above_it():
    v = by_std(assess_artifact(art('pyjwt', artifact_type='library',
                                   category='library')), 'CNSA 2.0')[0]
    assert v['status'] == 'action_required'
    assert 'no post-quantum support' in v['note']


# --------------------------------------------------------------- SP 800-131A

def test_sha1_is_disallowed_today():
    v = by_std(assess_artifact(art('SHA-1', category='hash')), 'SP 800-131A')
    assert any(x['status'] == 'disallowed' for x in v)
    assert all(x['confidence'] == 'published' for x in v)


def test_3des_is_disallowed_today():
    v = by_std(assess_artifact(art('3DES', category='symmetric-cipher')),
               'SP 800-131A')
    assert any(x['status'] == 'disallowed' for x in v)


def test_rsa_below_2048_is_a_separate_finding():
    a = art('RSA-1024', artifact_type='configuration',
            category='asymmetric-encryption', props={'key_size': 1024})
    v = by_std(assess_artifact(a), 'SP 800-131A')
    modulus = [x for x in v if 'modulus' in x['control']]
    assert modulus and modulus[0]['status'] == 'disallowed'
    assert '1024' in modulus[0]['note']


def test_the_modulus_control_does_not_fire_on_elliptic_curves():
    """A 256-bit EC key is strong. Scoring it as a 256-bit RSA modulus would be a
    confident false positive, which is worse than a miss."""
    a = art('Ed25519 certificate', artifact_type='certificate',
            category='certificate',
            props={'key_size': 256, 'signature_algorithm': 'ed25519'})
    v = by_std(assess_artifact(a), 'SP 800-131A')
    assert not any('modulus' in x['control'] for x in v)


def test_weak_chain_signature_is_its_own_finding():
    a = art('ML-DSA-65 certificate', artifact_type='certificate',
            category='certificate',
            props={'signature_algorithm': 'sha1WithRSAEncryption'})
    v = by_std(assess_artifact(a), 'SP 800-131A')
    chain = [x for x in v if 'signature algorithm' in x['control']]
    assert chain and chain[0]['status'] == 'disallowed'


def test_certificate_resolves_its_own_key_not_the_issuer_signature():
    """An Ed25519 certificate signed by an RSA CA is an Ed25519 finding."""
    a = art('Ed25519 certificate', artifact_type='certificate',
            category='certificate',
            props={'key_size': 256, 'signature_algorithm': 'sha256WithRSAEncryption'})
    ir = by_std(assess_artifact(a), 'NIST IR 8547')[0]
    assert 'Ed25519' in ir['note']
    assert 'RSA' not in ir['note']


# ------------------------------------------------------------------- rollup

@pytest.fixture(scope='module')
def estate() -> ScanResult:
    return ScanResult.load(RESULTS / f'{ESTATE_SCAN}.json')


def test_report_shape_over_the_real_estate(estate):
    rep = compliance_report(estate.artifacts)
    assert rep['artifacts_assessed'] == len(estate.artifacts)
    assert len(rep['standards']) == len(STANDARDS)
    for s in rep['standards']:
        assert set(s['counts_by_status']) == set(STATUS_ORDER)
        # Every artifact gets a verdict from every standard, so the counts must
        # account for all of them. A missing verdict is a silently dropped
        # artifact.
        assert sum(s['counts_by_status'].values()) >= len(estate.artifacts)
        assert len(s['offenders']) <= 12


def test_posture_is_bounded_and_explains_itself(estate):
    rep = compliance_report(estate.artifacts)
    p = rep['posture']
    assert 0 <= p['score'] <= 100
    assert p['band'] in ('critical', 'weak', 'partial', 'strong')
    assert p['basis'] and p['headline']
    # The basis quotes the passing count, so passing + failing must account for
    # every artifact assessed. A basis that does not reconcile is a basis nobody
    # can check.
    clean = rep['artifacts_assessed'] - p['failing_artifacts']
    assert f'({clean} of {rep["artifacts_assessed"]})' in p['basis']


def test_deadline_buckets_are_cumulative_per_standard(estate):
    buckets = compliance_report(estate.artifacts)['deadline_buckets']
    assert buckets
    running: dict[str, int] = {}
    for b in sorted(buckets, key=lambda x: (x['standard_short'], x['year'])):
        prev = running.get(b['standard_short'], 0)
        assert b['cumulative'] >= prev
        assert b['cumulative'] == prev + b['artifacts_falling_foul']
        running[b['standard_short']] = b['cumulative']


def test_worst_first_puts_already_disallowed_ahead_of_future_deadlines(estate):
    worst = compliance_report(estate.artifacts)['worst_first']
    assert worst
    statuses = [w['status'] for w in worst]
    if 'disallowed' in statuses and 'action_required' in statuses:
        assert statuses.index('disallowed') < statuses.index('action_required')


def test_governing_status_picks_the_worst():
    a = art('SHA-1', category='hash')
    assert governing_status(assess_artifact(a)) == 'disallowed'
    assert governing_status([]) == 'not_applicable'


def test_year_parameter_moves_the_verdicts(estate):
    now = compliance_report(estate.artifacts, current_year=2026)
    later = compliance_report(estate.artifacts, current_year=2036)
    now_ir = next(s for s in now['standards'] if s['standard_short'] == 'NIST IR 8547')
    later_ir = next(s for s in later['standards'] if s['standard_short'] == 'NIST IR 8547')
    assert later_ir['counts_by_status']['disallowed'] > now_ir['counts_by_status']['disallowed']
    assert later['posture']['score'] <= now['posture']['score']
