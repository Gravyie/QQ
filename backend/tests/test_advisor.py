"""Advisor tests.

The invariant that matters most is the last one: every rejected candidate must
name the constraint it violated. A recommendation engine that silently drops
options is indistinguishable from one that has no opinion, and an analyst cannot
audit what they cannot see.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from atlas.advisor import (CANDIDATES, DEFAULT_PROFILE, MSS_BYTES,
                           SCORE_WEIGHTS, STATEFUL, WORKLOAD_PROFILES,
                           advise_inventory, infer_profile, recommend)
from atlas.knowledge_base import ALGORITHMS
from atlas.models import Artifact, Evidence, ScanResult

RESULTS = Path(__file__).resolve().parent.parent.parent / 'results'
ESTATE_SCAN = '9a839012-dceb-48f3-b964-a4859d14f580'

SAMPLE_CURRENT = ['RSA', 'RSA-2048', 'ECDSA-P256', 'X25519', 'ECDH', 'Ed25519',
                  'AES-128', 'SHA-256', '3DES', 'ML-KEM-768']


def find(result, name):
    return next(c for c in result['candidates'] if c['name'] == name)


# ------------------------------------------------------------- the invariant

def test_every_rejected_candidate_names_its_blocker():
    """Across the full cross-product of profiles and starting algorithms."""
    checked = 0
    for profile in WORKLOAD_PROFILES:
        for alg in SAMPLE_CURRENT:
            r = recommend(alg, profile)
            for c in r['candidates']:
                if c['verdict'] == 'rejected':
                    assert c['blockers'], (
                        f'{c["name"]} rejected for {alg}@{profile} with no blocker')
                    assert all(isinstance(b, str) and b for b in c['blockers'])
                    checked += 1
                else:
                    assert not c['blockers'], (
                        f'{c["name"]} is {c["verdict"]} for {alg}@{profile} but '
                        f'carries blockers: {c["blockers"]}')
    assert checked > 20, 'expected the cross-product to exercise real rejections'


def test_no_candidate_is_ever_silently_dropped():
    for profile in WORKLOAD_PROFILES:
        r = recommend('RSA', profile)
        pool = CANDIDATES.get(r['role'], [])
        assert {c['name'] for c in r['candidates']} == set(pool)


def test_exactly_one_recommendation_when_anything_is_viable():
    for profile in WORKLOAD_PROFILES:
        r = recommend('X25519', profile)
        rec = [c for c in r['candidates'] if c['verdict'] == 'recommended']
        assert len(rec) <= 1
        if rec:
            assert r['decision']['choose'] == rec[0]['name']
        else:
            assert r['decision']['choose'] is None


# ---------------------------------------------------------------- CNSA 2.0

def test_national_security_chooses_the_mandated_kem():
    r = recommend('RSA-2048', 'national-security')
    assert r['role'] == 'kem'
    assert r['decision']['choose'] == 'ML-KEM-1024'
    assert 'required algorithm' in find(r, 'ML-KEM-1024')['reasons'][0]


def test_national_security_rejects_mlkem512_on_the_level_floor():
    c = find(recommend('RSA-2048', 'national-security'), 'ML-KEM-512')
    assert c['verdict'] == 'rejected'
    assert any('category 1' in b and 'category 5' in b for b in c['blockers'])


def test_national_security_signing_chooses_the_mandated_signature():
    r = recommend('ECDSA-P256', 'national-security')
    assert r['role'] == 'signature'
    assert r['decision']['choose'] == 'ML-DSA-87'


# ------------------------------------------------------------- TLS frontend

def test_tls_frontend_chooses_the_deployed_hybrid_group():
    r = recommend('X25519', 'tls-frontend')
    assert r['decision']['choose'] == 'X25519MLKEM768'
    reasons = ' '.join(find(r, 'X25519MLKEM768')['reasons']).lower()
    assert 'interop' in reasons


def test_tls_frontend_rejects_pure_mlkem_for_interoperability():
    c = find(recommend('X25519', 'tls-frontend'), 'ML-KEM-768')
    assert c['verdict'] == 'rejected'
    assert any('hybrid' in b for b in c['blockers'])


def test_internal_mtls_allows_pure_pqc():
    r = recommend('X25519', 'internal-mtls')
    pure = find(r, 'ML-KEM-768')
    assert pure['verdict'] in ('recommended', 'viable')
    assert not pure['blockers']


# -------------------------------------------------------------- constrained

def test_iot_wire_budget_blocker_quotes_the_actual_bytes():
    r = recommend('ECDSA-P256', 'iot-constrained')
    rejected = [c for c in r['candidates'] if c['verdict'] == 'rejected']
    assert rejected
    budget = WORKLOAD_PROFILES['iot-constrained']['wire_budget_bytes']
    wire_blocked = [c for c in rejected
                    if any('exceeds' in b and str(budget) in b for b in c['blockers'])]
    assert wire_blocked
    c = wire_blocked[0]
    blocker = next(b for b in c['blockers'] if 'exceeds' in b)
    assert str(c['wire_bytes']) in blocker
    assert str(c['wire_bytes'] - budget) in blocker


def test_iot_signature_has_no_viable_answer_and_says_so():
    """Post-quantum signatures do not fit in one datagram. Saying that plainly is
    the correct output; inventing a winner would not be."""
    r = recommend('ECDSA-P256', 'iot-constrained')
    assert r['decision']['choose'] is None
    assert 'hard constraint' in r['decision']['because']


# ------------------------------------------------------------ statefulness

def test_firmware_signing_accepts_stateful_hash_based_signatures():
    r = recommend('RSA', 'firmware-signing')
    assert r['role'] == 'signature', 'a firmware signing key needs a signature'
    lms = find(r, 'LMS')
    assert lms['verdict'] in ('recommended', 'viable')
    assert lms['stateful'] is True


def test_code_signing_rejects_the_same_algorithm_on_statefulness():
    c = find(recommend('RSA', 'code-signing'), 'XMSS')
    assert c['verdict'] == 'rejected'
    assert any('stateful' in b for b in c['blockers'])


def test_stateful_set_matches_the_knowledge_base_notes():
    for name in STATEFUL:
        entry = ALGORITHMS.get(name)
        if entry:
            assert 'stateful' in str(entry.get('note', '')).lower()


# ------------------------------------------------------------------- roles

def test_already_pqc_algorithm_is_not_downgraded():
    r = recommend('ML-KEM-768', 'internal-mtls')
    assert r['role'] == 'kem'
    assert r['decision']['choose'] == 'ML-KEM-768'
    assert find(r, 'ML-KEM-768')['wire_delta_bytes'] == 0


def test_shelf_life_raises_the_security_floor():
    short = recommend('ECDSA', 'internal-mtls', shelf_life_years=3)
    long = recommend('ECDSA', 'internal-mtls', shelf_life_years=25)
    assert short['input']['min_nist_level_applied'] == 3
    assert long['input']['min_nist_level_applied'] == 5
    assert any('shelf-life' in a for a in long['assumptions'])


def test_symmetric_and_hash_roles_resolve():
    assert recommend('AES-128', 'internal-mtls')['role'] == 'symmetric'
    assert recommend('SHA-256', 'internal-mtls')['role'] == 'hash'
    assert recommend('AES-128', 'internal-mtls')['decision']['choose'] == 'AES-256'


def test_unknown_profile_raises_rather_than_defaulting():
    with pytest.raises(KeyError):
        recommend('RSA', 'not-a-profile')


# ------------------------------------------------------- data and honesty

def test_every_candidate_algorithm_exists_in_the_knowledge_base():
    for role, names in CANDIDATES.items():
        for name in names:
            assert name in ALGORITHMS, f'{name} in the {role} pool is not in the KB'


def test_asymmetric_candidates_all_carry_wire_figures():
    """A candidate with no perf block would score neutrally on 35 of the 100
    points, which quietly flatters an undocumented algorithm."""
    for role in ('kem', 'signature'):
        for name in CANDIDATES[role]:
            perf = ALGORITHMS[name].get('perf')
            assert perf, f'{name} has no perf block'
            assert perf.get('pub_bytes'), f'{name} has no pub_bytes'
            assert perf.get('ct_bytes') or perf.get('sig_bytes'), name
            assert perf.get('ops_ms') is not None, f'{name} has no ops_ms'


def test_wire_figures_match_the_published_parameter_sets():
    """Spot-check against FIPS 203/204/205 parameter tables."""
    expected = {
        'ML-KEM-512': (800, 768), 'ML-KEM-768': (1184, 1088),
        'ML-KEM-1024': (1568, 1568),
    }
    for name, (pub, ct) in expected.items():
        perf = ALGORITHMS[name]['perf']
        assert (perf['pub_bytes'], perf['ct_bytes']) == (pub, ct), name
    sigs = {'ML-DSA-44': (1312, 2420), 'ML-DSA-65': (1952, 3309),
            'ML-DSA-87': (2592, 4627), 'SLH-DSA-128s': (32, 7856)}
    for name, (pub, sig) in sigs.items():
        perf = ALGORITHMS[name]['perf']
        assert (perf['pub_bytes'], perf['sig_bytes']) == (pub, sig), name


def test_hybrid_wire_cost_is_the_sum_of_its_parts():
    hybrid = ALGORITHMS['X25519MLKEM768']['perf']
    x = ALGORITHMS['X25519']['perf']
    kem = ALGORITHMS['ML-KEM-768']['perf']
    assert hybrid['pub_bytes'] == x['pub_bytes'] + kem['pub_bytes']
    assert hybrid['ct_bytes'] == x['pub_bytes'] + kem['ct_bytes']


def test_assumptions_disclose_the_weights_and_the_perf_caveat():
    a = ' '.join(recommend('RSA', DEFAULT_PROFILE)['assumptions'])
    for weight in SCORE_WEIGHTS:
        assert weight in a
    assert 'not benchmarks' in a
    assert str(MSS_BYTES) in a


def test_handshake_note_quantifies_the_cost():
    c = find(recommend('X25519', 'internal-mtls'), 'ML-KEM-768')
    assert str(c['wire_delta_bytes']) in c['handshake_delta_note']
    assert 'segment' in c['handshake_delta_note']


# ---------------------------------------------------------------- inventory

@pytest.fixture(scope='module')
def estate() -> ScanResult:
    return ScanResult.load(RESULTS / f'{ESTATE_SCAN}.json')


def test_advise_inventory_over_the_real_estate(estate):
    out = advise_inventory(estate.artifacts)
    assert out['by_algorithm']
    cov = out['coverage']
    assert cov['advised'] + cov['unadvised'] == cov['algorithms_seen']
    assert len(cov['unadvised_names']) == cov['unadvised']
    for row in out['by_algorithm']:
        assert row['profile_used'] in WORKLOAD_PROFILES
        assert row['uses'] >= 1
        assert row['because']


def test_inventory_reports_wire_impact_with_a_named_offender(estate):
    out = advise_inventory(estate.artifacts)
    w = out['wire_impact']
    assert w['total_added_bytes_per_op'] >= 0
    assert 'not a latency figure' in w['note']
    if w['total_added_bytes_per_op']:
        assert w['worst_offender']


def test_profile_inference_is_reported_not_hidden(estate):
    out = advise_inventory(estate.artifacts)
    assert out['profile_inference']
    for row in out['profile_inference']:
        assert row['inferred_profile'] in WORKLOAD_PROFILES
        assert row['why']


def test_archive_paths_infer_the_archive_profile():
    a = Artifact(artifact_type='algorithm-use', name='X25519',
                 category='key-agreement', source='source-code',
                 evidence=Evidence(file_path='/estate/treasury-archive/src/archive.py',
                                   line=15))
    profile, why = infer_profile(a)
    assert profile == 'document-archive'
    assert why


def test_service_hint_overrides_inference(estate):
    hinted = advise_inventory(estate.artifacts,
                              {'treasury-archive': 'national-security'})
    used = {r['profile_used'] for r in hinted['by_algorithm']}
    assert 'national-security' in used
