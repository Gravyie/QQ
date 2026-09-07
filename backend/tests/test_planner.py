"""Planner tests: wave ordering, effort model, simulation purity.

The plan is the part a reviewer will act on, so the tests pin the properties
that make it a plan rather than a sorted list: dependency order, deduplicated
effort, and a schedule that can actually miss a deadline.
"""
from __future__ import annotations

import pytest

from atlas.models import Artifact, Evidence
from atlas.risk import analyze, estimate_lifetime, MAX_CREDIBLE_LIFETIME_YEARS
from atlas.planner import (build_plan, simulate, risk_curve, schedule_waves,
                           exposure_matrix, lifetime_exposure, lifetime_band,
                           algorithm_rollup, _wave_for, WAVES)


def make(name, category, atype='algorithm-use', path='/estate/app/x.py', line=1,
         props=None) -> Artifact:
    return Artifact(artifact_type=atype, name=name, category=category,
                    source='source-code',
                    evidence=Evidence(file_path=path, line=line, snippet=name),
                    properties=props or {})


@pytest.fixture
def estate() -> list[Artifact]:
    arts = [
        make('MD5', 'hash', line=1),
        make('SHA-1', 'hash', line=2),
        make('DES', 'symmetric-cipher', line=3),
        make('openssl', 'library', 'library', path='/estate/requirements.txt',
             props={'version': '1.1.1f'}),
        make('TLSv1.0', 'protocol', 'protocol', path='/estate/nginx.conf', line=4),
        make('TLSv1.2', 'protocol', 'protocol', path='/estate/nginx.conf', line=5),
        make('ECDH', 'key-agreement', line=6),
        make('X25519', 'key-agreement', line=7),
        make('ECDSA', 'signature', line=8),
        make('RSA certificate', 'certificate', 'certificate',
             path='/estate/pki/a.pem', props={'lifetime_days': 365}),
        make('RSA private key', 'private-key', 'key', path='/estate/pki/a.key'),
        make('AWS KMS', 'service', 'cloud-service', path='/estate/app/kms.py', line=9),
        make('Thales Luna HSM', 'hardware', 'hardware', path='/estate/hsm.c', line=10),
        make('AES-128', 'symmetric-cipher', line=11),
        make('ML-KEM-768', 'kem', line=12),
        make('AES-256', 'symmetric-cipher', line=13),
    ]
    analyze(arts, crqc_year=2033)
    return arts


# ---------------------------------------------------------------------------
# Wave assignment and ordering
# ---------------------------------------------------------------------------
def test_wave_numbers_are_contiguous_and_ordered():
    numbers = [w['wave'] for w in WAVES]
    assert numbers == sorted(numbers)
    assert numbers == list(range(1, len(WAVES) + 1))


def test_classically_broken_goes_first(estate):
    md5 = next(a for a in estate if a.name == 'MD5')
    assert _wave_for(md5) == 1


def test_libraries_precede_the_things_that_depend_on_them(estate):
    """You cannot migrate to ML-KEM before a library implements it."""
    lib = next(a for a in estate if a.name == 'openssl')
    kex = next(a for a in estate if a.name == 'ECDH')
    assert _wave_for(lib) < _wave_for(kex)


def test_protocol_floor_precedes_key_agreement(estate):
    """TLS 1.2 cannot negotiate a hybrid group, so the floor moves first."""
    proto = next(a for a in estate if a.name == 'TLSv1.2')
    kex = next(a for a in estate if a.name == 'ECDH')
    assert _wave_for(proto) < _wave_for(kex)


def test_key_agreement_precedes_signatures(estate):
    """HNDL makes key agreement retroactively urgent; forgery is not."""
    kex = next(a for a in estate if a.name == 'ECDH')
    sig = next(a for a in estate if a.name == 'ECDSA')
    assert _wave_for(kex) < _wave_for(sig)


def test_pq_safe_artifacts_have_no_wave(estate):
    safe = next(a for a in estate if a.name == 'ML-KEM-768')
    assert _wave_for(safe) is None


def test_adequate_symmetric_has_no_wave(estate):
    ok = next(a for a in estate if a.name == 'AES-256')
    assert _wave_for(ok) is None


def test_plan_covers_every_actionable_artifact(estate):
    plan = build_plan(estate, 2033)
    planned = sum(w['artifact_count'] for w in plan['waves'])
    assert planned + plan['nothing_to_do'] == len(estate)


# ---------------------------------------------------------------------------
# Effort model
# ---------------------------------------------------------------------------
def test_effort_is_deduplicated_per_work_unit():
    """Three findings on one line and one target are one piece of work."""
    arts = [make('AES', 'symmetric-cipher', line=n, path='/estate/app/crypto.py')
            for n in (10, 10, 10)]
    for a in arts:
        a.evidence.line = 10
    analyze(arts, crqc_year=2033)
    plan = build_plan(arts, 2033)
    wave = plan['waves'][0]
    assert wave['artifact_count'] >= 1
    assert wave['work_units'] == 1
    assert wave['effort_days'] < 3 * 45


def test_effort_grows_with_estate_size(estate):
    small = build_plan(estate[:4], 2033)['total_effort_days']
    large = build_plan(estate, 2033)['total_effort_days']
    assert large > small


def test_schedule_can_miss_the_deadline():
    """A plan that always says 'we make it' is not a planning tool."""
    waves = [{'wave': 1, 'title': 'huge', 'effort_days': 40000}]
    sched = schedule_waves(waves, crqc_year=2030, engineers=2)
    assert sched['meets_deadline'] is False
    assert sched['slack_years'] < 0


def test_schedule_meets_a_generous_deadline():
    waves = [{'wave': 1, 'title': 'small', 'effort_days': 30}]
    sched = schedule_waves(waves, crqc_year=2045, engineers=4)
    assert sched['meets_deadline'] is True
    assert sched['slack_years'] > 0


def test_more_engineers_shortens_the_schedule():
    waves = [{'wave': 1, 'title': 'w', 'effort_days': 720}]
    slow = schedule_waves(waves, 2040, engineers=2)['total_months']
    fast = schedule_waves(waves, 2040, engineers=8)['total_months']
    assert fast < slow


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------
def test_simulate_does_not_mutate_the_input(estate):
    dicts = [a.to_dict() for a in estate]
    before = [dict(d) for d in dicts]
    simulate(dicts, crqc_year=2029)
    assert dicts == before, 'simulate mutated its input'


def test_simulate_reacts_to_the_crqc_assumption(estate):
    dicts = [a.to_dict() for a in estate]
    near = simulate(dicts, crqc_year=2028)
    far = simulate(dicts, crqc_year=2050)
    assert near['summary']['mosca_violations'] > far['summary']['mosca_violations']


def test_simulate_reacts_to_data_lifetime(estate):
    dicts = [a.to_dict() for a in estate]
    short = simulate(dicts, crqc_year=2035, data_lifetime_years=1)
    long = simulate(dicts, crqc_year=2035, data_lifetime_years=30)
    assert long['summary']['mosca_violations'] >= short['summary']['mosca_violations']


def test_simulate_reacts_to_migration_time(estate):
    dicts = [a.to_dict() for a in estate]
    quick = simulate(dicts, crqc_year=2032, migration_months=1)
    slow = simulate(dicts, crqc_year=2032, migration_months=96)
    assert slow['summary']['mosca_violations'] >= quick['summary']['mosca_violations']


def test_simulate_is_deterministic(estate):
    dicts = [a.to_dict() for a in estate]
    a = simulate(dicts, crqc_year=2033)['summary']
    b = simulate(dicts, crqc_year=2033)['summary']
    assert a == b


def test_simulate_matches_a_fresh_analyze(estate):
    """The simulator must agree with the scanner, or the UI lies."""
    dicts = [a.to_dict() for a in estate]
    sim = simulate(dicts, crqc_year=2033)
    fresh = build_plan(estate, 2033)
    assert sim['plan']['total_effort_days'] == fresh['total_effort_days']
    assert sim['summary']['mosca_violations'] == sum(
        1 for a in estate if a.mosca_violated)


# ---------------------------------------------------------------------------
# Risk curve
# ---------------------------------------------------------------------------
def test_risk_curve_is_monotonically_non_increasing(estate):
    """Later CRQC means fewer violations. A non-monotonic curve means a bug."""
    dicts = [a.to_dict() for a in estate]
    curve = risk_curve(dicts, years=range(2028, 2046, 2))
    violations = [p['mosca_violations'] for p in curve]
    assert violations == sorted(violations, reverse=True)


def test_risk_curve_covers_the_requested_years(estate):
    dicts = [a.to_dict() for a in estate]
    curve = risk_curve(dicts, years=range(2030, 2036))
    assert [p['crqc_year'] for p in curve] == list(range(2030, 2036))


# ---------------------------------------------------------------------------
# Rollups
# ---------------------------------------------------------------------------
def test_exposure_matrix_totals_match(estate):
    cells = exposure_matrix(estate)
    assert sum(c['count'] for c in cells) == len(estate)
    for c in cells:
        assert c['max_risk'] <= 10.0


def test_exposure_matrix_keys_match_what_the_heatmap_reads(estate):
    """The grid must be keyed on criticality x impact.

    Regression: this returned lifetime_band x criticality while the console's
    Heat component looked up criticality x impact, so every cell missed and the
    heatmap rendered as a grid of empty dots on a scan with 2,597 artefacts.
    A shape mismatch between producer and consumer is invisible to type-free
    JSON, so it is pinned here.
    """
    cells = exposure_matrix(estate)
    assert cells, 'grid must not be empty for a non-empty estate'
    for c in cells:
        assert set(c) >= {'criticality', 'impact', 'count', 'max_risk'}
        assert c['impact'] in ('broken_classically', 'shor_broken', 'grover',
                              'unknown', 'classical_ok', 'pq_safe')
    # Every artefact must land in exactly one cell.
    pairs = {(a.business_criticality, a.quantum_impact or 'unknown') for a in estate}
    assert {(c['criticality'], c['impact']) for c in cells} == pairs


def test_exposure_matrix_orders_worst_first(estate):
    """Reading order must be the migration order: critical + already-broken first."""
    cells = exposure_matrix(estate)
    crit_rank = ['critical', 'high', 'medium', 'low']
    ranks = [crit_rank.index(c['criticality']) for c in cells
             if c['criticality'] in crit_rank]
    assert ranks == sorted(ranks), 'criticality must descend down the grid'


@pytest.mark.parametrize('lifetime', [0, 1, 14, 15, 30, 100, 1000, 100_000])
def test_lifetime_band_covers_every_value(lifetime):
    """No lifetime value may fall outside every band.

    Regression: the top band was capped at 999, so a certificate carrying a
    1000-year validity window (routine in crypto library test corpora) matched
    nothing and a bare next() raised StopIteration. Inside a threadpool that
    surfaced as RuntimeError and returned HTTP 500 for the whole scan, so one
    absurd test fixture took out the entire report.
    """
    assert lifetime_band(lifetime) in ('0-3y', '3-7y', '7-15y', '15y+')


@pytest.mark.parametrize('lifetime', [0, 1000, 100_000])
def test_lifetime_exposure_survives_absurd_lifetimes(lifetime):
    a = make('RSA', 'certificate', atype='certificate')
    a.lifetime_years = lifetime
    a.risk_score = 5.0
    cells = lifetime_exposure([a])
    assert len(cells) == 1 and cells[0]['count'] == 1


def test_lifetime_exposure_bands_sort_by_duration_not_alphabetically():
    """'15y+' sorts after '7-15y'; string ordering would put it first."""
    arts = []
    for lt in (1, 5, 10, 40):
        a = make('RSA', 'certificate', atype='certificate', line=lt)
        a.lifetime_years = lt
        a.risk_score = 5.0
        a.business_criticality = 'high'
        arts.append(a)
    bands = [c['lifetime_band'] for c in lifetime_exposure(arts)]
    assert bands == ['0-3y', '3-7y', '7-15y', '15y+'], bands


def test_absurd_certificate_lifetime_is_capped_but_disclosed():
    """A 1000-year notAfter must not dominate the risk ranking.

    Taken literally it yields a Mosca margin near -1000 years, outranking every
    genuine finding. It is capped for scoring, but the raw figure and the reason
    are recorded on the artifact so the cap is visible rather than silent.
    """
    a = make('ECDSA certificate', 'certificate', atype='certificate',
             props={'lifetime_days': 365_000})
    years = estimate_lifetime(a)
    assert years == MAX_CREDIBLE_LIFETIME_YEARS
    assert a.properties['lifetime_years_raw'] == 1000
    assert 'capped' in a.properties['lifetime_capped']


def test_ordinary_certificate_lifetime_is_not_capped():
    """The cap must not touch realistic certificates."""
    a = make('RSA certificate', 'certificate', atype='certificate',
             props={'lifetime_days': 730})
    assert estimate_lifetime(a) == 2
    assert 'lifetime_capped' not in a.properties


def test_algorithm_rollup_groups_by_name(estate):
    rows = algorithm_rollup(estate)
    assert sum(r['count'] for r in rows) == len(estate)
    names = [r['name'] for r in rows]
    assert len(names) == len(set(names)), 'rollup produced duplicate rows'
    # Highest risk first.
    risks = [r['max_risk'] for r in rows]
    assert risks == sorted(risks, reverse=True)
