"""Migration wave planner, cost model, and Mosca re-simulation.

Two jobs:

1. `simulate` re-runs the entire risk model over a stored inventory with new
   assumptions (CRQC year, data lifetime, migration capacity) without touching
   the filesystem. That is what makes the assumptions interactive: a reviewer can
   move the CRQC year from 2035 to 2030 and watch the estate repaint in
   milliseconds instead of waiting for a rescan.

2. `build_plan` turns a flat inventory into a dependency-ordered migration
   programme. The ordering is not arbitrary: you cannot issue a PQC certificate
   before the library that parses it can, and you cannot negotiate a hybrid TLS
   group before the protocol floor is TLS 1.3.
"""
from __future__ import annotations

from collections import defaultdict

from .models import Artifact
from .risk import (analyze, CURRENT_YEAR, EFFORT_DAYS, CRITICALITY_WEIGHT,
                   hydrate_artifact)
from .knowledge_base import ALGORITHMS

# Wave definitions in strict execution order. `matches` decides membership; the
# first wave whose predicate matches an artifact claims it.
#
# The dependency logic:
#   1  Remove what is already exploitable. No quantum computer required, so this
#      is pure present-tense risk and usually a small diff.
#   2  Upgrade the crypto libraries and runtimes. Nothing downstream can move to
#      PQC until the implementation exists in the estate.
#   3  Raise protocol floors to TLS 1.3 / SSH with hybrid KEX. Prerequisite for
#      negotiating any PQC group.
#   4  Migrate key agreement. Highest HNDL value: every recorded handshake
#      protected by ECDH is retroactively readable.
#   5  Migrate signatures, certificates and key material. Not HNDL-exposed
#      (forgery needs a live CRQC), so it can trail key agreement.
#   6  Vendor-gated: HSMs and cloud KMS move when the vendor ships.
WAVES = [
    {
        'wave': 1,
        'title': 'Eliminate classically broken primitives',
        'rationale': ('These are exploitable today with classical hardware. They are not a '
                      'quantum problem and should not wait for a quantum programme.'),
        'matches': lambda a: a.quantum_impact == 'broken_classically',
    },
    {
        'wave': 2,
        'title': 'Upgrade cryptographic providers',
        'rationale': ('Libraries, runtimes and container images must expose ML-KEM and ML-DSA '
                      'before anything above them can use them. This wave unblocks every '
                      'later wave and is mostly dependency bumps.'),
        'matches': lambda a: a.artifact_type in ('library', 'binary', 'container-image'),
    },
    {
        'wave': 3,
        'title': 'Raise protocol floors',
        'rationale': ('TLS 1.2 and earlier cannot negotiate a hybrid key-exchange group at '
                      'all, so the protocol floor has to move before PQC key agreement is '
                      'even expressible on the wire.'),
        'matches': lambda a: a.artifact_type in ('protocol', 'configuration', 'tls-endpoint'),
    },
    {
        'wave': 4,
        'title': 'Migrate key agreement (harvest-now-decrypt-later)',
        'rationale': ('Recorded handshakes protected by ECDH, X25519 or finite-field DH are '
                      'decryptable retroactively the moment a CRQC exists. Confidentiality '
                      'of data already in flight depends on this wave, which is why it '
                      'precedes signatures.'),
        'matches': lambda a: a.category in ('key-agreement', 'kem', 'asymmetric-encryption',
                                            'cipher-suite'),
    },
    {
        'wave': 5,
        'title': 'Migrate signatures, certificates and key material',
        'rationale': ('Signature forgery requires a live CRQC rather than stored ciphertext, '
                      'so this wave has real deadline pressure but no retroactive exposure. '
                      'Composite certificates allow migration before every verifier is ready.'),
        'matches': lambda a: a.category in ('signature', 'certificate', 'private-key') or
                             a.artifact_type in ('certificate', 'key'),
    },
    {
        'wave': 6,
        'title': 'Vendor-gated hardware and managed services',
        'rationale': ('HSM firmware and cloud KMS key types are outside your release cycle. '
                      'Track vendor roadmaps and plan the cutover around them.'),
        'matches': lambda a: a.artifact_type in ('hardware', 'cloud-service'),
    },
    {
        'wave': 7,
        'title': 'Strengthen symmetric parameters',
        'rationale': ('Grover halves effective symmetric key length. AES-128 to AES-256 and '
                      'SHA-256 to SHA-384 are parameter changes with no protocol impact, so '
                      'they are safe to schedule last.'),
        'matches': lambda a: a.quantum_impact == 'grover',
    },
]


def _wave_for(a: Artifact) -> int | None:
    """Which wave owns this artifact. None means nothing to do."""
    if a.quantum_impact in ('pq_safe',):
        return None
    if a.quantum_impact == 'classical_ok' and a.artifact_type == 'algorithm-use':
        return None
    for w in WAVES:
        if w['matches'](a):
            return w['wave']
    if a.quantum_impact in ('shor_broken', 'grover'):
        return 5
    return None


def work_unit_effort(artifacts: list[Artifact]) -> tuple[int, int]:
    """Deduplicated effort for a set of artifacts: (engineer_days, work_units).

    One file plus one replacement target is one piece of work regardless of how
    many findings it produced. Summing raw finding counts would triple-count a
    single `Cipher(algorithms.AES(key), modes.CBC(iv))`, which reads as three
    findings and is one edit.

    Factored out of `build_plan` so the wave totals and the per-service totals in
    `services.service_rollup` cannot drift apart: two implementations of the same
    dedup rule is two answers to "what does this cost".
    """
    work_units: dict[tuple, int] = {}
    for a in artifacts:
        rec = a.recommendation or {}
        unit = (a.evidence.file_path, rec.get('target') or a.name)
        days = rec.get('effort_days', EFFORT_DAYS['medium'])
        work_units[unit] = max(work_units.get(unit, 0), days)
    return sum(work_units.values()), len(work_units)


def build_plan(artifacts: list[Artifact], crqc_year: int, engineers: int = 4) -> dict:
    """Group the inventory into ordered migration waves with effort and cost.

    Effort is deduplicated by (target algorithm, file) because migrating one
    call site fixes every finding on that line. Summing raw finding counts would
    triple-count a single `Cipher(algorithms.AES(key), modes.CBC(iv))`.
    """
    buckets: dict[int, list[Artifact]] = defaultdict(list)
    for a in artifacts:
        w = _wave_for(a)
        if w is not None:
            buckets[w].append(a)

    waves = []
    total_days = 0
    for spec in WAVES:
        items = buckets.get(spec['wave'], [])
        if not items:
            continue

        effort_days, unit_count = work_unit_effort(items)
        total_days += effort_days

        targets = sorted({(a.recommendation or {}).get('target')
                          for a in items if (a.recommendation or {}).get('target')})
        mosca_count = sum(1 for a in items if a.mosca_violated)
        crit_count = sum(1 for a in items if a.severity in ('critical', 'high'))

        waves.append({
            'wave': spec['wave'],
            'title': spec['title'],
            'rationale': spec['rationale'],
            'artifact_count': len(items),
            'work_units': unit_count,
            'effort_days': effort_days,
            'mosca_violations': mosca_count,
            'critical_or_high': crit_count,
            'targets': targets[:8],
            'artifact_ids': [a.id for a in sorted(items, key=lambda x: -x.risk_score)],
            'top_findings': [{
                'id': a.id, 'name': a.name, 'severity': a.severity,
                'risk_score': a.risk_score,
                'location': a.evidence.file_path,
                'line': a.evidence.line,
                'target': (a.recommendation or {}).get('target'),
                'hybrid': (a.recommendation or {}).get('hybrid'),
            } for a in sorted(items, key=lambda x: -x.risk_score)[:6]],
        })

    # Schedule: waves run sequentially, each at the assumed team capacity, and we
    # check the finish date against the CRQC horizon.
    return {
        'waves': waves,
        'total_effort_days': total_days,
        'total_work_units': sum(w['work_units'] for w in waves),
        'crqc_year': crqc_year,
        'years_until_crqc': crqc_year - CURRENT_YEAR,
        'schedule': schedule_waves(waves, crqc_year, engineers=engineers),
        'nothing_to_do': sum(1 for a in artifacts if _wave_for(a) is None),
    }


def schedule_waves(waves: list[dict], crqc_year: int, engineers: int = 4,
                   days_per_month: float = 18.0) -> dict:
    """Turn effort into calendar months and compare against the CRQC deadline.

    days_per_month is deliberately 18, not 22: nobody migrates cryptography full
    time. Assuming otherwise produces a plan that misses.

    Side effect by design: each wave dict is annotated with its start_month and
    end_month so the caller can render a timeline without re-deriving the
    sequence and risking a different answer from the schedule.
    """
    capacity_per_month = engineers * days_per_month
    cursor = 0.0
    rows = []
    for w in waves:
        months = w['effort_days'] / capacity_per_month
        w['start_month'] = round(cursor, 1)
        w['end_month'] = round(cursor + months, 1)
        w['months'] = round(months, 1)
        rows.append({
            'wave': w['wave'],
            'title': w['title'],
            'start_month': w['start_month'],
            'end_month': w['end_month'],
            'months': w['months'],
        })
        cursor += months
    finish_exact = CURRENT_YEAR + cursor / 12
    finish_year = int(finish_exact)
    finish_quarter = min(4, int((finish_exact - finish_year) * 4) + 1)
    return {
        'engineers': engineers,
        'engineers_assumed': engineers,      # kept: older result files read this
        'days_per_engineer_month': days_per_month,
        'total_days': sum(w['effort_days'] for w in waves),
        'total_months': round(cursor, 1),
        'finish_year': finish_year,
        'finish_label': f'Q{finish_quarter} {finish_year}',
        'crqc_year': crqc_year,
        'meets_deadline': finish_exact <= crqc_year,
        'slack_years': round(crqc_year - finish_exact, 1),
        'rows': rows,
    }


def simulate(artifact_dicts: list[dict], crqc_year: int, data_lifetime_years: int = 5,
             migration_months: int = 18, engineers: int = 4) -> dict:
    """Re-run the full risk model over a stored inventory with new assumptions.

    Pure: takes serialised artifacts, returns serialised results. No filesystem,
    no rescan. This is the engine behind the interactive assumption sliders.
    """
    artifacts = [hydrate_artifact(d) for d in artifact_dicts]
    # Clear anything cached from the previous run so nothing leaks between
    # simulations -- lifetime_years is the dangerous one, since estimate_lifetime
    # short-circuits when it is already set.
    for a in artifacts:
        a.lifetime_years = None
    analyze(artifacts, crqc_year=crqc_year, default_lifetime=data_lifetime_years,
            default_migration_months=migration_months)

    by_sev: dict[str, int] = defaultdict(int)
    by_impact: dict[str, int] = defaultdict(int)
    by_type: dict[str, int] = defaultdict(int)
    by_criticality: dict[str, int] = defaultdict(int)
    vulnerable = mosca = 0
    hndl_sum = 0.0
    hndl_n = 0
    for a in artifacts:
        by_sev[a.severity] += 1
        by_impact[a.quantum_impact] += 1
        by_type[a.artifact_type] += 1
        by_criticality[a.business_criticality] += 1
        if a.quantum_impact in ('shor_broken', 'grover'):
            vulnerable += 1
        if a.mosca_violated:
            mosca += 1
        if a.hndl_exposure is not None:
            hndl_sum += a.hndl_exposure
            hndl_n += 1

    plan = build_plan(artifacts, crqc_year, engineers=engineers)
    top = sorted(artifacts, key=lambda a: -a.risk_score)[:12]
    return {
        'assumptions': {
            'crqc_year': crqc_year,
            'data_lifetime_years': data_lifetime_years,
            'migration_months': migration_months,
            'engineers': engineers,
            'current_year': CURRENT_YEAR,
            'years_until_crqc': crqc_year - CURRENT_YEAR,
        },
        'summary': {
            'artifacts': len(artifacts),
            'by_severity': dict(by_sev),
            'by_impact': dict(by_impact),
            'by_type': dict(by_type),
            'by_criticality': dict(by_criticality),
            'quantum_vulnerable': vulnerable,
            'quantum_vulnerable_pct': round(100.0 * vulnerable / max(1, len(artifacts)), 1),
            'mosca_violations': mosca,
            'mosca_violation_pct': round(100.0 * mosca / max(1, len(artifacts)), 1),
            'mean_hndl_exposure': round(hndl_sum / hndl_n, 3) if hndl_n else None,
            'migration_effort_days': plan['total_effort_days'],
            'top_risks': [{
                'id': a.id, 'name': a.name, 'risk_score': a.risk_score,
                'location': a.evidence.file_path, 'severity': a.severity,
            } for a in top],
        },
        'plan': plan,
        'artifacts': [a.to_dict() for a in artifacts],
    }


def risk_curve(artifact_dicts: list[dict], years: range | None = None,
               data_lifetime_years: int = 5, migration_months: int = 18) -> list[dict]:
    """Mosca violations as a function of the assumed CRQC year.

    Sweeping the assumption instead of picking one is the honest way to present
    this: nobody knows when a CRQC arrives, so show the shape of the risk across
    the plausible range and let the reviewer locate their own assumption on it.
    """
    years = years or range(CURRENT_YEAR + 2, CURRENT_YEAR + 25)
    out = []
    for y in years:
        sim = simulate(artifact_dicts, crqc_year=y,
                       data_lifetime_years=data_lifetime_years,
                       migration_months=migration_months)
        out.append({
            'crqc_year': y,
            'mosca_violations': sim['summary']['mosca_violations'],
            'mosca_violation_pct': sim['summary']['mosca_violation_pct'],
            'critical': sim['summary']['by_severity'].get('critical', 0),
            'high': sim['summary']['by_severity'].get('high', 0),
            'total_effort_days': sim['plan']['total_effort_days'],
            'meets_deadline': sim['plan']['schedule']['meets_deadline'],
        })
    return out


def exposure_matrix(artifacts: list[Artifact]) -> list[dict]:
    """Business-criticality vs quantum-impact grid, for the risk heatmap.

    This is the grid the console renders: it answers "what does the programme
    start on?", and the answer is the cell where high criticality meets an
    already-broken or Shor-broken primitive.

    Cells hold the count and the worst risk score, which is what makes a heatmap
    actionable rather than decorative: the reviewer sees both volume and depth.
    Each cell also carries the longest data shelf-life inside it, because a cell
    of 7-year secrets and a cell of 25-year secrets are not the same finding.
    """
    crit_order = ['critical', 'high', 'medium', 'low']
    impact_order = ['broken_classically', 'shor_broken', 'grover',
                    'unknown', 'classical_ok', 'pq_safe']
    grid: dict[tuple, dict] = {}
    for a in artifacts:
        impact = a.quantum_impact or 'unknown'
        key = (a.business_criticality, impact)
        cell = grid.setdefault(key, {'criticality': a.business_criticality,
                                     'impact': impact,
                                     'count': 0, 'max_risk': 0.0, 'mosca': 0,
                                     'vulnerable': 0, 'max_lifetime_years': 0,
                                     'lifetime_band': '0-3y'})
        cell['count'] += 1
        cell['max_risk'] = max(cell['max_risk'], a.risk_score)
        lt = max(0, a.lifetime_years or 5)
        if lt > cell['max_lifetime_years']:
            cell['max_lifetime_years'] = lt
            cell['lifetime_band'] = lifetime_band(lt)
        if a.mosca_violated:
            cell['mosca'] += 1
        if impact in ('shor_broken', 'grover'):
            cell['vulnerable'] += 1
    return sorted(grid.values(),
                  key=lambda c: (crit_order.index(c['criticality'])
                                 if c['criticality'] in crit_order else 99,
                                 impact_order.index(c['impact'])
                                 if c['impact'] in impact_order else 99))


# The top band is deliberately unbounded. Real estates contain certificates with
# absurd validity windows (1000-year notAfter dates are routine in crypto
# library test corpora), and a capped top band silently matched nothing.
LIFETIME_BANDS = [(0, 3, '0-3y'), (3, 7, '3-7y'), (7, 15, '7-15y'),
                  (15, float('inf'), '15y+')]
_BAND_ORDER = {label: i for i, (_, _, label) in enumerate(LIFETIME_BANDS)}


def lifetime_band(years: float) -> str:
    """Bucket a data shelf-life. Never raises, whatever the input."""
    years = max(0, years or 0)
    return next((label for lo, hi, label in LIFETIME_BANDS if lo <= years < hi),
                LIFETIME_BANDS[-1][2])


def lifetime_exposure(artifacts: list[Artifact]) -> list[dict]:
    """Data-lifetime vs business-criticality grid.

    Separate from `exposure_matrix` because it answers a different question:
    not "what is weak?" but "how long does the data we are protecting have to
    stay secret?" — which is the X in Mosca's inequality and the reason a
    harvest-now-decrypt-later finding outranks its raw severity.
    """
    crit_order = ['low', 'medium', 'high', 'critical']
    grid: dict[tuple, dict] = {}
    for a in artifacts:
        band = lifetime_band(a.lifetime_years or 5)
        key = (band, a.business_criticality)
        cell = grid.setdefault(key, {'lifetime_band': band,
                                     'criticality': a.business_criticality,
                                     'count': 0, 'max_risk': 0.0, 'mosca': 0,
                                     'vulnerable': 0})
        cell['count'] += 1
        cell['max_risk'] = max(cell['max_risk'], a.risk_score)
        if a.mosca_violated:
            cell['mosca'] += 1
        if a.quantum_impact in ('shor_broken', 'grover'):
            cell['vulnerable'] += 1
    # Bands must sort by duration, not alphabetically: as strings '15y+' sorts
    # before '3-7y', which would put the longest-lived data in the middle.
    return sorted(grid.values(),
                  key=lambda c: (crit_order.index(c['criticality'])
                                 if c['criticality'] in crit_order else 0,
                                 _BAND_ORDER.get(c['lifetime_band'], 0)))


def algorithm_rollup(artifacts: list[Artifact]) -> list[dict]:
    """Per-algorithm rollup: how many instances, where, and what replaces it."""
    groups: dict[str, dict] = {}
    for a in artifacts:
        g = groups.setdefault(a.name, {
            'name': a.name, 'count': 0, 'impact': a.quantum_impact,
            'category': a.category, 'max_risk': 0.0, 'mosca': 0,
            'files': set(), 'target': None, 'hybrid': None, 'effort': None,
        })
        g['count'] += 1
        g['max_risk'] = max(g['max_risk'], a.risk_score)
        if a.mosca_violated:
            g['mosca'] += 1
        g['files'].add(a.evidence.file_path)
        rec = a.recommendation or {}
        g['target'] = g['target'] or rec.get('target')
        g['hybrid'] = g['hybrid'] or rec.get('hybrid')
        g['effort'] = g['effort'] or rec.get('effort')
    out = []
    for g in groups.values():
        g['file_count'] = len(g['files'])
        del g['files']
        entry = ALGORITHMS.get(g['name'], {})
        g['nist_status'] = entry.get('nist_status')
        g['classical_bits'] = entry.get('classical_bits')
        g['pq_bits'] = entry.get('pq_bits')
        out.append(g)
    return sorted(out, key=lambda g: (-g['max_risk'], -g['count']))
