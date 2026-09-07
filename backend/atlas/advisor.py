"""Constraint-aware PQC replacement advisor.

`risk.build_recommendation` picks one replacement per artefact, which is what an
inventory row needs. It is not what a migration decision needs, because the right
answer depends on where the thing runs: a firmware signing key and a public TLS
frontend and a 25-year document archive get three different answers from the same
starting algorithm, and the reasoning behind each is the part worth arguing with.

This module makes that reasoning explicit. Every candidate is scored, every
rejection names the constraint it violated, and nothing is silently dropped —
a candidate that lost is more informative than a candidate that vanished.

Scoring
-------
Hard constraints first. A candidate that fails one is `rejected` and carries the
specific blocker; it stays in the list with rank and score so the ordering is
still visible. Hard constraints are:

  * NIST category below the profile's `min_nist_level`
  * wire cost above the profile's `wire_budget_bytes`
  * reference CPU cost above the profile's `cpu_budget_ms`
  * stateful key management when the profile cannot accept it
  * non-hybrid when the profile requires hybrid, or hybrid when it forbids it

Surviving candidates are scored out of 100 from four terms, weights stated here
and echoed in every result's `assumptions` so nobody has to read this file to
know how a number was produced:

  standardisation  40   FIPS-final beats draft beats pre-standard. A migration
                        to a moving wire format is a migration you do twice.
  security margin  25   NIST category against the profile's floor.
  wire cost        20   bytes on the wire relative to the profile's budget, or
                        relative to the current algorithm when it has none.
  cpu cost         15   reference cost per operation, same treatment.

The weights are a judgement, not a measurement. They are round numbers on
purpose: a 37.4/22.6 split would imply a calibration that does not exist.

Performance figures
-------------------
Every size and cost figure comes from `knowledge_base.ALGORITHMS[...]['perf']`.
Sizes are exact parameter-set values from FIPS 203/204/205 and the relevant
drafts. `ops_ms` figures are relative indicators only: they were not measured on
this machine or any specific machine, and absolute latency depends on the
implementation, the CPU and whether AVX2/NEON paths are compiled in. They are
used for ordering candidates, never presented as a benchmark.
"""
from __future__ import annotations

from collections import defaultdict

from .knowledge_base import ALGORITHMS, canonical_algorithm
from .models import Artifact
from .risk import EFFORT_DAYS

# Bytes of TCP payload in one segment at a 1500-byte MTU. Used to translate a
# wire delta into something an operator can reason about: "one more round trip"
# lands differently than "+2240 bytes".
MSS_BYTES = 1460

SCORE_WEIGHTS = {
    'standardisation': 40,
    'security_margin': 25,
    'wire_cost': 20,
    'cpu_cost': 15,
}

# How settled the wire format is. A pre-standard format means migrating twice.
STANDARDISATION_SCORE = {
    'fips-final': 1.0,      # FIPS 203/204/205, SP 800-208
    'hybrid-draft': 0.85,   # IETF hybrid groups: deployed at scale, spec in flight
    'fips-draft': 0.55,     # FIPS 206 (FN-DSA) and similar
    'pre-standard': 0.15,   # Kyber/Dilithium round-3 wire formats
    'none': 0.0,
}

# Stateful signature schemes. One-time key reuse is a catastrophic, silent
# failure, so statefulness is a hard constraint rather than a scoring penalty.
STATEFUL = {'LMS', 'XMSS', 'HSS', 'XMSS-MT'}

WORKLOAD_PROFILES: dict[str, dict] = {
    'tls-frontend': {
        'label': 'Public TLS frontend',
        'description': ('High handshake rate, arbitrary client population. Whatever '
                        'is deployed has to interoperate with clients you do not '
                        'control, which is what makes hybrid the only deployable '
                        'answer today.'),
        'wire_budget_bytes': 3000,
        'cpu_budget_ms': 2.0,
        'min_nist_level': 3,
        'hybrid_required': True,
        'stateful_ok': False,
        # Not a mandate — a deployment fact. Chrome, Firefox and Cloudflare's
        # edge negotiate X25519MLKEM768 by default, so it is the group that
        # actually completes a handshake with the client population today. A
        # higher-category hybrid that nothing negotiates is a worse answer for
        # this profile than a level-3 one that everything does.
        'prefer': ('X25519MLKEM768',),
        'prefer_reason': 'already negotiated by default by mainstream browsers and CDNs',
        'notes': ('Chrome and Firefox negotiate X25519MLKEM768 by default, so the '
                  'hybrid group is the interoperable choice and pure ML-KEM is not '
                  'yet. Budget allows roughly two extra segments per handshake.'),
    },
    'internal-mtls': {
        'label': 'Internal mutual TLS',
        'description': ('Both ends are yours, so pure post-quantum can be deployed '
                        'as soon as both sides support it. No third-party client to '
                        'wait for.'),
        'wire_budget_bytes': 8000,
        'cpu_budget_ms': 5.0,
        'min_nist_level': 3,
        'hybrid_required': None,
        'stateful_ok': False,
        'notes': ('Controlled fleet: the hybrid step is optional insurance rather '
                  'than an interop requirement.'),
    },
    'firmware-signing': {
        'label': 'Firmware and boot signing',
        'description': ('A small number of signatures, verified by a constrained '
                        'bootloader that may not be updatable. Statefulness is '
                        'acceptable because signing happens in one controlled place.'),
        'wire_budget_bytes': None,
        'cpu_budget_ms': None,
        'min_nist_level': 1,
        'hybrid_required': None,
        'stateful_ok': True,
        'notes': ('SP 800-208 stateful hash-based signatures are named by CNSA 2.0 '
                  'specifically for this case: the verifier is tiny and the '
                  'security argument rests only on a hash function. Requires '
                  'disciplined state management at the signer.'),
    },
    'code-signing': {
        'label': 'Software and release signing',
        'description': ('Long-lived trust with a diverse verifier population and '
                        'signing spread across CI systems. State cannot be kept '
                        'reliably, so stateful schemes are out.'),
        'wire_budget_bytes': None,
        'cpu_budget_ms': 500.0,
        'min_nist_level': 2,
        'hybrid_required': None,
        'stateful_ok': False,
        'notes': ('Parallel CI runners signing from the same key are exactly how '
                  'one-time keys get reused. Verification cost matters more than '
                  'signing cost because it happens far more often.'),
    },
    'document-archive': {
        'label': 'Long-term document archive',
        'description': ('Records that must verify decades from now. Signature size '
                        'is irrelevant next to the shelf-life, and the security '
                        'floor should be the highest available.'),
        'wire_budget_bytes': None,
        'cpu_budget_ms': None,
        'min_nist_level': 5,
        'hybrid_required': None,
        'stateful_ok': False,
        'notes': ('Highest NIST category on the assumption that nobody re-signs a '
                  '25-year archive twice. Hash-based schemes are attractive here '
                  'because their security rests on the fewest assumptions.'),
    },
    'iot-constrained': {
        'label': 'Constrained IoT device',
        'description': ('Hard ceiling on both bytes and cycles. Often a single '
                        'datagram, frequently no fragmentation, sometimes no '
                        'firmware update path at all.'),
        'wire_budget_bytes': 1400,
        'cpu_budget_ms': 50.0,
        'min_nist_level': 1,
        'hybrid_required': False,
        'stateful_ok': False,
        'notes': ('A 1400-byte budget is one datagram inside a 1500-byte MTU. '
                  'Hybrid is excluded because paying for two key exchanges is '
                  'exactly what this profile cannot afford.'),
    },
    'national-security': {
        'label': 'National-security system (CNSA 2.0)',
        'description': ('CNSA 2.0 mandates specific parameter sets. The suite is '
                        'the constraint; latency and size are not negotiable '
                        'against it.'),
        'wire_budget_bytes': None,
        'cpu_budget_ms': None,
        'min_nist_level': 5,
        'hybrid_required': None,
        'stateful_ok': True,
        # CNSA 2.0 names exact algorithms, and NSA has stated hybrid is not
        # required for CNSA 2.0 compliance. So the mandated set wins outright
        # here rather than competing on score with a hybrid group that would
        # also clear the level-5 floor.
        'mandated': ('ML-KEM-1024', 'ML-DSA-87', 'LMS', 'XMSS'),
        'notes': ('ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/512, and LMS/XMSS for '
                  'software and firmware signing. Level 5 floor is what excludes '
                  'ML-KEM-768 and ML-DSA-65 here even though both are FIPS-final.'),
    },
    'payments-hsm': {
        'label': 'Payments HSM and KMS',
        'description': ('The binding constraint is vendor firmware, not your own '
                        'release cycle. Choose what hardware will actually support, '
                        'and treat the vendor roadmap as the schedule.'),
        'wire_budget_bytes': None,
        'cpu_budget_ms': 100.0,
        'min_nist_level': 3,
        'hybrid_required': None,
        'stateful_ok': False,
        'notes': ('FIPS-final parameter sets only: an HSM vendor will not certify '
                  'a draft wire format, and PCI evaluation lags FIPS validation.'),
    },
}

DEFAULT_PROFILE = 'internal-mtls'

# Candidate pools per role. Every name must be a knowledge-base key so the perf
# figures come from one place.
CANDIDATES: dict[str, list[str]] = {
    'kem': ['X25519MLKEM768', 'SecP384r1MLKEM1024', 'ML-KEM-512', 'ML-KEM-768',
            'ML-KEM-1024', 'SecP256r1MLKEM768'],
    'signature': ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-128s',
                  'SLH-DSA-128f', 'SLH-DSA-256s', 'Falcon-512', 'LMS', 'XMSS'],
    'symmetric': ['AES-256'],
    'hash': ['SHA-384', 'SHA-512', 'SHA-3-512'],
    'mac': ['HMAC'],
}

# Primitive -> role. `combiner` is a hybrid KEM group in this knowledge base.
_ROLE_BY_PRIMITIVE = {
    'kem': 'kem', 'key-agree': 'kem', 'pke': 'kem', 'combiner': 'kem',
    'signature': 'signature',
    'block-cipher': 'symmetric', 'stream-cipher': 'symmetric', 'ae': 'symmetric',
    'hash': 'hash', 'xof': 'hash',
    'mac': 'mac',
}

# Algorithms that serve both key transport and signing. RSA is the whole reason
# this set exists: `primitive: pke` describes only half of what RSA is used for,
# and advising a KEM for a firmware signing key would be plainly wrong. When the
# workload is a signing workload, these resolve to the signature role.
DUAL_USE = {'RSA', 'RSA-KEM'}
SIGNING_PROFILES = {'firmware-signing', 'code-signing', 'document-archive'}

# Profiles whose combiner (hybrid) entries are signature composites rather than
# KEM groups. Kept explicit rather than inferred so a new composite added to the
# knowledge base cannot silently appear in the KEM pool.
_SIGNATURE_COMBINERS = ('ML-DSA-65+ECDSA-P256', 'ML-DSA-65+Ed25519')


def resolve_role(canon: str, entry: dict | None, profile: str) -> str:
    """Which primitive role a replacement has to fill.

    Driven by the knowledge base, with one deliberate override: a dual-use
    algorithm in a signing workload needs a signature, not a KEM.
    """
    role = _ROLE_BY_PRIMITIVE.get((entry or {}).get('primitive', ''), 'none')
    if canon in DUAL_USE and profile in SIGNING_PROFILES:
        return 'signature'
    return role

# Hybrid groups: a classical primitive combined with a PQ KEM. Recognised by
# primitive rather than by name so a new group added to the knowledge base is
# picked up without touching this module.
def _is_hybrid(name: str, entry: dict) -> bool:
    return entry.get('primitive') == 'combiner' or '+' in name


def _standardisation_tier(entry: dict) -> str:
    status = str(entry.get('nist_status', '')).lower()
    if 'fips 20' in status and 'draft' not in status:
        return 'fips-final'
    if 'sp 800-208' in status:
        return 'fips-final'
    if 'draft' in status and 'fips' in status:
        return 'fips-draft'
    if 'hybrid' in status:
        return 'hybrid-draft'
    if 'pre-standard' in status or 'round' in status:
        return 'pre-standard'
    if status in ('active',):
        return 'fips-final'
    return 'none'


def _wire_bytes(entry: dict, role: str) -> int | None:
    """Bytes this algorithm puts on the wire for one exchange or one signature.

    KEM: public key plus ciphertext, because a handshake carries both.
    Signature: public key plus signature, because a certificate carries both.
    Symmetric and hash: no asymmetric wire cost, so None rather than 0 — the
    distinction between "free" and "not applicable" matters in the UI.
    """
    perf = entry.get('perf') or {}
    if role == 'kem':
        pub, ct = perf.get('pub_bytes'), perf.get('ct_bytes')
        if pub is None and ct is None:
            return None
        return (pub or 0) + (ct or 0)
    if role == 'signature':
        pub, sig = perf.get('pub_bytes'), perf.get('sig_bytes')
        if pub is None and sig is None:
            return None
        return (pub or 0) + (sig or 0)
    return None


def _role_of(entry: dict | None) -> str:
    if not entry:
        return 'none'
    return _ROLE_BY_PRIMITIVE.get(entry.get('primitive', ''), 'none')


def _segments(delta: int | None) -> str:
    if delta is None:
        return 'no asymmetric wire cost to compare'
    if delta <= 0:
        return f'{abs(delta)} bytes smaller on the wire'
    extra = delta / MSS_BYTES
    if extra < 1:
        return (f'+{delta} bytes, under one extra {MSS_BYTES}-byte segment')
    return (f'+{delta} bytes, about {extra:.1f} extra {MSS_BYTES}-byte segments '
            'per exchange')


def _hard_constraints(name: str, entry: dict, role: str, profile: dict,
                      min_level: int, current_wire: int | None) -> list[str]:
    """Every hard constraint this candidate violates, named specifically."""
    blockers: list[str] = []

    level = entry.get('nist_pq_level') or 0
    # Symmetric and hash algorithms have no NIST PQC category; judge them on
    # post-quantum bits instead of failing them for a field they cannot have.
    if role in ('kem', 'signature'):
        if level < min_level:
            blockers.append(
                f'NIST category {level} is below the {profile["label"]} floor of '
                f'category {min_level}')
    elif (entry.get('pq_bits') or 0) < 128:
        blockers.append(
            f'{entry.get("pq_bits", 0)} bits of post-quantum strength is below the '
            '128-bit floor')

    wire = _wire_bytes(entry, role)
    budget = profile.get('wire_budget_bytes')
    if budget is not None and wire is not None and wire > budget:
        blockers.append(
            f'{wire} bytes on the wire exceeds the {profile["label"]} budget of '
            f'{budget} bytes by {wire - budget}')

    ops = (entry.get('perf') or {}).get('ops_ms')
    cpu_budget = profile.get('cpu_budget_ms')
    if cpu_budget is not None and ops is not None and ops > cpu_budget:
        blockers.append(
            f'{ops} ms per operation (reference figure) exceeds the '
            f'{cpu_budget} ms budget for {profile["label"]}')

    if name in STATEFUL and not profile.get('stateful_ok'):
        blockers.append(
            'stateful key management: reusing a one-time key silently destroys the '
            f'signature scheme, and {profile["label"]} cannot guarantee single-use '
            'state')

    hybrid_required = profile.get('hybrid_required')
    hybrid = _is_hybrid(name, entry)
    if hybrid_required is True and not hybrid:
        blockers.append(
            f'{profile["label"]} requires a hybrid group for interoperability with '
            'clients that do not yet negotiate pure post-quantum')
    if hybrid_required is False and hybrid:
        blockers.append(
            f'{profile["label"]} cannot afford a hybrid group: it pays for both a '
            'classical and a post-quantum exchange')

    if current_wire is not None and wire is not None and wire < current_wire:
        # Not a blocker, just worth noting nothing here.
        pass
    return blockers


def _score(name: str, entry: dict, role: str, profile: dict, min_level: int,
           current: dict | None) -> tuple[float, list[str]]:
    reasons: list[str] = []
    tier = _standardisation_tier(entry)
    std = STANDARDISATION_SCORE[tier] * SCORE_WEIGHTS['standardisation']
    if tier == 'fips-final':
        reasons.append(f'standardised: {entry.get("nist_status")}')
    elif tier == 'hybrid-draft':
        reasons.append('hybrid group already deployed at internet scale')
    elif tier == 'fips-draft':
        reasons.append(f'standardisation still in draft ({entry.get("nist_status")})')
    else:
        reasons.append(f'wire format is not settled ({entry.get("nist_status")})')

    level = entry.get('nist_pq_level') or 0
    if role in ('kem', 'signature') and min_level:
        margin = min(1.0, level / max(1, min_level))
        if level > min_level:
            reasons.append(f'NIST category {level}, above the category {min_level} floor')
        elif level == min_level:
            reasons.append(f'NIST category {level}, exactly the required floor')
    else:
        margin = min(1.0, (entry.get('pq_bits') or 0) / 128)
        reasons.append(f'{entry.get("pq_bits", 0)} bits of post-quantum strength')
    sec = margin * SCORE_WEIGHTS['security_margin']

    wire = _wire_bytes(entry, role)
    budget = profile.get('wire_budget_bytes')
    if wire is None:
        # Unknown wire cost must not score as free — that would rank an
        # unmeasured algorithm above a measured small one purely for being
        # undocumented. Half marks, and the gap is stated.
        wire_score = SCORE_WEIGHTS['wire_cost'] * 0.5
        reasons.append('wire cost is not recorded for this algorithm; scored '
                       'neutrally rather than assumed free')
    elif budget:
        wire_score = max(0.0, 1 - wire / budget) * SCORE_WEIGHTS['wire_cost']
        if wire <= budget * 0.5:
            reasons.append(f'{wire} bytes uses under half the wire budget')
    else:
        # No budget: score relative to the smallest candidate for this role, so
        # size still orders the list without an invented ceiling.
        smallest = min((w for w in (_wire_bytes(ALGORITHMS[n], role)
                                    for n in CANDIDATES.get(role, []))
                        if w), default=None)
        if smallest and wire:
            wire_score = (smallest / wire) * SCORE_WEIGHTS['wire_cost']
        else:
            wire_score = SCORE_WEIGHTS['wire_cost'] * 0.5
    ops = (entry.get('perf') or {}).get('ops_ms')
    cpu_budget = profile.get('cpu_budget_ms')
    if ops is None:
        cpu_score = SCORE_WEIGHTS['cpu_cost'] * 0.5
    elif cpu_budget:
        cpu_score = max(0.0, 1 - ops / cpu_budget) * SCORE_WEIGHTS['cpu_cost']
    else:
        fastest = min((o for o in ((ALGORITHMS[n].get('perf') or {}).get('ops_ms')
                                   for n in CANDIDATES.get(role, []))
                       if o), default=None)
        cpu_score = ((fastest / ops) * SCORE_WEIGHTS['cpu_cost']
                     if fastest else SCORE_WEIGHTS['cpu_cost'] * 0.5)

    if current and current.get('name') and _is_hybrid(name, entry):
        reasons.append('classical component keeps the connection safe if the '
                       'post-quantum one is later broken')

    return round(std + sec + wire_score + cpu_score, 1), reasons


def recommend(current_algorithm: str, profile: str = DEFAULT_PROFILE, *,
              shelf_life_years: int | None = None,
              override_min_level: int | None = None,
              role: str | None = None) -> dict:
    """Score every candidate replacement for one algorithm in one workload."""
    if profile not in WORKLOAD_PROFILES:
        raise KeyError(f'unknown workload profile: {profile!r}. '
                       f'Known: {sorted(WORKLOAD_PROFILES)}')
    prof = WORKLOAD_PROFILES[profile]
    canon, entry = canonical_algorithm(current_algorithm)
    role = role or resolve_role(canon, entry, profile)

    min_level = override_min_level if override_min_level is not None else prof['min_nist_level']
    assumptions = [
        f'Scoring weights: {", ".join(f"{k} {v}" for k, v in SCORE_WEIGHTS.items())} '
        '(out of 100). Round numbers on purpose — they are a judgement, not a '
        'calibration.',
        'Hard constraints reject rather than penalise: NIST category floor, wire '
        'budget, CPU budget, statefulness, hybrid requirement.',
        'ops_ms figures are relative indicators from published parameter tables, '
        'not benchmarks measured on this machine. Absolute latency depends on the '
        'implementation and CPU.',
        f'Wire cost is translated into {MSS_BYTES}-byte TCP segments, which assumes '
        'a 1500-byte MTU and no fragmentation.',
    ]

    # Shelf-life raises the security floor: a 25-year record should not be
    # protected at the minimum acceptable category today.
    if shelf_life_years and shelf_life_years >= 20 and min_level < 5:
        assumptions.append(
            f'{shelf_life_years}-year shelf-life raised the NIST category floor from '
            f'{min_level} to 5: nobody re-signs a multi-decade archive twice.')
        min_level = 5
    elif shelf_life_years and shelf_life_years >= 10 and min_level < 3:
        assumptions.append(
            f'{shelf_life_years}-year shelf-life raised the NIST category floor from '
            f'{min_level} to 3.')
        min_level = 3

    current = None
    if entry:
        current = {
            'name': canon,
            'impact': entry.get('impact'),
            'classical_bits': entry.get('classical_bits'),
            'pq_bits': entry.get('pq_bits'),
            'nist_status': entry.get('nist_status'),
            'primitive': entry.get('primitive'),
            'perf': entry.get('perf'),
            'wire_bytes': _wire_bytes(entry, role),
        }
    current_wire = current['wire_bytes'] if current else None
    current_ops = ((entry or {}).get('perf') or {}).get('ops_ms')

    pool = CANDIDATES.get(role, [])
    candidates: list[dict] = []
    for name in pool:
        c_entry = ALGORITHMS.get(name)
        if c_entry is None:
            # A candidate pool that names an algorithm the knowledge base does not
            # have is a bug, not a runtime condition. Surface it rather than
            # skipping quietly.
            raise KeyError(f'candidate {name!r} is not in the knowledge base')
        blockers = _hard_constraints(name, c_entry, role, prof, min_level, current_wire)
        score, reasons = _score(name, c_entry, role, prof, min_level, current)
        wire = _wire_bytes(c_entry, role)
        ops = (c_entry.get('perf') or {}).get('ops_ms')
        delta = None if (wire is None or current_wire is None) else wire - current_wire
        candidates.append({
            'name': name,
            'verdict': 'rejected' if blockers else 'viable',
            'score': score,
            'nist_level': c_entry.get('nist_pq_level') or 0,
            'nist_status': c_entry.get('nist_status'),
            'hybrid': _is_hybrid(name, c_entry),
            'stateful': name in STATEFUL,
            'wire_bytes': wire,
            'wire_delta_bytes': delta,
            'ops_ms': ops,
            'ops_delta_ratio': (round(ops / current_ops, 2)
                                if (ops and current_ops) else None),
            'handshake_delta_note': _segments(delta),
            'reasons': reasons,
            'blockers': blockers,
            'interop_note': _interop_note(name, c_entry, role),
            'standard_ref': c_entry.get('nist_status'),
        })

    viable = [c for c in candidates if c['verdict'] == 'viable']
    # Two overrides sort ahead of raw score, both for stated reasons:
    #   `mandated` — the profile quotes a requirement (CNSA 2.0 names algorithms).
    #   `prefer`   — the profile has a deployment reality that outranks a marginal
    #                security-margin win (the browser-default TLS group).
    mandated = set(prof.get('mandated') or ())
    preferred = set(prof.get('prefer') or ())
    viable.sort(key=lambda c: (c['name'] not in mandated,
                               c['name'] not in preferred, -c['score']))
    for c in viable:
        if c['name'] in mandated:
            c['reasons'].insert(0, f'named by {prof["label"]} as a required algorithm')
        elif c['name'] in preferred:
            c['reasons'].insert(0, f'interoperability: {prof["prefer_reason"]}')
    if viable:
        viable[0]['verdict'] = 'recommended'
    order = {c['name']: i for i, c in enumerate(viable)}
    candidates.sort(key=lambda c: (c['verdict'] == 'rejected',
                                   order.get(c['name'], 999), -c['score']))
    for i, c in enumerate(candidates, start=1):
        c['rank'] = i

    chosen = viable[0] if viable else None
    runner = viable[1] if len(viable) > 1 else None
    if chosen is None:
        decision = {
            'choose': None,
            'because': ('No candidate satisfies every hard constraint for '
                        f'{prof["label"]}. Relax a constraint or accept a named '
                        'blocker explicitly — this is a real answer, not a gap.'),
            'runner_up': None,
            'tradeoff': None,
        }
    else:
        decision = {
            'choose': chosen['name'],
            'because': (f'{chosen["name"]} scores {chosen["score"]} of 100 for '
                        f'{prof["label"]}: ' + '; '.join(chosen['reasons'][:2]) + '.'),
            'runner_up': runner['name'] if runner else None,
            'tradeoff': _tradeoff(chosen, runner, current),
        }

    return {
        'input': {
            'algorithm': current_algorithm,
            'canonical': canon,
            'recognised': entry is not None,
            'profile': profile,
            'shelf_life_years': shelf_life_years,
            'min_nist_level_applied': min_level,
        },
        'current': current,
        'profile': {'key': profile, **prof},
        'role': role,
        'candidates': candidates,
        'decision': decision,
        'assumptions': assumptions,
    }


def _interop_note(name: str, entry: dict, role: str) -> str:
    if _is_hybrid(name, entry):
        return ('Negotiates with clients that only understand the classical half, '
                'so it can be deployed before the fleet is ready.')
    if name in STATEFUL:
        return ('Verifier is simple and widely implementable; the signer must keep '
                'state, which constrains where signing can happen.')
    if role == 'kem':
        return ('Requires both peers to support the group. Fine on a controlled '
                'fleet, premature on the public internet.')
    if role == 'signature':
        return ('Verifiers must understand the new algorithm. Composite '
                'certificates are the transitional path where they do not.')
    return 'Parameter change only; no protocol negotiation involved.'


def _tradeoff(chosen: dict, runner: dict | None, current: dict | None) -> str:
    parts = []
    if current and chosen['wire_delta_bytes'] is not None:
        parts.append(f'{chosen["handshake_delta_note"]} versus {current["name"]}')
    if chosen['ops_delta_ratio'] and chosen['ops_delta_ratio'] > 1.2:
        parts.append(f'roughly {chosen["ops_delta_ratio"]}x the per-operation cost')
    if runner:
        parts.append(f'{runner["name"]} was the alternative at {runner["score"]}')
    if not parts:
        return 'No material cost against the current algorithm.'
    return '; '.join(parts) + '.'


# ---------------------------------------------------------------------------
# Inventory rollup
# ---------------------------------------------------------------------------

# Path and type signals that imply a workload. First match wins, so the most
# specific signals come first. Documented here rather than buried in code because
# an inferred profile that a reviewer cannot audit is worse than no inference.
PROFILE_INFERENCE = [
    ('firmware', 'firmware-signing', 'path names firmware or a boot image'),
    ('bootloader', 'firmware-signing', 'path names a bootloader'),
    ('/boot', 'firmware-signing', 'path is a boot directory'),
    ('hsm', 'payments-hsm', 'path names an HSM integration'),
    ('kms', 'payments-hsm', 'path names a managed key service'),
    ('archive', 'document-archive', 'path names an archive'),
    ('treasury', 'document-archive', 'treasury records have decade-scale shelf-life'),
    ('records', 'document-archive', 'path names long-term records'),
    ('ledger', 'document-archive', 'ledger data is retained for decades'),
    ('release', 'code-signing', 'path names a release pipeline'),
    ('codesign', 'code-signing', 'path names code signing'),
    ('ci/', 'code-signing', 'signing from CI cannot keep one-time-key state'),
    ('iot', 'iot-constrained', 'path names an IoT or embedded target'),
    ('embedded', 'iot-constrained', 'path names an embedded target'),
    ('edge-api', 'tls-frontend', 'edge API terminates public TLS'),
    ('gateway', 'tls-frontend', 'gateway terminates public TLS'),
    ('ingress', 'tls-frontend', 'ingress terminates public TLS'),
    ('public', 'tls-frontend', 'path names a public-facing component'),
    ('mesh', 'internal-mtls', 'service mesh is internal mutual TLS'),
    ('internal', 'internal-mtls', 'path names an internal component'),
]


def infer_profile(artifact: Artifact) -> tuple[str, str]:
    """(profile, why) for one artifact."""
    if artifact.artifact_type == 'tls-endpoint':
        return 'tls-frontend', 'observed on a live TLS handshake with an external host'
    if artifact.artifact_type in ('hardware',):
        return 'payments-hsm', 'hardware security module: vendor firmware is the constraint'
    path = (artifact.evidence.file_path or '').lower()
    for token, profile, why in PROFILE_INFERENCE:
        if token in path:
            return profile, why
    if artifact.lifetime_years and artifact.lifetime_years >= 20:
        return 'document-archive', f'{artifact.lifetime_years}-year data shelf-life'
    return DEFAULT_PROFILE, 'no stronger signal; defaulted to internal mutual TLS'


def advise_inventory(artifacts: list[Artifact],
                     profile_hint_by_service: dict[str, str] | None = None) -> dict:
    """Roll per-algorithm advice up over a whole inventory.

    Grouped by (algorithm, inferred profile) rather than by algorithm alone,
    because the same algorithm in two workloads has two right answers and merging
    them would hide the interesting half.
    """
    hints = profile_hint_by_service or {}
    groups: dict[tuple[str, str], dict] = {}
    inference_log: dict[tuple[str, str], str] = {}
    seen_names: set[str] = set()
    unadvised: set[str] = set()

    for a in artifacts:
        canon, entry = canonical_algorithm(a.name)
        seen_names.add(canon)
        role = _role_of(entry)
        if entry is None or role == 'none' or entry.get('impact') == 'pq_safe':
            # pq_safe artifacts need no replacement; unresolved ones cannot be
            # advised. Both are reported rather than counted as covered.
            if entry is None or role == 'none':
                unadvised.add(canon)
            continue

        profile = None
        path = (a.evidence.file_path or '').lower()
        for service, hinted in hints.items():
            if service.lower() in path:
                profile, why = hinted, f'explicit hint for service {service}'
                break
        if profile is None:
            profile, why = infer_profile(a)
        inference_log.setdefault((profile, why), why)

        key = (canon, profile)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {'uses': 0, 'impact': entry.get('impact'),
                               'effort_days': 0, 'files': set()}
        g['uses'] += 1
        g['files'].add(a.evidence.file_path)
        rec = a.recommendation or {}
        g['effort_days'] = max(g['effort_days'],
                               rec.get('effort_days', EFFORT_DAYS['medium']))

    rows: list[dict] = []
    total_added = 0
    worst_offender: tuple[int, str] | None = None
    for (canon, profile), g in groups.items():
        advice = recommend(canon, profile)
        chosen = advice['decision']['choose']
        delta = None
        if chosen:
            c = next(c for c in advice['candidates'] if c['name'] == chosen)
            delta = c['wire_delta_bytes']
        total = (delta or 0) * g['uses']
        total_added += max(0, total)
        if delta and (worst_offender is None or total > worst_offender[0]):
            worst_offender = (total, canon)
        rows.append({
            'current': canon,
            'uses': g['uses'],
            'files': len(g['files']),
            'impact': g['impact'],
            'profile_used': profile,
            'profile_label': WORKLOAD_PROFILES[profile]['label'],
            'choose': chosen,
            'wire_delta_bytes': delta,
            'total_wire_delta_bytes': total,
            'effort_days': g['effort_days'],
            'runner_up': advice['decision']['runner_up'],
            'because': advice['decision']['because'],
            'tradeoff': advice['decision']['tradeoff'],
            'rejected_count': sum(1 for c in advice['candidates']
                                  if c['verdict'] == 'rejected'),
        })

    rows.sort(key=lambda r: (-r['uses'], r['current']))
    advised_names = {r['current'] for r in rows}
    return {
        'by_algorithm': rows,
        'wire_impact': {
            'total_added_bytes_per_op': total_added,
            'worst_offender': worst_offender[1] if worst_offender else None,
            'note': (f'Summed across every use site: {total_added} extra bytes per '
                     'operation estate-wide, assuming one exchange per use. This is '
                     'a size figure, not a latency figure — whether it costs a round '
                     'trip depends on MTU and congestion window.'),
        },
        'profile_inference': [{'inferred_profile': p, 'why': w}
                              for (p, w) in sorted(inference_log)],
        'coverage': {
            'algorithms_seen': len(seen_names),
            'advised': len(advised_names),
            'unadvised': len(seen_names - advised_names),
            'unadvised_names': sorted(seen_names - advised_names),
            'note': ('Unadvised names are either already post-quantum, not '
                     'cryptographic primitives (libraries, services, protocols), or '
                     'unresolved by the knowledge base. Listed rather than hidden.'),
        },
    }
