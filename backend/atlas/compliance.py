"""Compliance mapping: the estate against published transition mandates.

Risk scoring answers "how bad is this". A CISO's next question is "what am I
required to have done, and by when" — a different question with a different
answer, because mandates are calendar-driven and do not care about your risk
appetite.

Three sources are modelled:

  NIST IR 8547     Transition to Post-Quantum Cryptography Standards.
                   INITIAL PUBLIC DRAFT (November 2024). Its dates are a
                   proposal, not settled policy, and every verdict derived from
                   it is labelled `draft` so nobody quotes it as law.
  NSA CNSA 2.0     Commercial National Security Algorithm Suite 2.0. Binding for
                   US national-security systems. Modelled here as the strictest
                   available bar — an organisation outside NSS scope can read it
                   as an upper bound rather than an obligation.
  NIST SP 800-131A Transitioning the Use of Cryptographic Algorithms and Key
  Rev.2            Lengths. Published, in force, and its deadlines are in the
                   past. Anything failing this is failing today.

Design constraints this module holds itself to:

* A verdict never invents a date. Where a real document gives a per-category
  timeline rather than one number, the control carries the figure it is
  confident in and states the rest in prose. Every control declares its
  `confidence`: `published` (in force), `draft` (IR 8547), or `reported` (widely
  cited but the exact figure varies by source document and category).
* `not_applicable` is a real verdict and is returned, not filtered. An analyst
  needs to see that a mandate was considered and did not bite.
* The posture score is deliberately crude and says so. A three-decimal
  compliance index computed from an unvalidated weighting would look more
  authoritative than it is; `basis` states the arithmetic in one sentence so a
  reviewer can disagree with it precisely.
"""
from __future__ import annotations

from collections import defaultdict

from .knowledge_base import ALGORITHMS, canonical_algorithm
from .models import Artifact
from .risk import CURRENT_YEAR, _version_at_least
from .crypto_services import lookup_library

# Status vocabulary, ordered worst-first. Used for sorting and for picking the
# governing verdict when several controls fire on one artifact.
STATUS_ORDER = ['disallowed', 'deprecated', 'action_required', 'compliant', 'not_applicable']
STATUS_RANK = {s: i for i, s in enumerate(STATUS_ORDER)}

# Classical asymmetric families. Shor takes all of them to zero post-quantum
# strength, which is what every mandate below is actually reacting to.
_CLASSICAL_ASYMMETRIC_PRIMITIVES = {'pke', 'signature', 'key-agree', 'kem'}

# Role words the scanners append to an algorithm name. "RSA certificate" and
# "Ed25519 private key" both need to resolve to the primitive, and the knowledge
# base's guarded substring match deliberately skips keys shorter than four
# characters so that "RSA" never matches inside another token.
_ROLE_WORDS = ('certificate', 'private key', 'public key', 'keypair', 'key pair',
               'key', 'cert', 'signature', 'suite', 'endpoint')


def _strip_role_words(raw: str) -> str:
    out = raw.strip()
    low = out.lower()
    for word in _ROLE_WORDS:
        if low.endswith(' ' + word):
            return out[: -(len(word) + 1)].strip()
    return out


def _entry_for(artifact: Artifact) -> tuple[str, dict | None]:
    """Resolve the artifact to the knowledge-base entry for its own key material.

    Order matters. The artifact name is tried first because for certificates and
    keys it names the *subject* key algorithm, which is what determines that
    artifact's own quantum exposure. `properties['signature_algorithm']` on a
    certificate names the algorithm the *issuer* signed with — a different
    finding, assessed separately by `_assess_chain_signature`. Resolving the
    subject key from the issuer's signature would report an Ed25519 certificate
    as RSA, and then score its 256-bit curve as a 256-bit RSA modulus.

    Cipher-suite decomposition and alias handling both live in the knowledge
    base; this only decides what string to hand it.
    """
    props = artifact.properties or {}
    for raw in (artifact.name, _strip_role_words(artifact.name or ''),
                props.get('algorithm'), props.get('key_algorithm'),
                props.get('signature_algorithm')):
        if not raw or not isinstance(raw, str):
            continue
        name, entry = canonical_algorithm(raw)
        if entry:
            return name, entry
    return artifact.name, None


def _is_classical_asymmetric(entry: dict | None) -> bool:
    if not entry:
        return False
    return (entry.get('primitive') in _CLASSICAL_ASYMMETRIC_PRIMITIVES
            and entry.get('impact') == 'shor_broken')


def _key_bits(artifact: Artifact, entry: dict | None) -> int | None:
    """Best available classical strength in bits.

    `properties['key_size']` is a modulus or curve size, not a security level;
    the knowledge base's `classical_bits` already carries the security level, so
    prefer it and fall back to the raw key size only for the RSA-below-2048
    control, which is expressed in modulus bits.
    """
    if entry and entry.get('classical_bits'):
        return int(entry['classical_bits'])
    return None


# ---------------------------------------------------------------------------
# NIST IR 8547 (initial public draft, November 2024)
#
# The draft's transition table deprecates 112-bit-strength classical public-key
# algorithms after 2030 and disallows all classical public-key algorithms after
# 2035. Both figures are proposals in a draft document; `confidence: draft`
# propagates that into every verdict.
# ---------------------------------------------------------------------------
IR8547_DEPRECATE_YEAR = 2030
IR8547_DISALLOW_YEAR = 2035

# ---------------------------------------------------------------------------
# NSA CNSA 2.0
#
# Approved algorithms are a short list; anything else is out of scope for new
# national-security systems. The published timeline is per-category (software
# and firmware signing first, general-purpose networking and OS later, all NSS
# by 2035). Only the two figures that are quoted consistently across NSA's own
# CNSA 2.0 material are encoded as dates:
#
#   2030  software and firmware signing exclusively CNSA 2.0
#   2035  all national-security systems exclusively CNSA 2.0
#
# The intermediate per-category milestones (browsers, servers, cloud services,
# networking equipment, operating systems) vary by category and are stated in
# prose on the control rather than as a machine-readable deadline, because
# attributing the wrong category's date to an artifact would be worse than
# attributing none.
# ---------------------------------------------------------------------------
CNSA_SIGNING_YEAR = 2030
CNSA_ALL_NSS_YEAR = 2035

CNSA_APPROVED = {
    'ML-KEM-1024': 'FIPS 203, CNSA 2.0 asymmetric key establishment',
    'ML-DSA-87': 'FIPS 204, CNSA 2.0 digital signature',
    'AES-256': 'FIPS 197, CNSA 2.0 symmetric block cipher',
    'SHA-384': 'FIPS 180-4, CNSA 2.0 hashing',
    'SHA-512': 'FIPS 180-4, CNSA 2.0 hashing',
    'LMS': 'SP 800-208, CNSA 2.0 software and firmware signing',
    'XMSS': 'SP 800-208, CNSA 2.0 software and firmware signing',
}

# Algorithms that are post-quantum and standardised but below the CNSA 2.0
# parameter floor. These are not failures in general — they are failures against
# this specific mandate, and the distinction is worth stating.
CNSA_UNDERSTRENGTH = {
    'ML-KEM-512': 'CNSA 2.0 requires ML-KEM-1024; this is NIST category 1',
    'ML-KEM-768': 'CNSA 2.0 requires ML-KEM-1024; this is NIST category 3',
    'ML-DSA-44': 'CNSA 2.0 requires ML-DSA-87; this is NIST category 2',
    'ML-DSA-65': 'CNSA 2.0 requires ML-DSA-87; this is NIST category 3',
    'AES-128': 'CNSA 2.0 requires AES-256',
    'AES-192': 'CNSA 2.0 requires AES-256',
    'SHA-256': 'CNSA 2.0 requires SHA-384 or SHA-512',
    'SLH-DSA-128s': 'CNSA 2.0 names LMS/XMSS for signing, not SLH-DSA at level 1',
}

STANDARDS: dict[str, dict] = {
    'nist-ir-8547': {
        'standard': 'NIST IR 8547, Transition to Post-Quantum Cryptography Standards',
        'standard_short': 'NIST IR 8547',
        'url_or_ref': 'NIST Internal Report 8547 ipd (initial public draft, November 2024)',
        'status': 'draft',
        'summary': (
            'Deprecates 112-bit-strength classical public-key algorithms after '
            f'{IR8547_DEPRECATE_YEAR} and disallows all classical public-key '
            f'cryptography after {IR8547_DISALLOW_YEAR}. Draft dates, not final policy.'),
    },
    'cnsa-2.0': {
        'standard': 'NSA Commercial National Security Algorithm Suite 2.0',
        'standard_short': 'CNSA 2.0',
        'url_or_ref': 'NSA CNSA 2.0 algorithm suite and FAQ',
        'status': 'published',
        'summary': (
            'ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/512, and LMS/XMSS for software '
            f'and firmware signing. Signing exclusively CNSA 2.0 by {CNSA_SIGNING_YEAR}; '
            f'all national-security systems by {CNSA_ALL_NSS_YEAR}. Applies to NSS; '
            'other organisations can read it as the strictest available bar.'),
    },
    'nist-sp-800-131a': {
        'standard': 'NIST SP 800-131A Rev.2, Transitioning Cryptographic Algorithms and Key Lengths',
        'standard_short': 'SP 800-131A',
        'url_or_ref': 'NIST Special Publication 800-131A Revision 2 (March 2019)',
        'status': 'published',
        'summary': (
            'In force today, with deadlines already past: SHA-1 disallowed for '
            'signature generation, three-key TDEA disallowed for encryption after '
            '2023, RSA below 2048 bits disallowed, MD5 never approved.'),
    },
}


def _verdict(std_key: str, control: str, status: str, note: str,
             deadline_year: int | None, year: int, confidence: str) -> dict:
    std = STANDARDS[std_key]
    return {
        'standard': std['standard'],
        'standard_short': std['standard_short'],
        'control': control,
        'status': status,
        'deadline_year': deadline_year,
        'years_remaining': None if deadline_year is None else deadline_year - year,
        'note': note,
        'confidence': confidence,
    }


# ---------------------------------------------------------------------------
# Per-standard assessment
# ---------------------------------------------------------------------------

def _assess_ir8547(artifact: Artifact, name: str, entry: dict | None,
                   year: int) -> list[dict]:
    if not _is_classical_asymmetric(entry):
        if entry and entry.get('impact') == 'pq_safe':
            return [_verdict(
                'nist-ir-8547', 'classical public-key transition', 'compliant',
                f'{name} is post-quantum; the classical public-key transition does not apply.',
                None, year, 'draft')]
        return [_verdict(
            'nist-ir-8547', 'classical public-key transition', 'not_applicable',
            f'{name} is not a classical public-key algorithm.', None, year, 'draft')]

    bits = _key_bits(artifact, entry) or 0
    basis = entry.get('bits_basis', f'{bits}-bit classical strength')

    if year > IR8547_DISALLOW_YEAR:
        status, deadline = 'disallowed', IR8547_DISALLOW_YEAR
        note = (f'{name} ({basis}) is past the draft {IR8547_DISALLOW_YEAR} disallow date '
                'for all classical public-key cryptography.')
    elif bits <= 112 and year > IR8547_DEPRECATE_YEAR:
        status, deadline = 'deprecated', IR8547_DEPRECATE_YEAR
        note = (f'{name} ({basis}) is past the draft {IR8547_DEPRECATE_YEAR} deprecation '
                f'date for 112-bit classical strength; disallowed after {IR8547_DISALLOW_YEAR}.')
    elif bits <= 112:
        status, deadline = 'action_required', IR8547_DEPRECATE_YEAR
        note = (f'{name} ({basis}) is deprecated after {IR8547_DEPRECATE_YEAR} and '
                f'disallowed after {IR8547_DISALLOW_YEAR} under the draft.')
    else:
        status, deadline = 'action_required', IR8547_DISALLOW_YEAR
        note = (f'{name} ({basis}) exceeds 112-bit strength, so it escapes the '
                f'{IR8547_DEPRECATE_YEAR} deprecation, but all classical public-key '
                f'cryptography is disallowed after {IR8547_DISALLOW_YEAR} under the draft.')

    return [_verdict('nist-ir-8547', 'classical public-key transition', status, note,
                     deadline, year, 'draft')]


def _cnsa_category(artifact: Artifact) -> tuple[str, int, str]:
    """Which CNSA 2.0 timeline this artifact sits on.

    Returns (category, deadline_year, prose). Only the signing and all-NSS dates
    are encoded; everything else carries the 2035 backstop with the intermediate
    milestone described rather than asserted.
    """
    path = (artifact.evidence.file_path or '').lower()
    name = (artifact.name or '').lower()
    signing_signal = any(k in path or k in name for k in
                         ('firmware', 'bootloader', 'boot', 'image-signing', 'codesign',
                          'code-signing', 'signing', 'update'))
    if signing_signal and artifact.category in ('signature', 'certificate', 'private-key'):
        return ('software and firmware signing', CNSA_SIGNING_YEAR,
                f'Software and firmware signing must be exclusively CNSA 2.0 by '
                f'{CNSA_SIGNING_YEAR}.')
    if artifact.artifact_type in ('tls-endpoint', 'protocol', 'configuration'):
        return ('networking and web', CNSA_ALL_NSS_YEAR,
                'NSA publishes an earlier milestone for browsers, servers and cloud '
                'services than for NSS as a whole; the exact year depends on the '
                f'category, so only the {CNSA_ALL_NSS_YEAR} backstop is scored here.')
    return ('general national-security systems', CNSA_ALL_NSS_YEAR,
            f'All national-security systems must be exclusively CNSA 2.0 by '
            f'{CNSA_ALL_NSS_YEAR}.')


def _assess_cnsa(artifact: Artifact, name: str, entry: dict | None,
                 year: int) -> list[dict]:
    category, deadline, prose = _cnsa_category(artifact)
    control = f'approved suite — {category}'

    # Providers are assessed on capability, not on an algorithm they name. A
    # library that cannot express ML-KEM-1024 blocks CNSA 2.0 compliance for
    # everything above it, which is a stronger statement than "unclassified".
    if artifact.artifact_type in ('library', 'binary', 'container-image'):
        return _assess_provider(artifact, name, deadline, prose, year)

    if name in CNSA_APPROVED:
        return [_verdict('cnsa-2.0', control, 'compliant',
                         f'{name} is CNSA 2.0 approved ({CNSA_APPROVED[name]}).',
                         None, year, 'published')]

    if name in CNSA_UNDERSTRENGTH:
        status = 'disallowed' if year > deadline else 'action_required'
        return [_verdict('cnsa-2.0', control, status,
                         f'{CNSA_UNDERSTRENGTH[name]}. {prose}',
                         deadline, year, 'published')]

    if entry is None:
        return [_verdict('cnsa-2.0', control, 'not_applicable',
                         f'{name} did not resolve to a known algorithm, so no CNSA 2.0 '
                         'verdict can be issued. Classify it before relying on this row.',
                         None, year, 'published')]

    impact = entry.get('impact')
    if impact == 'broken_classically':
        return [_verdict('cnsa-2.0', control, 'disallowed',
                         f'{name} is broken with classical hardware and was never in any '
                         'CNSA suite.', None, year, 'published')]

    if impact in ('shor_broken', 'grover'):
        status = 'disallowed' if year > deadline else 'action_required'
        why = ('falls entirely to Shor' if impact == 'shor_broken'
               else 'is below the CNSA 2.0 symmetric floor once Grover is accounted for')
        return [_verdict('cnsa-2.0', control, status,
                         f'{name} {why} and is not in the CNSA 2.0 suite. {prose}',
                         deadline, year, 'published')]

    if impact == 'pq_safe':
        # Post-quantum, standardised, but not on the CNSA 2.0 list — hybrids and
        # FIPS 206 candidates land here.
        return [_verdict('cnsa-2.0', control, 'action_required',
                         f'{name} is post-quantum but is not one of the CNSA 2.0 named '
                         f'algorithms. {prose}', deadline, year, 'published')]

    return [_verdict('cnsa-2.0', control, 'not_applicable',
                     f'{name} is a supporting primitive outside the CNSA 2.0 algorithm '
                     'list.', None, year, 'published')]


def _assess_provider(artifact: Artifact, name: str, deadline: int,
                     prose: str, year: int) -> list[dict]:
    """CNSA 2.0 verdict for a cryptographic provider rather than an algorithm.

    The question for a library, binary or image is not "is this algorithm
    approved" but "can this thing implement the approved algorithms at all". The
    provider registry in crypto_services carries that, including the version at
    which PQC support landed where it is known.
    """
    control = 'provider can implement the approved suite'
    props = artifact.properties or {}
    version = props.get('version')
    key, lib = lookup_library(name)
    if lib is None and props.get('package'):
        key, lib = lookup_library(str(props['package']))

    if lib is None:
        return [_verdict('cnsa-2.0', control, 'not_applicable',
                         f'{name} is not in the provider registry, so no capability '
                         'verdict can be issued for it.', None, year, 'published')]

    if not lib.get('pqc'):
        status = 'disallowed' if year > deadline else 'action_required'
        return [_verdict('cnsa-2.0', control, status,
                         f'{name} has no post-quantum support: {lib.get("pqc_note", "")} '
                         f'Nothing built on it can reach the CNSA 2.0 suite until it does. '
                         f'{prose}', deadline, year, 'published')]

    min_ver = lib.get('min_pqc_version')
    if min_ver and version and not _version_at_least(str(version), str(min_ver)):
        status = 'disallowed' if year > deadline else 'action_required'
        return [_verdict('cnsa-2.0', control, status,
                         f'{name} {version} predates PQC support, which landed in '
                         f'{min_ver}. {lib.get("pqc_note", "")}',
                         deadline, year, 'published')]

    return [_verdict('cnsa-2.0', control, 'compliant',
                     f'{name} can implement post-quantum algorithms: '
                     f'{lib.get("pqc_note", "PQC-capable")}. Whether the deployment '
                     'actually enables them is a configuration finding, not a provider one.',
                     None, year, 'published')]


# SP 800-131A controls whose deadlines have already passed. Each entry is
# (algorithm key, control label, note).
_131A_DISALLOWED = {
    'SHA-1': ('SHA-1 for digital signature generation',
              'SHA-1 is disallowed for digital signature generation and for most '
              'applications requiring collision resistance.'),
    'MD5': ('MD5', 'MD5 has never been an approved hash function.'),
    '3DES': ('three-key TDEA for encryption',
             'Three-key TDEA was disallowed for encryption after 2023.'),
    'DES': ('single-DES', 'Single-DES has been disallowed since 2005.'),
    'RC4': ('RC4', 'RC4 is not an approved algorithm and is prohibited in TLS by RFC 7465.'),
    'RC2': ('RC2', 'RC2 is not an approved algorithm.'),
    'MD4': ('MD4', 'MD4 has never been an approved hash function.'),
    'RIPEMD-160': ('RIPEMD-160', 'RIPEMD-160 is not a NIST-approved hash function.'),
}


def _assess_131a(artifact: Artifact, name: str, entry: dict | None,
                 year: int) -> list[dict]:
    out: list[dict] = []

    if name in _131A_DISALLOWED:
        control, note = _131A_DISALLOWED[name]
        out.append(_verdict('nist-sp-800-131a', control, 'disallowed', note,
                            None, year, 'published'))

    # RSA below a 2048-bit modulus. Expressed in modulus bits, so it reads the
    # raw key size — and only for RSA. `key_size` on an EC certificate is a curve
    # size, where 256 bits is strong rather than a violation, so applying this
    # control to anything but RSA would produce a confident false positive.
    props = artifact.properties or {}
    key_size = props.get('key_size')
    if (isinstance(key_size, int) and key_size and name.startswith('RSA')
            and key_size < 2048):
        out.append(_verdict(
            'nist-sp-800-131a', 'RSA modulus below 2048 bits', 'disallowed',
            f'{key_size}-bit RSA modulus is below the 2048-bit floor and provides under '
            '112 bits of classical strength.', None, year, 'published'))

    out.extend(_assess_chain_signature(artifact, year))

    if not out:
        if entry and str(entry.get('nist_status', '')).lower() in ('disallowed', 'deprecated'):
            out.append(_verdict(
                'nist-sp-800-131a', 'approved algorithm and key length',
                'deprecated' if 'deprecat' in str(entry.get('nist_status')).lower() else 'disallowed',
                f'{name} carries NIST status "{entry["nist_status"]}" in the knowledge base: '
                f'{entry.get("note", "see SP 800-131A Rev.2")}',
                None, year, 'published'))
        elif entry:
            out.append(_verdict(
                'nist-sp-800-131a', 'approved algorithm and key length', 'compliant',
                f'{name} is within the SP 800-131A Rev.2 approved set at its stated '
                'parameters.', None, year, 'published'))
        else:
            out.append(_verdict(
                'nist-sp-800-131a', 'approved algorithm and key length', 'not_applicable',
                f'{name} did not resolve to a known algorithm.', None, year, 'published'))
    return out


# Signature algorithms a CA can sign a certificate with that are themselves
# disallowed. A certificate is only as trustworthy as the signature over it: a
# perfectly good ML-DSA subject key in a chain signed with SHA-1 is forgeable
# today, and this is a distinct finding from the subject key's own exposure.
_WEAK_CHAIN_SIGNATURES = {
    'SHA-1': 'SHA-1 in a certificate signature is disallowed for signature generation',
    'MD5': 'MD5 in a certificate signature has never been approved',
    'MD2': 'MD2 in a certificate signature has never been approved',
}


def _assess_chain_signature(artifact: Artifact, year: int) -> list[dict]:
    """Assess the algorithm the issuer signed this certificate with."""
    if artifact.artifact_type != 'certificate':
        return []
    sig = (artifact.properties or {}).get('signature_algorithm')
    if not isinstance(sig, str) or not sig:
        return []
    # A signature algorithm OID name is "<hash>With<pk>Encryption" or
    # "ecdsa-with-<hash>"; resolve the hash component specifically, since that is
    # what the control is about.
    upper = sig.upper().replace('_', '-')
    for weak, note in _WEAK_CHAIN_SIGNATURES.items():
        token = weak.replace('-', '')
        if token in upper.replace('-', ''):
            return [_verdict(
                'nist-sp-800-131a', 'certificate signature algorithm', 'disallowed',
                f'{note} (issuer signed with {sig}).', None, year, 'published')]
    return []


def assess_artifact(artifact: Artifact, year: int = CURRENT_YEAR) -> list[dict]:
    """Every applicable mandate verdict for one artifact, worst-first."""
    name, entry = _entry_for(artifact)
    verdicts = (_assess_ir8547(artifact, name, entry, year)
                + _assess_cnsa(artifact, name, entry, year)
                + _assess_131a(artifact, name, entry, year))
    verdicts.sort(key=lambda v: (STATUS_RANK[v['status']],
                                 v['deadline_year'] if v['deadline_year'] else 9999))
    return verdicts


def governing_status(verdicts: list[dict]) -> str:
    """The single worst status across a set of verdicts."""
    if not verdicts:
        return 'not_applicable'
    return min(verdicts, key=lambda v: STATUS_RANK[v['status']])['status']


# ---------------------------------------------------------------------------
# Estate rollup
# ---------------------------------------------------------------------------

_FAILING = ('disallowed', 'deprecated', 'action_required')

# Posture bands. Deliberately coarse: the score is an ordering device, not a
# measurement, and pretending otherwise would be the same false precision this
# module exists to avoid.
_BANDS = [(80, 'strong'), (60, 'partial'), (35, 'weak'), (0, 'critical')]


def _band(score: float) -> str:
    for floor, name in _BANDS:
        if score >= floor:
            return name
    return 'critical'


def _location(artifact: Artifact) -> str:
    return artifact.evidence.file_path or '(no location recorded)'


def compliance_report(artifacts: list[Artifact],
                      current_year: int = CURRENT_YEAR) -> dict:
    """Assess a whole inventory against every modelled mandate."""
    per_standard: dict[str, dict] = {}
    for key, std in STANDARDS.items():
        per_standard[key] = {
            'standard': std['standard'],
            'standard_short': std['standard_short'],
            'url_or_ref': std['url_or_ref'],
            'document_status': std['status'],
            'summary': std['summary'],
            'counts_by_status': {s: 0 for s in STATUS_ORDER},
            'offenders': [],
        }

    short_to_key = {std['standard_short']: k for k, std in STANDARDS.items()}

    # year -> standard_short -> count of artifacts that first fall foul then
    deadline_hits: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    worst: list[dict] = []
    counted = 0

    for a in artifacts:
        verdicts = assess_artifact(a, current_year)
        counted += 1
        worst_status = governing_status(verdicts)
        soonest: int | None = None

        for v in verdicts:
            key = short_to_key[v['standard_short']]
            bucket = per_standard[key]
            bucket['counts_by_status'][v['status']] += 1
            if v['status'] in _FAILING:
                bucket['offenders'].append({
                    'id': a.id,
                    'name': a.name,
                    'severity': a.severity,
                    'risk_score': a.risk_score,
                    'location': _location(a),
                    'line': a.evidence.line,
                    'status': v['status'],
                    'control': v['control'],
                    'note': v['note'],
                    'deadline_year': v['deadline_year'],
                    'confidence': v['confidence'],
                })
            if v['deadline_year'] and v['status'] in ('action_required', 'deprecated'):
                deadline_hits[v['deadline_year']][v['standard_short']] += 1
                soonest = v['deadline_year'] if soonest is None else min(soonest, v['deadline_year'])

        if worst_status in _FAILING:
            # Deadline pressure: already-failing outranks a future deadline, and a
            # nearer deadline outranks a distant one. Risk score breaks ties.
            pressure = (0 if worst_status == 'disallowed'
                        else 1 if worst_status == 'deprecated' else 2)
            worst.append({
                'id': a.id,
                'name': a.name,
                'severity': a.severity,
                'risk_score': a.risk_score,
                'location': _location(a),
                'line': a.evidence.line,
                'status': worst_status,
                'deadline_year': soonest,
                'criticality': a.business_criticality,
                'mosca_violated': a.mosca_violated,
                '_sort': (pressure, soonest or 9999, -a.risk_score),
            })

    for bucket in per_standard.values():
        bucket['offenders'].sort(key=lambda o: (STATUS_RANK[o['status']], -o['risk_score']))
        bucket['offenders'] = bucket['offenders'][:12]
        scored = sum(bucket['counts_by_status'][s] for s in STATUS_ORDER
                     if s != 'not_applicable')
        ok = bucket['counts_by_status']['compliant']
        bucket['assessed'] = scored
        bucket['compliant_pct'] = round(100.0 * ok / scored, 1) if scored else None
        bucket['failing'] = sum(bucket['counts_by_status'][s] for s in _FAILING)

    # Cumulative deadline buckets: how many artifacts have fallen foul by year Y.
    buckets: list[dict] = []
    running: dict[str, int] = defaultdict(int)
    for year in sorted(deadline_hits):
        for short in sorted(deadline_hits[year]):
            n = deadline_hits[year][short]
            running[short] += n
            buckets.append({
                'year': year,
                'standard_short': short,
                'artifacts_falling_foul': n,
                'cumulative': running[short],
            })

    worst.sort(key=lambda w: w.pop('_sort'))
    worst_first = worst[:20]

    # Posture: the share of artifacts that pass every mandate that applies to
    # them, penalised for anything already disallowed. Stated plainly so a
    # reviewer can argue with the arithmetic rather than guess at it.
    disallowed_ids = {o['id'] for b in per_standard.values()
                      for o in b['offenders'] if o['status'] == 'disallowed'}
    total_failing = len({w['id'] for w in worst})
    clean = max(0, counted - total_failing)
    base = 100.0 * clean / counted if counted else 100.0
    penalty = min(25.0, 25.0 * len(disallowed_ids) / max(1, counted) * 4)
    score = round(max(0.0, base - penalty), 1)

    ir = per_standard['nist-ir-8547']
    cnsa = per_standard['cnsa-2.0']
    a131 = per_standard['nist-sp-800-131a']
    headline_parts = []
    if a131['failing']:
        headline_parts.append(
            f'{a131["failing"]} artefacts already fail SP 800-131A, which is in force today')
    if ir['failing']:
        headline_parts.append(
            f'{ir["failing"]} would fall foul of the NIST IR 8547 draft timeline by '
            f'{IR8547_DISALLOW_YEAR}')
    if cnsa['failing']:
        headline_parts.append(
            f'{cnsa["failing"]} are outside the CNSA 2.0 suite')
    headline = ('; '.join(headline_parts) + '.') if headline_parts else (
        'No artefact in this inventory fails any modelled mandate.')

    return {
        'as_of_year': current_year,
        'artifacts_assessed': counted,
        'standards': list(per_standard.values()),
        'deadline_buckets': buckets,
        'posture': {
            'score': score,
            'band': _band(score),
            'headline': headline,
            'basis': (
                'Share of artefacts passing every mandate that applies to them '
                f'({clean} of {counted}), minus up to 25 points scaled by the share '
                'already disallowed. Deliberately coarse: it orders estates, it does '
                'not measure them.'),
            'failing_artifacts': total_failing,
            'disallowed_artifacts': len(disallowed_ids),
        },
        'worst_first': worst_first,
    }
