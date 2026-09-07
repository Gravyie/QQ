"""Mosca risk analysis, HNDL exposure, and PQC migration advisory.

The whole risk model is deliberately a pure function of (artifact, assumptions).
Nothing here touches the filesystem or the clock beyond CURRENT_YEAR, which
means the API can re-run the entire analysis against new assumptions without
re-scanning anything -- that is what powers the live Mosca simulator.
"""
from __future__ import annotations

from .models import Artifact, Severity, Evidence
from .knowledge_base import ALGORITHMS, canonical_algorithm, extract_mode, UNAUTHENTICATED_MODES
from .crypto_services import LIBRARIES, lookup_library

CURRENT_YEAR = 2026

# How damaging is a break of this artifact class, 0..1. Drives both severity and
# harvest-now-decrypt-later exposure.
SENSITIVITY = {
    'signature': 0.9, 'key-agreement': 0.9, 'kem': 0.9, 'certificate': 0.85,
    'private-key': 0.95, 'asymmetric-encryption': 0.85,
    'symmetric-cipher': 0.5, 'hash': 0.4, 'mac': 0.4, 'kdf': 0.4,
    'protocol': 0.6, 'cipher-suite': 0.6, 'library': 0.4, 'library-binary': 0.4,
    'hardware': 0.7, 'service': 0.6, 'configuration-weakness': 0.55,
    'key-size-sensitivity': 0.5,
}

# Path/name signals that imply business criticality. Ordered: the first match
# wins, so put the strongest signals first and the dampeners (test/fixture) last.
CRITICAL_PATH_HINTS = [
    ('payment', 'critical'), ('settlement', 'critical'), ('billing', 'critical'),
    ('clearing', 'critical'), ('treasury', 'critical'), ('secret', 'critical'),
    ('vault', 'critical'), ('core-banking', 'critical'), ('hsm', 'critical'),
    ('root-ca', 'critical'), ('signing', 'critical'),
    ('auth', 'high'), ('token', 'high'), ('session', 'high'), ('jwt', 'high'),
    ('admin', 'high'), ('tls', 'high'), ('pki', 'high'), ('key', 'high'),
    ('gateway', 'high'), ('mesh', 'high'), ('archive', 'high'),
    ('user', 'medium'), ('service', 'medium'),
    ('test', 'low'), ('sample', 'low'), ('fixture', 'low'), ('example', 'low'),
    ('mock', 'low'), ('docs', 'low'),
]

CRITICALITY_WEIGHT = {'critical': 1.0, 'high': 0.8, 'medium': 0.55, 'low': 0.3}

# Data shelf-life per artifact class, in years. This is the X in Mosca's X+Y>Z.
# Long-lived material (roots of trust, archives) dominates the risk picture.
LIFETIME_BY_CATEGORY = {
    'private-key': 8, 'certificate': 7, 'signature': 7,
    'key-agreement': 5, 'kem': 5, 'asymmetric-encryption': 5,
    'symmetric-cipher': 3, 'hash': 3, 'mac': 3, 'kdf': 3,
    'protocol': 5, 'cipher-suite': 5,
}

# Migration effort per artifact class, in months. This is the Y.
MIGRATION_MONTHS_BY_TYPE = {
    'certificate': 4, 'protocol': 4, 'configuration': 3, 'library': 3,
    'binary': 6, 'container-image': 6, 'algorithm-use': 5,
    'key': 6, 'cloud-service': 9, 'hardware': 12, 'tls-endpoint': 4,
}

# Path signals for data that must stay confidential for decades. These override
# the per-class defaults upward, which is exactly the HNDL case Mosca is for.
LONG_LIVED_PATH_HINTS = [
    ('archive', 25), ('treasury', 20), ('records', 20), ('ledger', 15),
    ('backup', 15), ('kyc', 12), ('root-ca', 15), ('clearing', 10),
]


def infer_criticality(path: str) -> str:
    low = path.lower()
    for hint, level in CRITICAL_PATH_HINTS:
        if hint in low:
            return level
    return 'medium'


# Above this, a certificate's validity window has stopped being a statement
# about data shelf-life. 100-year and 1000-year notAfter dates are routine in
# crypto library test corpora and occasionally escape into real PKI through
# misconfiguration. Taking them literally produces Mosca margins like -993
# years, which is not a finding an analyst can act on -- it is noise that
# outranks every genuine one. Capped, and the raw figure is preserved on the
# artifact so nothing is hidden.
MAX_CREDIBLE_LIFETIME_YEARS = 30


def estimate_lifetime(artifact: Artifact, default_lifetime: int = 5) -> int:
    """Years the data protected by this artifact must stay confidential (X)."""
    if artifact.lifetime_years:
        return min(artifact.lifetime_years, MAX_CREDIBLE_LIFETIME_YEARS)

    # A certificate's own validity window is hard evidence, prefer it.
    props = artifact.properties or {}
    if artifact.artifact_type == 'certificate' and props.get('lifetime_days'):
        cert_years = max(1, round(props['lifetime_days'] / 365))
        # A root CA signs material that outlives the CA certificate itself.
        if props.get('self_signed') or 'root' in artifact.evidence.file_path.lower():
            cert_years = max(cert_years, 15)
        if cert_years > MAX_CREDIBLE_LIFETIME_YEARS:
            props['lifetime_years_raw'] = cert_years
            props['lifetime_capped'] = (
                f'certificate asserts a {cert_years}-year validity window; '
                f'shelf-life capped at {MAX_CREDIBLE_LIFETIME_YEARS}y for risk scoring')
            return MAX_CREDIBLE_LIFETIME_YEARS
        return cert_years

    path = artifact.evidence.file_path.lower()
    for hint, years in LONG_LIVED_PATH_HINTS:
        if hint in path:
            return years

    return LIFETIME_BY_CATEGORY.get(artifact.category, default_lifetime)


def estimate_migration_months(artifact: Artifact, default_months: int = 18) -> int:
    """Months of engineering work to replace this artifact (Y).

    Hardware and cloud KMS dominate because you wait on a vendor, not on your
    own sprint board. A tuned default from the caller only applies to classes we
    have no specific figure for.
    """
    base = MIGRATION_MONTHS_BY_TYPE.get(artifact.artifact_type)
    if base is None:
        return default_months
    # Critical-path systems carry change-control overhead: staged rollout,
    # regression suites, regulator sign-off.
    if artifact.business_criticality == 'critical':
        base = round(base * 1.5)
    elif artifact.business_criticality == 'low':
        base = max(1, round(base * 0.6))
    return base


def quantum_year_for(artifact: Artifact, crqc_year: int) -> int | None:
    """Year this artifact falls to a cryptographically relevant quantum computer."""
    impact = artifact.quantum_impact
    if impact == 'shor_broken':
        return crqc_year
    if impact == 'grover':
        # Grover needs far more logical qubits and a serial oracle, so a
        # Grover-relevant machine trails a Shor-relevant one.
        return crqc_year + 5
    return None


def mosca_check(crqc_year: int, lifetime_years: int, migration_months: int):
    """Mosca's inequality: X + Y > Z means migration must already be underway.

    X = data shelf-life, Y = migration time, Z = years until CRQC.
    Returns (violated, margin_years). Negative margin is how late you are.
    """
    z_years = crqc_year - CURRENT_YEAR
    y_years = migration_months / 12
    x_plus_y = lifetime_years + y_years
    return x_plus_y > z_years, round(z_years - x_plus_y, 2)


def hndl_exposure(artifact: Artifact) -> float | None:
    """Harvest-now-decrypt-later exposure, 0..1.

    Only asymmetric primitives qualify: traffic protected with them today can be
    recorded now and opened once a CRQC exists. Symmetric traffic is not
    retroactively readable in the same way, so it returns None rather than 0 --
    the distinction matters in the UI.
    """
    if artifact.quantum_impact != 'shor_broken':
        return None
    sens = SENSITIVITY.get(artifact.category, 0.5)
    path = artifact.evidence.file_path.lower()
    external = any(k in path for k in ('public', 'api', 'gateway', 'edge', 'web',
                                       'ingress', 'lb', 'proxy', 'cdn', 'interbank'))
    crit = CRITICALITY_WEIGHT.get(artifact.business_criticality, 0.55)
    exposure = sens * (1.2 if external else 1.0) * (0.6 + 0.4 * crit / 1.0)
    return round(min(1.0, exposure), 2)


def compute_severity(artifact: Artifact, margin_years: float) -> tuple[str, float]:
    """Severity plus a 0..10 risk score.

    The score is deliberately dominated by two things a security team can act
    on: how broken the primitive is, and how far past the Mosca deadline the
    artifact already is. Business criticality modulates, it does not decide.
    """
    impact = artifact.quantum_impact
    sens = SENSITIVITY.get(artifact.category, 0.5)
    crit = CRITICALITY_WEIGHT.get(artifact.business_criticality, 0.55)

    if impact == 'broken_classically':
        base = 9.0          # already exploitable, no quantum computer required
    elif impact == 'shor_broken':
        base = 7.0 + 1.5 * sens
    elif impact == 'grover':
        base = 3.5 + 1.5 * sens
    elif impact == 'pq_safe':
        base = 0.8
    else:
        base = 2.5

    # Mosca urgency: past the deadline escalates, comfortable margin de-escalates.
    if impact in ('shor_broken', 'grover'):
        if margin_years < -3:
            base += 1.6
        elif margin_years < 0:
            base += 1.0
        elif margin_years > 5:
            base -= 0.8

    base *= (0.72 + 0.28 * (crit / 1.0) / 1.0) if impact != 'pq_safe' else 1.0

    props = artifact.properties or {}
    if props.get('expired'):
        base += 1.5
    if artifact.category == 'private-key' and props.get('encrypted') is False:
        base += 1.0
    key_size = props.get('key_size')
    if key_size and artifact.category in ('asymmetric-encryption', 'certificate',
                                          'private-key', 'signature') and key_size < 2048:
        base += 1.5     # below the NIST classical floor, quantum aside
    if props.get('mode') in UNAUTHENTICATED_MODES:
        base += 0.4
    if artifact.category == 'configuration-weakness':
        base += 1.0

    score = round(max(0.0, min(10.0, base)), 1)
    if score >= 8.5:
        sev = Severity.CRITICAL.value
    elif score >= 6.5:
        sev = Severity.HIGH.value
    elif score >= 4.0:
        sev = Severity.MEDIUM.value
    elif score >= 2.0:
        sev = Severity.LOW.value
    else:
        sev = Severity.INFO.value
    return sev, score


# ----------------------------------------------------------------------------
# PQC recommendation table.
#
# `target` must be a knowledge-base key so the planner can look up real wire
# sizes and CPU cost instead of guessing. `hybrid` is the transitional option.
# ----------------------------------------------------------------------------
RECOMMENDATIONS = {
    'RSA': {'target': 'ML-KEM-768', 'alt': 'ML-DSA-65', 'hybrid': 'X25519MLKEM768',
            'effort': 'high',
            'note': 'RSA key transport and RSA signatures both fall to Shor. '
                    'For TLS use a hybrid KEM group; for code signing use ML-DSA.'},
    'RSA-PSS': {'target': 'ML-DSA-65', 'hybrid': 'ML-DSA-65+ECDSA-P256', 'effort': 'medium',
                'note': 'Signature-only usage migrates to a composite certificate first.'},
    'RSA-OAEP': {'target': 'ML-KEM-768', 'hybrid': 'X25519MLKEM768', 'effort': 'high',
                 'note': 'Replace key transport with a KEM; OAEP has no PQC analogue.'},
    'DSA': {'target': 'ML-DSA-65', 'effort': 'medium',
            'note': 'Already withdrawn by FIPS 186-5. Migrate straight to ML-DSA.'},
    'ECDSA': {'target': 'ML-DSA-65', 'hybrid': 'ML-DSA-65+ECDSA-P256', 'effort': 'medium',
              'note': 'Composite certificates let you migrate before every verifier is ready.'},
    'ECDSA-P256': {'target': 'ML-DSA-65', 'hybrid': 'ML-DSA-65+ECDSA-P256', 'effort': 'medium'},
    'ECDSA-P384': {'target': 'ML-DSA-87', 'hybrid': 'ML-DSA-65+ECDSA-P256', 'effort': 'medium'},
    'ECDSA-P521': {'target': 'ML-DSA-87', 'effort': 'medium'},
    'Ed25519': {'target': 'ML-DSA-65', 'hybrid': 'ML-DSA-65+Ed25519', 'effort': 'medium',
                'note': 'Edwards curves are as Shor-exposed as NIST curves.'},
    'Ed448': {'target': 'ML-DSA-87', 'effort': 'medium'},
    'ECDH': {'target': 'ML-KEM-768', 'hybrid': 'X25519MLKEM768', 'effort': 'medium',
             'note': 'Highest HNDL priority: recorded handshakes are decryptable later.'},
    'X25519': {'target': 'ML-KEM-768', 'hybrid': 'X25519MLKEM768', 'effort': 'low',
               'note': 'The hybrid group is already the browser default, so this is a config change.'},
    'X448': {'target': 'ML-KEM-1024', 'hybrid': 'SecP384r1MLKEM1024', 'effort': 'low'},
    'DH': {'target': 'ML-KEM-768', 'hybrid': 'X25519MLKEM768', 'effort': 'high',
           'note': 'Finite-field DH usually means an old protocol stack; budget for the stack, not the primitive.'},
    'Diffie-Hellman': {'target': 'ML-KEM-768', 'hybrid': 'X25519MLKEM768', 'effort': 'high'},
    'ElGamal': {'target': 'ML-KEM-768', 'effort': 'high'},
    'SM2': {'target': 'ML-DSA-65', 'effort': 'medium'},
    'SRP': {'target': 'ML-KEM-768', 'effort': 'high',
            'note': 'Password-authenticated key exchange has no standardised PQC replacement yet.'},

    'AES': {'target': 'AES-256', 'effort': 'low',
            'note': 'Unqualified AES: pin the key size. AES-128 leaves 64-bit post-quantum strength.'},
    'AES-128': {'target': 'AES-256', 'effort': 'low',
                'note': 'Key-size change only, no protocol or API change.'},
    'AES-192': {'target': 'AES-256', 'effort': 'low'},
    'AES-CBC': {'target': 'AES-256', 'effort': 'low',
                'note': 'CBC is unauthenticated. Move to AES-256-GCM and gain integrity.'},
    'AES-ECB': {'target': 'AES-256', 'effort': 'low',
                'note': 'ECB leaks plaintext structure. This is a defect independent of quantum.'},
    '3DES': {'target': 'AES-256', 'effort': 'low',
             'note': 'Disallowed by NIST SP 800-131A Rev.2 and only a 64-bit block.'},
    'DES': {'target': 'AES-256', 'effort': 'low', 'note': 'Brute-forceable since 1998.'},
    'RC4': {'target': 'AES-256', 'effort': 'low', 'note': 'Prohibited in TLS by RFC 7465.'},
    'RC2': {'target': 'AES-256', 'effort': 'low'},
    'Blowfish': {'target': 'AES-256', 'effort': 'low', 'note': '64-bit block, Sweet32 applies.'},
    'IDEA': {'target': 'AES-256', 'effort': 'low'},
    'CAST5': {'target': 'AES-256', 'effort': 'low'},
    'SM4': {'target': 'AES-256', 'effort': 'low'},
    'SEED': {'target': 'AES-256', 'effort': 'low'},
    'ARIA-128': {'target': 'AES-256', 'effort': 'low'},
    'Camellia-128': {'target': 'AES-256', 'effort': 'low'},

    'MD5': {'target': 'SHA-384', 'effort': 'low',
            'note': 'Chosen-prefix collisions are trivial. Replace regardless of quantum timeline.'},
    'SHA-1': {'target': 'SHA-384', 'effort': 'low', 'note': 'SHAttered 2017; NIST retires it in 2030.'},
    'SHA-224': {'target': 'SHA-384', 'effort': 'low'},
    'SHA-256': {'target': 'SHA-384', 'effort': 'low',
                'note': 'Adequate today; SHA-384 is the CNSA 2.0 floor for long-lived data.'},
    'RIPEMD-160': {'target': 'SHA-384', 'effort': 'low'},
    'CMAC': {'target': 'HMAC', 'effort': 'low'},
    'GMAC': {'target': 'HMAC', 'effort': 'low'},
    'PBKDF2': {'target': 'Argon2', 'effort': 'low',
               'note': 'Quantum-irrelevant, but raise iterations to the 210k NIST floor or move to Argon2id.'},
    'bcrypt': {'target': 'Argon2', 'effort': 'low', 'note': '72-byte input truncation.'},

    'SSLv2': {'target': 'TLSv1.3', 'effort': 'medium', 'note': 'DROWN. Prohibited by RFC 6176.'},
    'SSLv3': {'target': 'TLSv1.3', 'effort': 'medium', 'note': 'POODLE. Prohibited by RFC 7568.'},
    'TLSv1.0': {'target': 'TLSv1.3', 'effort': 'medium',
                'note': 'Deprecated by RFC 8996 and cannot negotiate a PQC group at all.'},
    'TLSv1.1': {'target': 'TLSv1.3', 'effort': 'medium', 'note': 'Deprecated by RFC 8996.'},
    'TLSv1.2': {'target': 'TLSv1.3', 'hybrid': 'X25519MLKEM768', 'effort': 'medium',
                'note': 'TLS 1.2 has no standardised hybrid group: PQC requires TLS 1.3 first.'},
    'TLSv1.3': {'target': 'X25519MLKEM768', 'effort': 'low',
                'note': 'Already PQC-capable. Enable a hybrid group so one is actually negotiated.'},
    'TLS': {'target': 'X25519MLKEM768', 'effort': 'medium'},
    'SSH-2': {'target': 'mlkem768x25519', 'hybrid': 'sntrup761x25519', 'effort': 'low',
              'note': 'OpenSSH 9+ ships hybrid KEX; this is a KexAlgorithms line.'},
    'IKEv2': {'target': 'ML-KEM-768', 'effort': 'high',
              'note': 'RFC 9370 adds a PQC round to IKEv2; needs both VPN peers upgraded.'},

    'SIKE': {'target': 'ML-KEM-768', 'effort': 'high',
             'note': 'SIKE was broken classically in 2022. Remove immediately, it protects nothing.'},
    'Rainbow': {'target': 'ML-DSA-65', 'effort': 'high',
                'note': 'Broken by the Beullens attack in 2022.'},
    'Kyber': {'target': 'ML-KEM-768', 'effort': 'low',
              'note': 'Pre-standard wire format. Not interoperable with FIPS 203.'},
    'Dilithium': {'target': 'ML-DSA-65', 'effort': 'low',
                  'note': 'Pre-standard wire format. Not interoperable with FIPS 204.'},
    'SPHINCS+': {'target': 'SLH-DSA-128s', 'effort': 'low', 'note': 'Renamed and standardised as SLH-DSA.'},
    'NewHope': {'target': 'ML-KEM-768', 'effort': 'low'},
}

# Fallbacks when the exact algorithm is unknown but the family is not.
FAMILY_RECOMMENDATIONS = {
    'signature': {'target': 'ML-DSA-65', 'hybrid': 'ML-DSA-65+ECDSA-P256', 'effort': 'medium'},
    'key-agreement': {'target': 'ML-KEM-768', 'hybrid': 'X25519MLKEM768', 'effort': 'medium'},
    'kem': {'target': 'ML-KEM-768', 'hybrid': 'X25519MLKEM768', 'effort': 'medium'},
    'asymmetric-encryption': {'target': 'ML-KEM-768', 'hybrid': 'X25519MLKEM768', 'effort': 'high'},
    'symmetric-cipher': {'target': 'AES-256', 'effort': 'low'},
    'hash': {'target': 'SHA-384', 'effort': 'low'},
    'mac': {'target': 'HMAC', 'effort': 'low'},
    'kdf': {'target': 'Argon2', 'effort': 'low'},
    'protocol': {'target': 'TLSv1.3', 'hybrid': 'X25519MLKEM768', 'effort': 'medium'},
    'cipher-suite': {'target': 'X25519MLKEM768', 'effort': 'medium'},
    'certificate': {'target': 'ML-DSA-65', 'hybrid': 'ML-DSA-65+ECDSA-P256', 'effort': 'medium',
                    'note': 'Reissue from a CA offering composite or PQC signatures.'},
    'private-key': {'target': 'ML-DSA-65', 'effort': 'high',
                    'note': 'Rotate key material through the KMS/HSM that owns it.'},
}

EFFORT_DAYS = {'low': 3, 'medium': 15, 'high': 45}


def build_recommendation(artifact: Artifact) -> dict | None:
    """Pick a PQC/hybrid replacement and attach its real cost figures.

    Returns None for artifacts that are already post-quantum safe, so "no
    recommendation" in the UI means "nothing to do" rather than "we gave up".
    """
    if artifact.quantum_impact == 'pq_safe':
        return None

    canon, _ = canonical_algorithm(artifact.name)
    rec = None
    for key in (artifact.name, canon):
        if key in RECOMMENDATIONS:
            rec = dict(RECOMMENDATIONS[key])
            break
    if rec is None:
        rec = dict(FAMILY_RECOMMENDATIONS.get(artifact.category, {}))
    if not rec:
        # Libraries, binaries, services: the action is an upgrade, not a swap.
        if artifact.artifact_type in ('library', 'binary', 'container-image'):
            props = artifact.properties or {}
            note = props.get('pqc_note') or 'Verify whether the installed version exposes PQC algorithms.'
            return {'for': artifact.name, 'target': None, 'action': 'upgrade',
                    'effort': 'medium', 'effort_days': EFFORT_DAYS['medium'], 'note': note}
        if artifact.artifact_type in ('cloud-service', 'hardware'):
            return {'for': artifact.name, 'target': None, 'action': 'vendor-dependent',
                    'effort': 'high', 'effort_days': EFFORT_DAYS['high'],
                    'note': 'Migration timing is set by the vendor roadmap. Track it and plan around it.'}
        return None

    rec['for'] = artifact.name
    rec.setdefault('action', 'replace')
    rec.setdefault('effort', 'medium')
    rec['effort_days'] = EFFORT_DAYS.get(rec['effort'], 15)

    # Attach measured cost of the replacement so the UI can show the real
    # latency/bandwidth trade instead of a vague "PQC is bigger".
    target_entry = ALGORITHMS.get(rec.get('target') or '')
    if target_entry:
        rec['target_nist_level'] = target_entry.get('nist_pq_level')
        rec['target_status'] = target_entry.get('nist_status')
        perf = target_entry.get('perf')
        if perf:
            rec['target_perf'] = perf
    current_entry = ALGORITHMS.get(canon)
    if current_entry and current_entry.get('perf'):
        rec['current_perf'] = current_entry['perf']
    if target_entry and current_entry:
        rec['wire_delta_bytes'] = _wire_delta(current_entry, target_entry)
    return rec


def _wire_delta(current: dict, target: dict) -> int | None:
    """Extra bytes on the wire per operation after migrating. Honest about None."""
    cp, tp = current.get('perf'), target.get('perf')
    if not cp or not tp:
        return None
    def total(p):
        return sum(p.get(k, 0) for k in ('pub_bytes', 'sig_bytes', 'ct_bytes'))
    return total(tp) - total(cp)


def resolve_impact(artifact: Artifact) -> str:
    """Determine the quantum-impact class for any artifact type.

    Every artifact type is handled here. Anything that names an algorithm --
    including configuration findings and TLS endpoint observations, which the
    earlier version silently skipped -- resolves through the knowledge base.
    """
    atype = artifact.artifact_type
    props = artifact.properties or {}

    if atype in ('algorithm-use', 'protocol', 'cipher-suite', 'configuration', 'tls-endpoint'):
        _, entry = canonical_algorithm(artifact.name)
        if entry:
            return entry['impact']
        # A configuration weakness need not name an algorithm (SECLEVEL=1).
        if artifact.category == 'configuration-weakness':
            return 'broken_classically' if props.get('severity_hint') == 'critical' else 'unknown'
        return 'unknown'

    if atype == 'certificate':
        # "RSA certificate", "ECDSA certificate (P-256)" -> leading token.
        alg = props.get('signature_algorithm') or (artifact.name.split()[0] if artifact.name else '')
        _, entry = canonical_algorithm(alg)
        return entry['impact'] if entry else 'unknown'

    if atype == 'key':
        name = artifact.name.lower()
        for marker in ('rsa', 'dsa', 'ec', 'ed25519', 'openssh', 'x25519'):
            if marker in name:
                return 'shor_broken'
        for marker in ('ml-kem', 'ml-dsa', 'mlkem', 'mldsa', 'slh-dsa'):
            if marker in name:
                return 'pq_safe'
        return 'unknown'

    if atype in ('library', 'binary', 'container-image'):
        # A library is only pq_safe if the *installed* version can do PQC.
        _, entry = lookup_library(artifact.name)
        if not entry or not entry.get('pqc'):
            return 'unknown'
        min_ver = entry.get('min_pqc_version')
        version = props.get('version')
        if min_ver and version and not _version_at_least(version, min_ver):
            return 'unknown'
        if version and _known_pre_pqc(artifact.name, version):
            return 'unknown'
        return 'pq_safe'

    return 'unknown'


# Versions of common libraries that predate any PQC support. Being explicit
# beats a generic "library exists so assume it's fine".
PRE_PQC_CEILINGS = {
    'openssl': '3.5', 'boringssl': '0.0', 'gnutls': '3.8.9', 'botan': '3.6',
    'wolfssl': '5.7', 'mbedtls': '3.6', 'rustls': '0.23', 'cryptography': '46.0',
    'bouncycastle': '1.80', 'bcprov-jdk18on': '1.80', 'bcpkix-jdk18on': '1.80',
}


def _version_tuple(v: str) -> tuple:
    parts = []
    for chunk in str(v).replace('-', '.').split('.'):
        digits = ''.join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _version_at_least(have: str, need: str) -> bool:
    h, n = _version_tuple(have), _version_tuple(need)
    length = max(len(h), len(n))
    h += (0,) * (length - len(h))
    n += (0,) * (length - len(n))
    return h >= n


def _known_pre_pqc(name: str, version: str) -> bool:
    ceiling = PRE_PQC_CEILINGS.get(name.lower())
    if not ceiling:
        return False
    return not _version_at_least(version, ceiling)


def hydrate_artifact(d: dict) -> Artifact:
    """Rebuild an Artifact from its dict form, for scan reload and re-simulation."""
    a = Artifact(
        artifact_type=d['artifact_type'], name=d['name'], category=d['category'],
        source=d['source'],
        evidence=Evidence(**dict(d.get('evidence', {}))),
        properties=d.get('properties', {}) or {})
    a.quantum_impact = d.get('quantum_impact', 'unknown')
    a.quantum_year = d.get('quantum_year')
    a.severity = d.get('severity', 'info')
    a.risk_score = d.get('risk_score', 0.0)
    a.mosca_violated = d.get('mosca_violated')
    a.mosca_margin_years = d.get('mosca_margin_years')
    a.migration_months = d.get('migration_months')
    a.hndl_exposure = d.get('hndl_exposure')
    a.recommendation = d.get('recommendation')
    a.business_criticality = d.get('business_criticality', 'medium')
    a.lifetime_years = d.get('lifetime_years')
    a.id = d.get('id', a.id)
    return a


def analyze(artifacts: list[Artifact], crqc_year: int, default_lifetime: int = 5,
            default_migration_months: int = 18) -> list[Artifact]:
    """Run impact resolution, Mosca, HNDL, severity and advisory over all artifacts.

    Idempotent and side-effect free apart from mutating the artifacts, which is
    what lets the simulator re-run it with different assumptions on stored data.
    """
    for a in artifacts:
        a.quantum_impact = resolve_impact(a)

        # Mode/padding detail is useful evidence and feeds severity.
        if a.artifact_type in ('algorithm-use', 'configuration', 'protocol'):
            mode = extract_mode(a.name)
            if mode and 'mode' not in a.properties:
                a.properties['mode'] = mode

        a.business_criticality = infer_criticality(
            f"{a.evidence.file_path} {a.name} {a.evidence.container_layer or ''}")
        a.lifetime_years = estimate_lifetime(a, default_lifetime)
        a.migration_months = estimate_migration_months(a, default_migration_months)

        if a.quantum_impact in ('shor_broken', 'grover'):
            a.mosca_violated, a.mosca_margin_years = mosca_check(
                crqc_year, a.lifetime_years, a.migration_months)
        else:
            # Mosca only speaks about quantum-vulnerable material. Saying
            # "false" for AES-256 would be true but meaningless; saying it for
            # MD5 would hide that MD5 is already broken.
            a.mosca_violated = False
            _, a.mosca_margin_years = mosca_check(crqc_year, a.lifetime_years, a.migration_months)

        a.quantum_year = quantum_year_for(a, crqc_year)
        a.hndl_exposure = hndl_exposure(a)
        a.severity, a.risk_score = compute_severity(a, a.mosca_margin_years or 0.0)
        a.recommendation = build_recommendation(a)
    return artifacts
