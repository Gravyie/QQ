"""CycloneDX 1.6 CBOM writer, SARIF exporter, and executive report generator.

The CBOM output follows the real CycloneDX 1.6 schema for `cryptoProperties`:
`assetType` is one of algorithm|certificate|protocol|related-crypto-material,
and each asset type has its own properties object. Getting this right matters
because the whole point of a standardised CBOM is that another tool can read it.

Reference: CycloneDX 1.6 specification, cryptoProperties.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from .models import ScanResult
from .knowledge_base import ALGORITHMS, canonical_algorithm, extract_mode, extract_padding

# CycloneDX 1.6 cryptoProperties.assetType enum.
#
# Binary and container-image findings map to `algorithm` because they are
# algorithm uses observed through a different lens -- a symbol table or an image
# layer rather than a source line. Libraries, hardware and cloud services are
# *carriers* of cryptography rather than crypto assets themselves, so they become
# ordinary CycloneDX components (library / device / platform) with no
# cryptoProperties block, which is what the spec intends.
ASSET_TYPE = {
    'algorithm-use': 'algorithm',
    'protocol': 'protocol',
    'certificate': 'certificate',
    'key': 'related-crypto-material',
    'configuration': 'algorithm',
    'tls-endpoint': 'protocol',
    'binary': 'algorithm',
    'container-image': 'algorithm',
}

# CycloneDX 1.6 primitive enum. Anything outside it must be emitted as "other"
# or the document fails schema validation.
VALID_PRIMITIVES = {
    'drbg', 'mac', 'block-cipher', 'stream-cipher', 'signature', 'hash', 'pke',
    'xof', 'kdf', 'key-agree', 'kem', 'ae', 'combiner', 'other', 'unknown',
}

# CycloneDX 1.6 executionEnvironment / cryptoFunctions enums.
VALID_CRYPTO_FUNCTIONS = {
    'generate', 'keygen', 'encrypt', 'decrypt', 'digest', 'tag', 'keyderive',
    'sign', 'verify', 'encapsulate', 'decapsulate', 'other', 'unknown',
}

# Map our internal category onto the CycloneDX relatedCryptoMaterial type enum.
RELATED_MATERIAL_TYPE = {
    'private-key': 'private-key', 'public-key': 'public-key',
    'secret-key': 'secret-key', 'key': 'key',
}

FUNCTIONS_BY_FAMILY = {
    'signature': ['sign', 'verify'],
    'kem': ['encapsulate', 'decapsulate'],
    'key-agreement': ['keyderive'],
    'asymmetric-encryption': ['encrypt', 'decrypt'],
    'symmetric-cipher': ['encrypt', 'decrypt'],
    'hash': ['digest'],
    'mac': ['tag'],
    'kdf': ['keyderive'],
}

NIST_LEVEL_TO_CDX = {
    1: 'nist-1', 2: 'nist-2', 3: 'nist-3', 4: 'nist-4', 5: 'nist-5',
}


def _crypto_properties(a) -> dict:
    """Build a schema-valid cryptoProperties block for one artifact."""
    asset_type = ASSET_TYPE.get(a.artifact_type)
    if asset_type is None:
        return {}

    canon, entry = canonical_algorithm(a.name)
    entry = entry or {}
    cp: dict = {'assetType': asset_type}

    if asset_type == 'algorithm':
        primitive = entry.get('primitive', 'unknown')
        alg: dict = {'primitive': primitive if primitive in VALID_PRIMITIVES else 'other'}
        # parameterSetIdentifier is a string in the spec, not an integer.
        key_size = (a.properties or {}).get('key_size')
        if key_size:
            alg['parameterSetIdentifier'] = str(key_size)
        elif entry.get('nist_pq_level'):
            alg['parameterSetIdentifier'] = canon
        if entry.get('classical_bits'):
            alg['classicalSecurityLevel'] = entry['classical_bits']
        if entry.get('nist_pq_level') and entry['nist_pq_level'] in NIST_LEVEL_TO_CDX:
            alg['nistQuantumSecurityLevel'] = entry['nist_pq_level']
        mode = (a.properties or {}).get('mode') or extract_mode(a.name)
        if mode:
            alg['mode'] = mode.lower().replace('-', '')  # spec enum is e.g. "gcm"
        padding = extract_padding(a.name)
        if padding:
            alg['padding'] = padding.lower()
        curve = (a.properties or {}).get('curve')
        if curve:
            alg['curve'] = curve
        funcs = [f for f in FUNCTIONS_BY_FAMILY.get(entry.get('family', ''), [])
                 if f in VALID_CRYPTO_FUNCTIONS]
        if funcs:
            alg['cryptoFunctions'] = funcs
        alg['executionEnvironment'] = ('hardware' if a.artifact_type == 'hardware'
                                      else 'software-plain-ram')
        alg['implementationPlatform'] = 'generic'
        cp['algorithmProperties'] = alg
        if entry.get('oid'):
            cp['oid'] = entry['oid']

    elif asset_type == 'certificate':
        props = a.properties or {}
        cert: dict = {}
        if props.get('subject'):
            cert['subjectName'] = props['subject']
        if props.get('issuer'):
            cert['issuerName'] = props['issuer']
        if props.get('not_before'):
            cert['notValidBefore'] = props['not_before']
        if props.get('not_after'):
            cert['notValidAfter'] = props['not_after']
        if props.get('signature_algorithm'):
            cert['signatureAlgorithmRef'] = props['signature_algorithm']
        cert['certificateFormat'] = props.get('format', 'X.509')
        ext = Path(a.evidence.file_path).suffix.lstrip('.').upper()
        cert['certificateExtension'] = ext or 'PEM'
        cp['certificateProperties'] = cert

    elif asset_type == 'protocol':
        props = a.properties or {}
        proto: dict = {}
        lowered = canon.lower()
        if lowered.startswith('tls'):
            proto['type'] = 'tls'
            proto['version'] = canon.replace('TLSv', '').replace('TLS', '') or None
        elif lowered.startswith('ssl'):
            proto['type'] = 'tls'
            proto['version'] = canon.replace('SSLv', '')
        elif lowered.startswith('ssh'):
            proto['type'] = 'ssh'
            proto['version'] = canon.replace('SSH-', '')
        elif 'ike' in lowered:
            proto['type'] = 'ipsec'
            proto['version'] = canon
        else:
            proto['type'] = 'other'
        proto = {k: v for k, v in proto.items() if v is not None}
        suite_raw = props.get('raw')
        if suite_raw and props.get('setting') in ('tls-ciphers', 'ssh-ciphers', 'ssh-kex'):
            proto['cipherSuites'] = [{'name': suite_raw}]
        cp['protocolProperties'] = proto

    elif asset_type == 'related-crypto-material':
        props = a.properties or {}
        mat: dict = {'type': RELATED_MATERIAL_TYPE.get(a.category, 'key')}
        if props.get('key_size'):
            mat['size'] = props['key_size']
        if props.get('encrypted') is not None:
            mat['state'] = 'active'
        mat['format'] = props.get('format', 'PEM')
        cp['relatedCryptoMaterialProperties'] = mat

    return cp


def artifact_to_cbom_component(a) -> dict:
    """One artifact -> one CycloneDX component with cryptoProperties + evidence."""
    canon, entry = canonical_algorithm(a.name)
    is_crypto_asset = a.artifact_type in ASSET_TYPE

    comp: dict = {
        'type': 'cryptographic-asset' if is_crypto_asset else _component_type(a),
        'bom-ref': a.id,
        'name': a.name,
    }
    props = a.properties or {}
    if props.get('version'):
        comp['version'] = str(props['version'])

    cp = _crypto_properties(a)
    if cp:
        comp['cryptoProperties'] = cp

    # Occurrence evidence is how a CBOM consumer navigates back to the source.
    occurrence: dict = {'location': a.evidence.file_path}
    if a.evidence.line:
        occurrence['line'] = a.evidence.line
    if a.evidence.snippet:
        occurrence['additionalContext'] = a.evidence.snippet[:200]
    comp['evidence'] = {'occurrences': [occurrence]}

    # Atlas-specific analysis rides in properties, namespaced so it never
    # collides with anything the spec defines.
    extra = [
        ('atlas:quantum-impact', a.quantum_impact),
        ('atlas:severity', a.severity),
        ('atlas:risk-score', a.risk_score),
        ('atlas:business-criticality', a.business_criticality),
        ('atlas:artifact-type', a.artifact_type),
        ('atlas:discovery-source', a.source),
        ('atlas:quantum-year', a.quantum_year),
        ('atlas:mosca-violated', a.mosca_violated),
        ('atlas:mosca-margin-years', a.mosca_margin_years),
        ('atlas:data-lifetime-years', a.lifetime_years),
        ('atlas:migration-months', a.migration_months),
        ('atlas:hndl-exposure', a.hndl_exposure),
        ('atlas:container-layer', a.evidence.container_layer),
        ('atlas:binary-section', a.evidence.binary_section),
    ]
    if a.recommendation:
        extra.append(('atlas:recommended-target', a.recommendation.get('target')))
        extra.append(('atlas:migration-effort', a.recommendation.get('effort')))
        if a.recommendation.get('hybrid'):
            extra.append(('atlas:recommended-hybrid', a.recommendation['hybrid']))
    comp['properties'] = [
        {'name': k, 'value': _as_str(v)} for k, v in extra if v is not None and v != ''
    ]
    return comp


def _component_type(a) -> str:
    return {
        'library': 'library', 'binary': 'file', 'container-image': 'container',
        'cloud-service': 'platform', 'hardware': 'device',
    }.get(a.artifact_type, 'file')


def _serial_uuid(scan_id: str) -> str:
    """CycloneDX requires serialNumber to be a real UUID.

    Scan ids are normally UUID4 already, but tests and CLI runs can use readable
    ids, so anything non-conforming is hashed into a deterministic UUID5 instead
    of emitting an invalid document.
    """
    try:
        return str(uuid.UUID(scan_id))
    except (ValueError, AttributeError, TypeError):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f'urn:atlas:scan:{scan_id}'))


def _as_str(v) -> str:
    if isinstance(v, bool):
        return 'true' if v else 'false'
    return str(v)


def write_cbom(result: ScanResult, out_path: Path) -> Path:
    components = [artifact_to_cbom_component(a) for a in result.artifacts]

    # Dependency graph: every discovered asset hangs off the scanned root so the
    # BOM is a connected graph rather than a flat bag, which is what downstream
    # CycloneDX tooling expects.
    root_ref = f'atlas-scan-{result.scan_id}'
    dependencies = [{'ref': root_ref, 'dependsOn': [c['bom-ref'] for c in components]}]
    dependencies += [{'ref': c['bom-ref'], 'dependsOn': []} for c in components]

    bom = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.6',
        'serialNumber': f'urn:uuid:{_serial_uuid(result.scan_id)}',
        'version': 1,
        'metadata': {
            'timestamp': result.summary.started_at,
            'lifecycles': [{'phase': 'operations'}],
            'tools': {
                'components': [{
                    'type': 'application',
                    'name': 'Quantum Atlas',
                    'version': '1.0.0',
                    'description': 'Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)',
                }],
            },
            'component': {
                'type': 'application',
                'bom-ref': root_ref,
                'name': result.config.organization,
                'description': 'Cryptographic estate scanned by Quantum Atlas',
            },
            'properties': [
                {'name': 'atlas:crqc-year', 'value': str(result.config.crqc_year)},
                {'name': 'atlas:mosca-violations', 'value': str(result.summary.mosca_violations)},
                {'name': 'atlas:quantum-vulnerable-pct',
                 'value': f'{result.summary.quantum_vulnerable_pct:.1f}'},
                {'name': 'atlas:files-scanned', 'value': str(result.summary.files_scanned)},
            ],
        },
        'components': components,
        'dependencies': dependencies,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bom, indent=2))
    return out_path


# ----------------------------------------------------------------------------
# SARIF 2.1.0 -- lets a CI pipeline surface crypto findings as code-scanning
# alerts in GitHub, annotated on the exact line.
# ----------------------------------------------------------------------------
SARIF_LEVEL = {'critical': 'error', 'high': 'error', 'medium': 'warning',
               'low': 'note', 'info': 'note'}


def write_sarif(result: ScanResult, out_path: Path) -> Path:
    rules: dict[str, dict] = {}
    sarif_results = []

    for a in result.artifacts:
        rule_id = f'atlas/{a.quantum_impact}/{a.category}'
        if rule_id not in rules:
            rules[rule_id] = {
                'id': rule_id,
                'name': f'{a.quantum_impact}-{a.category}'.replace('_', '-'),
                'shortDescription': {'text': _rule_title(a.quantum_impact, a.category)},
                'fullDescription': {'text': _rule_description(a.quantum_impact)},
                'defaultConfiguration': {'level': SARIF_LEVEL.get(a.severity, 'note')},
                'properties': {'tags': ['cryptography', 'post-quantum', a.quantum_impact],
                               'security-severity': str(a.risk_score)},
            }
        rec = a.recommendation or {}
        message = f'{a.name}: {_rule_title(a.quantum_impact, a.category)}'
        if rec.get('target'):
            message += f'. Recommended replacement: {rec["target"]}'
            if rec.get('hybrid'):
                message += f' (transitional hybrid: {rec["hybrid"]})'
        if a.mosca_violated:
            message += (f'. Mosca violation: data lifetime {a.lifetime_years}y + migration '
                        f'{a.migration_months}mo exceeds the {result.config.crqc_year} CRQC horizon '
                        f'by {abs(a.mosca_margin_years or 0):.1f}y')

        sarif_results.append({
            'ruleId': rule_id,
            'level': SARIF_LEVEL.get(a.severity, 'note'),
            'message': {'text': message},
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {'uri': _relative_uri(a.evidence.file_path)},
                    'region': ({'startLine': a.evidence.line,
                                'snippet': {'text': a.evidence.snippet[:200]}}
                               if a.evidence.line and a.evidence.snippet
                               else {'startLine': a.evidence.line} if a.evidence.line else {}),
                },
            }],
            'partialFingerprints': {'atlasArtifactId': a.id},
            'properties': {'riskScore': a.risk_score,
                           'businessCriticality': a.business_criticality,
                           'moscaViolated': bool(a.mosca_violated)},
        })

    sarif = {
        'version': '2.1.0',
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'runs': [{
            'tool': {'driver': {
                'name': 'Quantum Atlas',
                'version': '1.0.0',
                'informationUri': 'https://github.com/quantum-atlas',
                'rules': list(rules.values()),
            }},
            'results': sarif_results,
            'invocations': [{'executionSuccessful': True,
                             'startTimeUtc': result.summary.started_at}],
        }],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sarif, indent=2))
    return out_path


def _relative_uri(path: str) -> str:
    """SARIF wants repository-relative URIs; absolute paths break annotation."""
    p = Path(path)
    parts = p.parts
    for anchor in ('corpus', 'src', 'backend', 'app'):
        if anchor in parts:
            return str(Path(*parts[parts.index(anchor):]))
    return p.name


def _rule_title(impact: str, category: str) -> str:
    return {
        'shor_broken': f'Quantum-vulnerable {category} (broken by Shor\'s algorithm)',
        'grover': f'Quantum-weakened {category} (effective key length halved by Grover)',
        'broken_classically': f'Classically broken {category}',
        'pq_safe': f'Post-quantum {category}',
        'classical_ok': f'Classically adequate {category}',
    }.get(impact, f'Unclassified {category}')


def _rule_description(impact: str) -> str:
    return {
        'shor_broken': ("Shor's algorithm recovers private keys from public keys for "
                        'factoring and discrete-log primitives. Traffic protected this way '
                        'can be recorded today and decrypted once a CRQC exists.'),
        'grover': ("Grover's algorithm gives a quadratic speed-up on key search, halving "
                   'the effective strength of symmetric keys and hash preimages.'),
        'broken_classically': ('This primitive is already exploitable with classical '
                               'computers and should be removed regardless of quantum timelines.'),
        'pq_safe': 'Post-quantum algorithm. No known quantum attack better than generic search.',
        'classical_ok': 'Adequate parameters for both classical and quantum adversaries.',
    }.get(impact, 'Impact could not be determined from available evidence.')


# ----------------------------------------------------------------------------
# Executive report
# ----------------------------------------------------------------------------
def write_report(result: ScanResult, out_path: Path) -> Path:
    from .planner import build_plan

    s = result.summary
    plan = build_plan(result.artifacts, result.config.crqc_year)
    L: list[str] = []

    L.append(f'# Quantum Atlas — Cryptographic Risk Report')
    L.append('')
    L.append(f'**Organisation** {result.config.organization}  ')
    L.append(f'**Scan** `{result.scan_id}`  ')
    L.append(f'**Started** {s.started_at}  ')
    L.append(f'**CRQC horizon assumption** {result.config.crqc_year}  ')
    L.append('')
    L.append('## Executive summary')
    L.append('')
    L.append(f'- **{s.artifacts_found}** cryptographic artefacts across {s.files_scanned} '
             f'files and {s.targets} target(s)')
    L.append(f'- **{s.quantum_vulnerable_pct:.1f}%** are quantum-vulnerable '
             '(Shor-broken or Grover-weakened)')
    L.append(f'- **{s.mosca_violations}** fail Mosca\'s inequality and are already past '
             'their migration deadline')
    sev = s.by_severity
    L.append(f'- Severity: critical {sev.get("critical", 0)}, high {sev.get("high", 0)}, '
             f'medium {sev.get("medium", 0)}, low {sev.get("low", 0)}, info {sev.get("info", 0)}')
    L.append(f'- Estimated migration effort: **{plan["total_effort_days"]} engineer-days** '
             f'across {len(plan["waves"])} waves')
    L.append('')

    L.append('## Mosca\'s inequality')
    L.append('')
    L.append('```')
    L.append('X (data shelf-life)  +  Y (migration time)  >  Z (years until CRQC)')
    L.append(f'                                              Z = {result.config.crqc_year} - 2026 '
             f'= {result.config.crqc_year - 2026} years')
    L.append('```')
    L.append('')
    L.append('Where the inequality holds, an adversary can harvest ciphertext today and decrypt '
             'it before the data stops being sensitive. Those artefacts are listed first.')
    L.append('')

    L.append('## Inventory by artefact type')
    L.append('')
    L.append('| Type | Count |')
    L.append('|------|-------|')
    for t, n in sorted(s.by_type.items(), key=lambda kv: -kv[1]):
        L.append(f'| {t} | {n} |')
    L.append('')

    L.append('## Migration plan')
    L.append('')
    for wave in plan['waves']:
        L.append(f'### Wave {wave["wave"]} — {wave["title"]}')
        L.append('')
        L.append(f'{wave["rationale"]}')
        L.append('')
        L.append(f'- Artefacts: {wave["artifact_count"]}')
        L.append(f'- Effort: {wave["effort_days"]} engineer-days')
        if wave['targets']:
            L.append(f'- Targets: {", ".join(wave["targets"])}')
        L.append('')

    L.append('## Act-now findings')
    L.append('')
    urgent = sorted([a for a in result.artifacts if a.severity in ('critical', 'high')],
                    key=lambda a: -a.risk_score)
    if not urgent:
        L.append('No critical or high findings.')
        L.append('')
    for a in urgent[:25]:
        rec = a.recommendation or {}
        loc = a.evidence.file_path + (f':{a.evidence.line}' if a.evidence.line else '')
        L.append(f'### `{a.name}` — {a.severity}, risk {a.risk_score}')
        L.append('')
        L.append(f'- **Location** `{loc}`'
                 + (f' (container layer `{a.evidence.container_layer}`)'
                    if a.evidence.container_layer else ''))
        if a.evidence.snippet:
            L.append(f'- **Evidence** `{a.evidence.snippet[:140]}`')
        L.append(f'- **Quantum impact** {a.quantum_impact}'
                 + (f', falls ~{a.quantum_year}' if a.quantum_year else ''))
        L.append(f'- **Mosca** X={a.lifetime_years}y + Y={a.migration_months}mo vs '
                 f'Z={result.config.crqc_year - 2026}y → '
                 f'{"VIOLATED" if a.mosca_violated else "within margin"} '
                 f'(margin {a.mosca_margin_years}y)')
        if a.hndl_exposure:
            L.append(f'- **HNDL exposure** {a.hndl_exposure:.2f}')
        L.append(f'- **Business criticality** {a.business_criticality}')
        if rec.get('target'):
            line = f'- **Recommendation** migrate to `{rec["target"]}`'
            if rec.get('hybrid'):
                line += f', transitional hybrid `{rec["hybrid"]}`'
            line += f' — effort {rec.get("effort")} (~{rec.get("effort_days")}d)'
            L.append(line)
            if rec.get('wire_delta_bytes') is not None:
                L.append(f'- **Wire cost** {rec["wire_delta_bytes"]:+d} bytes per operation')
        if rec.get('note'):
            L.append(f'- {rec["note"]}')
        L.append('')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text('\n'.join(L))
    return out_path
