"""Export-format correctness: CycloneDX 1.6 CBOM and SARIF 2.1.0.

A CBOM whose only consumer is its own producer is a JSON file, not a bill of
materials. These tests assert conformance to the published enums and required
structures so another CycloneDX tool can actually read the output.
"""
from __future__ import annotations

import json

import pytest

from atlas.models import Artifact, Evidence, ScanConfig, ScanResult, ScanSummary
from atlas.cbom import (write_cbom, write_sarif, write_report,
                        artifact_to_cbom_component, VALID_PRIMITIVES,
                        VALID_CRYPTO_FUNCTIONS)
from atlas.risk import analyze

CDX_ASSET_TYPES = {'algorithm', 'certificate', 'protocol', 'related-crypto-material'}
CDX_COMPONENT_TYPES = {'application', 'framework', 'library', 'container', 'platform',
                       'operating-system', 'device', 'device-driver', 'firmware',
                       'file', 'machine-learning-model', 'data',
                       'cryptographic-asset'}
CDX_PROTOCOL_TYPES = {'tls', 'ssh', 'ipsec', 'ike', 'sstp', 'wpa', 'other', 'unknown'}
CDX_MATERIAL_TYPES = {'private-key', 'public-key', 'secret-key', 'key', 'ciphertext',
                      'signature', 'digest', 'initialization-vector', 'nonce', 'seed',
                      'salt', 'shared-secret', 'tag', 'additional-data', 'password',
                      'credential', 'token', 'other', 'unknown'}
SARIF_LEVELS = {'none', 'note', 'warning', 'error'}


def make(name, category, atype, path='/estate/app/x.py', line=3, props=None) -> Artifact:
    return Artifact(artifact_type=atype, name=name, category=category,
                    source='source-code',
                    evidence=Evidence(file_path=path, line=line, snippet=f'use of {name}'),
                    properties=props or {})


@pytest.fixture
def result(tmp_path) -> ScanResult:
    artifacts = [
        make('RSA', 'asymmetric-encryption', 'algorithm-use'),
        make('AES-128', 'symmetric-cipher', 'algorithm-use', props={'mode': 'CBC'}),
        make('AES-256-GCM', 'symmetric-cipher', 'algorithm-use'),
        make('ECDSA', 'signature', 'algorithm-use'),
        make('ML-KEM-768', 'kem', 'algorithm-use'),
        make('SHA-1', 'hash', 'algorithm-use'),
        make('TLSv1.0', 'protocol', 'protocol', props={'setting': 'tls-min-version'}),
        make('ECDH', 'cipher-suite', 'protocol',
             props={'setting': 'tls-ciphers', 'raw': 'ECDHE-RSA-AES128-SHA256'}),
        make('RSA certificate', 'certificate', 'certificate',
             path='/estate/pki/gateway.pem',
             props={'subject': 'CN=gateway', 'issuer': 'CN=Root CA',
                    'not_before': '2026-01-01T00:00:00+00:00',
                    'not_after': '2027-01-01T00:00:00+00:00',
                    'signature_algorithm': 'sha256WithRSAEncryption',
                    'key_size': 2048, 'lifetime_days': 365}),
        make('RSA private key', 'private-key', 'key', path='/estate/pki/gateway.key',
             props={'encrypted': False, 'key_size': 2048}),
        make('openssl', 'library', 'library', path='/estate/requirements.txt',
             props={'version': '1.1.1f'}),
        make('AWS KMS', 'service', 'cloud-service', path='/estate/app/kms.py'),
        make('PKCS#11 HSM interface', 'hardware', 'hardware', path='/estate/hsm/bridge.c'),
    ]
    analyze(artifacts, crqc_year=2033)
    cfg = ScanConfig(targets=[{'path': '/estate', 'kind': 'source'}], crqc_year=2033,
                     organization='Test Bank')
    summary = ScanSummary(scan_id='test-scan-0001', started_at='2026-08-31T10:00:00Z',
                          artifacts_found=len(artifacts), files_scanned=9)
    r = ScanResult(scan_id='test-scan-0001', config=cfg, summary=summary,
                   artifacts=artifacts)
    return r


# ---------------------------------------------------------------------------
# CycloneDX 1.6
# ---------------------------------------------------------------------------
def test_cbom_top_level_shape(result, tmp_path):
    bom = json.loads(write_cbom(result, tmp_path / 'c.json').read_text())
    assert bom['bomFormat'] == 'CycloneDX'
    assert bom['specVersion'] == '1.6'
    assert bom['serialNumber'].startswith('urn:uuid:')
    assert isinstance(bom['version'], int)
    assert bom['metadata']['component']['bom-ref']
    assert bom['metadata']['tools']['components'][0]['name'] == 'Quantum Atlas'


def test_cbom_has_a_component_per_artifact(result, tmp_path):
    bom = json.loads(write_cbom(result, tmp_path / 'c.json').read_text())
    assert len(bom['components']) == len(result.artifacts)
    assert len(bom['components']) > 0, 'regression: CBOM emitted zero components'


def test_cbom_component_types_are_valid(result, tmp_path):
    bom = json.loads(write_cbom(result, tmp_path / 'c.json').read_text())
    for c in bom['components']:
        assert c['type'] in CDX_COMPONENT_TYPES, f'{c["name"]}: bad type {c["type"]}'


def test_cbom_asset_types_and_primitives_are_valid(result, tmp_path):
    bom = json.loads(write_cbom(result, tmp_path / 'c.json').read_text())
    saw_crypto = 0
    for c in bom['components']:
        cp = c.get('cryptoProperties')
        if not cp:
            continue
        saw_crypto += 1
        assert cp['assetType'] in CDX_ASSET_TYPES
        if cp['assetType'] == 'algorithm':
            prim = cp['algorithmProperties']['primitive']
            assert prim in VALID_PRIMITIVES, f'{c["name"]}: bad primitive {prim}'
            for fn in cp['algorithmProperties'].get('cryptoFunctions', []):
                assert fn in VALID_CRYPTO_FUNCTIONS
        if cp['assetType'] == 'protocol':
            assert cp['protocolProperties']['type'] in CDX_PROTOCOL_TYPES
        if cp['assetType'] == 'related-crypto-material':
            assert cp['relatedCryptoMaterialProperties']['type'] in CDX_MATERIAL_TYPES
    assert saw_crypto >= 8


def test_cbom_parameter_set_identifier_is_a_string(result, tmp_path):
    """Spec type is string. Emitting an integer breaks schema validation."""
    bom = json.loads(write_cbom(result, tmp_path / 'c.json').read_text())
    for c in bom['components']:
        alg = (c.get('cryptoProperties') or {}).get('algorithmProperties') or {}
        if 'parameterSetIdentifier' in alg:
            assert isinstance(alg['parameterSetIdentifier'], str)


def test_cbom_never_emits_null_valued_properties(result, tmp_path):
    """Regression: the old writer wrote parameterSize: null into every entry."""
    raw = write_cbom(result, tmp_path / 'c.json').read_text()
    bom = json.loads(raw)
    for c in bom['components']:
        for prop in c.get('properties', []):
            assert prop['value'] not in (None, 'None', ''), f'{c["name"]}: {prop}'
        alg = (c.get('cryptoProperties') or {}).get('algorithmProperties') or {}
        for k, v in alg.items():
            assert v is not None, f'{c["name"]}: algorithmProperties.{k} is null'


def test_cbom_certificate_properties_use_spec_field_names(result, tmp_path):
    bom = json.loads(write_cbom(result, tmp_path / 'c.json').read_text())
    certs = [c for c in bom['components']
             if (c.get('cryptoProperties') or {}).get('assetType') == 'certificate']
    assert certs
    props = certs[0]['cryptoProperties']['certificateProperties']
    assert 'subjectName' in props and 'issuerName' in props
    assert 'notValidBefore' in props and 'notValidAfter' in props
    assert props['certificateFormat'] == 'X.509'


def test_cbom_carries_evidence_occurrences(result, tmp_path):
    """Evidence is what makes a CBOM auditable rather than a claim."""
    bom = json.loads(write_cbom(result, tmp_path / 'c.json').read_text())
    for c in bom['components']:
        occ = c['evidence']['occurrences']
        assert occ and occ[0]['location']


def test_cbom_dependency_graph_is_connected(result, tmp_path):
    bom = json.loads(write_cbom(result, tmp_path / 'c.json').read_text())
    root_ref = bom['metadata']['component']['bom-ref']
    root_dep = next(d for d in bom['dependencies'] if d['ref'] == root_ref)
    refs = {c['bom-ref'] for c in bom['components']}
    assert set(root_dep['dependsOn']) == refs


def test_cbom_oid_present_for_known_algorithms(result, tmp_path):
    bom = json.loads(write_cbom(result, tmp_path / 'c.json').read_text())
    rsa = next(c for c in bom['components'] if c['name'] == 'RSA')
    assert rsa['cryptoProperties']['oid'] == '1.2.840.113549.1.1.1'


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------
def test_sarif_top_level_shape(result, tmp_path):
    s = json.loads(write_sarif(result, tmp_path / 's.json').read_text())
    assert s['version'] == '2.1.0'
    assert s['runs'][0]['tool']['driver']['name'] == 'Quantum Atlas'


def test_sarif_result_per_artifact_with_valid_levels(result, tmp_path):
    s = json.loads(write_sarif(result, tmp_path / 's.json').read_text())
    run = s['runs'][0]
    assert len(run['results']) == len(result.artifacts)
    rule_ids = {r['id'] for r in run['tool']['driver']['rules']}
    for res in run['results']:
        assert res['level'] in SARIF_LEVELS
        assert res['ruleId'] in rule_ids, 'result references an undeclared rule'
        assert res['message']['text']
        assert res['locations'][0]['physicalLocation']['artifactLocation']['uri']


def test_sarif_uris_are_relative(result, tmp_path):
    """Absolute paths prevent GitHub from annotating the diff."""
    s = json.loads(write_sarif(result, tmp_path / 's.json').read_text())
    for res in s['runs'][0]['results']:
        uri = res['locations'][0]['physicalLocation']['artifactLocation']['uri']
        assert not uri.startswith('/'), f'absolute SARIF uri: {uri}'


def test_sarif_critical_findings_are_errors(result, tmp_path):
    s = json.loads(write_sarif(result, tmp_path / 's.json').read_text())
    by_fingerprint = {r['partialFingerprints']['atlasArtifactId']: r
                      for r in s['runs'][0]['results']}
    for a in result.artifacts:
        if a.severity == 'critical':
            assert by_fingerprint[a.id]['level'] == 'error'


def test_sarif_messages_name_the_replacement(result, tmp_path):
    s = json.loads(write_sarif(result, tmp_path / 's.json').read_text())
    texts = [r['message']['text'] for r in s['runs'][0]['results']]
    assert any('ML-KEM-768' in t for t in texts)
    assert any('ML-DSA-65' in t for t in texts)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def test_report_contains_summary_and_plan(result, tmp_path):
    from atlas.planner import build_plan
    result.plan = build_plan(result.artifacts, 2033)
    text = write_report(result, tmp_path / 'r.md').read_text()
    assert 'Quantum Atlas' in text
    assert "Mosca's inequality" in text
    assert 'Migration plan' in text
    assert 'Wave 1' in text or 'Wave 2' in text
    assert 'Test Bank' in text
