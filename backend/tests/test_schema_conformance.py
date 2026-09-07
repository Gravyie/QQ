"""Schema conformance: the exports must validate against the published schemas.

A CBOM that only its own producer can read is a JSON file, not a bill of
materials. These tests validate freshly generated output against the real
CycloneDX 1.6 and SARIF 2.1.0 schemas vendored under tests/schemas/, so a
regression in the writer fails here rather than in somebody else's tool.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip('jsonschema', reason='jsonschema not installed')

from atlas.cbom import write_cbom, write_sarif
from atlas.models import Artifact, Evidence, ScanConfig, ScanResult, ScanSummary
from atlas.planner import build_plan
from atlas.risk import analyze

SCHEMAS = Path(__file__).parent / 'schemas'


def _cdx_validator():
    from jsonschema import Draft7Validator, RefResolver
    main = json.loads((SCHEMAS / 'bom-1.6.schema.json').read_text())
    store = {
        'http://cyclonedx.org/schema/spdx.schema.json':
            json.loads((SCHEMAS / 'spdx.schema.json').read_text()),
        'http://cyclonedx.org/schema/jsf-0.82.schema.json':
            json.loads((SCHEMAS / 'jsf-0.82.schema.json').read_text()),
        main['$id']: main,
    }
    resolver = RefResolver(base_uri=main['$id'], referrer=main, store=store)
    return Draft7Validator(main, resolver=resolver)


def _sarif_validator():
    from jsonschema import Draft4Validator
    return Draft4Validator(json.loads((SCHEMAS / 'sarif-2.1.0.schema.json').read_text()))


def make(name, category, atype, path='/estate/app/x.py', line=3, props=None) -> Artifact:
    return Artifact(artifact_type=atype, name=name, category=category, source='source-code',
                    evidence=Evidence(file_path=path, line=line, snippet=f'use of {name}'),
                    properties=props or {})


@pytest.fixture(scope='module')
def result() -> ScanResult:
    """One artifact of every class Atlas can emit, so every branch of the
    CBOM writer is exercised by the schema check."""
    artifacts = [
        make('RSA', 'asymmetric-encryption', 'algorithm-use'),
        make('AES-128', 'symmetric-cipher', 'algorithm-use', props={'mode': 'CBC'}),
        make('ChaCha20', 'symmetric-cipher', 'algorithm-use'),
        make('ECDSA', 'signature', 'algorithm-use'),
        make('ML-KEM-768', 'kem', 'algorithm-use'),
        make('ML-DSA-65', 'signature', 'algorithm-use'),
        make('SHA-1', 'hash', 'algorithm-use'),
        make('SHAKE256', 'xof', 'algorithm-use'),
        make('HMAC', 'mac', 'algorithm-use'),
        make('PBKDF2', 'kdf', 'algorithm-use'),
        make('X25519MLKEM768', 'combiner', 'algorithm-use'),
        make('TLSv1.0', 'protocol', 'protocol', props={'setting': 'tls-min-version'}),
        make('TLSv1.3', 'protocol', 'protocol'),
        make('ECDH', 'cipher-suite', 'protocol',
             props={'setting': 'tls-ciphers', 'raw': 'ECDHE-RSA-AES128-SHA256'}),
        make('X25519', 'key-agreement', 'tls-endpoint', path='tls://edge.example.com:443'),
        make('RSA certificate', 'certificate', 'certificate', path='/estate/pki/gw.pem',
             props={'subject': 'CN=gw', 'issuer': 'CN=Root',
                    'not_before': '2026-01-01T00:00:00+00:00',
                    'not_after': '2027-01-01T00:00:00+00:00',
                    'signature_algorithm': 'sha256WithRSAEncryption',
                    'key_size': 2048, 'lifetime_days': 365, 'serial': 'a1b2'}),
        make('Unparseable certificate', 'certificate', 'certificate',
             path='/estate/pki/weird.der', props={'parse_error': True}),
        make('RSA private key', 'private-key', 'key', path='/estate/pki/gw.key',
             props={'encrypted': False, 'key_size': 2048}),
        make('ED25519 private key', 'private-key', 'key', path='/estate/pki/ed.key'),
        make('openssl', 'library', 'library', path='/estate/requirements.txt',
             props={'version': '1.1.1f'}),
        make('bouncycastle', 'library', 'library', path='/estate/pom.xml',
             props={'version': '1.81'}),
        make('AWS KMS', 'service', 'cloud-service', path='/estate/app/kms.py'),
        make('PKCS#11 HSM interface', 'hardware', 'hardware', path='/estate/hsm/bridge.c'),
        make('RSA', 'asymmetric-encryption', 'binary', path='/estate/bin/gateway',
             props={'symbol': 'RSA_public_encrypt'}),
        make('AES-256', 'symmetric-cipher', 'container-image',
             path='/estate/images/app.tar', props={'layer': 'sha256:deadbeef'}),
        make('RSA-1024', 'asymmetric-encryption', 'configuration',
             path='/estate/nginx.conf', props={'setting': 'key-size', 'key_size': 1024}),
    ]
    analyze(artifacts, crqc_year=2033)
    cfg = ScanConfig(targets=[{'path': '/estate', 'kind': 'source'}], crqc_year=2033,
                     organization='Schema Test Bank')
    summary = ScanSummary(scan_id='schema-test', started_at='2026-08-31T10:00:00Z',
                          artifacts_found=len(artifacts), files_scanned=20)
    r = ScanResult(scan_id='schema-test', config=cfg, summary=summary, artifacts=artifacts)
    r.plan = build_plan(artifacts, 2033)
    return r


def test_cbom_validates_against_cyclonedx_16(result, tmp_path):
    bom = json.loads(write_cbom(result, tmp_path / 'c.cbom.json').read_text())
    errors = sorted(_cdx_validator().iter_errors(bom), key=lambda e: list(e.path))
    detail = '\n'.join(f'{"/".join(map(str, e.path))}: {e.message}' for e in errors[:12])
    assert not errors, f'{len(errors)} CycloneDX 1.6 violations:\n{detail}'


def test_sarif_validates_against_sarif_210(result, tmp_path):
    doc = json.loads(write_sarif(result, tmp_path / 's.sarif.json').read_text())
    errors = sorted(_sarif_validator().iter_errors(doc), key=lambda e: list(e.path))
    detail = '\n'.join(f'{"/".join(map(str, e.path))}: {e.message}' for e in errors[:12])
    assert not errors, f'{len(errors)} SARIF 2.1.0 violations:\n{detail}'


def test_every_artifact_type_reaches_the_cbom(result, tmp_path):
    """Coverage guard: if a new artifact type is added without a CBOM mapping,
    this fails instead of silently dropping it from the bill of materials."""
    bom = json.loads(write_cbom(result, tmp_path / 'c.cbom.json').read_text())
    assert len(bom['components']) == len(result.artifacts)
    for c in bom['components']:
        assert c.get('cryptoProperties') or c['type'] in ('library', 'device', 'platform'), \
            f'{c["name"]} has neither cryptoProperties nor a non-crypto component type'
