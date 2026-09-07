"""Network probe tests.

Two kinds of test here. The offline ones pin the shape and honesty of the probe
result and the artifact conversion. The live ones are marked `network` and make
real handshakes; they are skipped when the host has no internet, because a test
that silently passes offline would defeat the point.

Run only the offline set with:  pytest -m 'not network'
"""
from __future__ import annotations

import socket

import pytest

from atlas.network import (probe_endpoint, probe_to_artifacts, _flatten,
                           find_pqc_capable_openssl)
from atlas.risk import analyze


def _online(host='cloudflare.com', port=443, timeout=3) -> bool:
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


ONLINE = _online()
needs_net = pytest.mark.skipif(not ONLINE, reason='no network access')


# ---------------------------------------------------------------------------
# Result shape and honesty (offline)
# ---------------------------------------------------------------------------
def test_flatten_reports_unknown_when_pqc_untestable():
    """No PQC-aware openssl must yield None, never False.

    "We could not test" and "the server refused" are different findings and the
    UI renders them differently.
    """
    out = _flatten({'reachable': True, 'negotiated': {'version': 'TLSv1.3'},
                    'pqc_probe': 'unavailable', 'accepted_versions': ['TLSv1.3']})
    assert out['pqc_hybrid_supported'] is None
    assert out['pqc_probe_supported'] is False
    assert any('could not be tested' in n for n in out['probe_notes'])


def test_flatten_reports_false_when_server_declines():
    out = _flatten({'reachable': True, 'negotiated': {'version': 'TLSv1.3'},
                    'pqc_probe': 'ok', 'pqc_group': None,
                    'accepted_versions': ['TLSv1.3'],
                    'groups_tested': ['X25519MLKEM768']})
    assert out['pqc_hybrid_supported'] is False
    assert out['pqc_probe_supported'] is True
    assert any('offered' in n for n in out['probe_notes'])


def test_flatten_reports_true_when_hybrid_negotiated():
    out = _flatten({'reachable': True, 'negotiated': {'version': 'TLSv1.3'},
                    'pqc_probe': 'ok', 'pqc_group': 'X25519MLKEM768',
                    'accepted_versions': ['TLSv1.3']})
    assert out['pqc_hybrid_supported'] is True


def test_flatten_explains_missing_group_on_pre_tls13_endpoint():
    out = _flatten({'reachable': True, 'negotiated': {'version': 'TLSv1.2'},
                    'pqc_probe': 'unavailable', 'accepted_versions': ['TLSv1.2']})
    assert any('does not accept TLS 1.3' in n for n in out['probe_notes'])


def test_flatten_exposes_flat_aliases():
    out = _flatten({'reachable': True, 'accepted_versions': [],
                    'negotiated': {'version': 'TLSv1.3', 'cipher_suite': 'TLS_AES_256_GCM_SHA384',
                                   'secret_bits': 256}})
    assert out['negotiated_version'] == 'TLSv1.3'
    assert out['cipher'] == 'TLS_AES_256_GCM_SHA384'
    assert out['secret_bits'] == 256


def test_unreachable_host_is_a_result_not_an_exception():
    p = probe_endpoint('nonexistent-host-for-atlas-tests.invalid', 443, timeout=3)
    assert p['reachable'] is False
    assert p['error']
    assert p['pqc_hybrid_supported'] is None
    assert probe_to_artifacts(p) == [], 'unreachable host must not invent findings'


def test_unreachable_host_says_why():
    p = probe_endpoint('nonexistent-host-for-atlas-tests.invalid', 443, timeout=3)
    assert any('did not complete' in n for n in p['probe_notes'])


# ---------------------------------------------------------------------------
# Artifact conversion (offline, synthetic probe)
# ---------------------------------------------------------------------------
def _fake_probe(**over) -> dict:
    base = {
        'host': 'edge.example.com', 'port': 443, 'sni': 'edge.example.com',
        'reachable': True,
        'accepted_versions': ['TLSv1.3', 'TLSv1.2', 'TLSv1.0'],
        'rejected_versions': [],
        'negotiated': {'version': 'TLSv1.2', 'cipher_suite': 'ECDHE-RSA-AES128-GCM-SHA256',
                       'secret_bits': 128},
        'pqc_probe': 'ok', 'pqc_group': None, 'default_group': 'X25519',
        'groups_tested': ['X25519MLKEM768'],
        'certificate': {
            'subject': 'CN=edge.example.com', 'issuer': 'CN=Test CA',
            'public_key_algorithm': 'RSA', 'key_size': 2048,
            'signature_algorithm': 'sha256WithRSAEncryption',
            'not_before': '2026-01-01T00:00:00+00:00',
            'not_after': '2027-01-01T00:00:00+00:00',
            'expired': False, 'days_remaining': 120, 'lifetime_days': 365,
            'self_signed': False, 'serial': 'ab12',
        },
        'error': None,
    }
    base.update(over)
    return _flatten(base)


def test_probe_artifacts_cover_version_cipher_group_and_cert():
    arts = probe_to_artifacts(_fake_probe())
    names = [a.name for a in arts]
    assert any('TLS' in n for n in names), 'no protocol version artifact'
    assert any(a.artifact_type == 'certificate' for a in arts), 'no certificate artifact'
    for a in arts:
        assert a.evidence.file_path.startswith('tls://'), \
            'probe findings must be traceable to the endpoint'


def test_legacy_version_acceptance_is_flagged():
    arts = probe_to_artifacts(_fake_probe())
    analyze(arts, crqc_year=2033)
    legacy = [a for a in arts if a.name in ('TLSv1.0', 'TLSv1.1')]
    assert legacy, 'accepting TLS 1.0 must produce a finding'
    assert all(a.severity in ('critical', 'high') for a in legacy)


def test_probe_findings_flow_through_the_risk_model():
    arts = probe_to_artifacts(_fake_probe())
    analyze(arts, crqc_year=2033)
    assert any(a.recommendation for a in arts), 'probe findings need remediation advice'
    assert all(a.quantum_impact != 'unknown' or a.artifact_type == 'certificate'
               for a in arts)


# ---------------------------------------------------------------------------
# Live handshakes (network)
# ---------------------------------------------------------------------------
@needs_net
def test_live_probe_reads_real_parameters():
    p = probe_endpoint('cloudflare.com', 443, timeout=8)
    assert p['reachable'] is True
    assert p['negotiated_version'] in ('TLSv1.3', 'TLSv1.2')
    assert p['cipher']
    assert 'TLSv1.3' in p['accepted_versions']
    assert p['certificate'] and p['certificate']['subject']


@needs_net
def test_live_probe_detects_cloudflare_hybrid_pqc():
    """Cloudflare has shipped X25519MLKEM768 since 2024.

    Skipped rather than failed when this machine has no PQC-capable openssl,
    because that is a local capability gap, not a product defect.
    """
    if not find_pqc_capable_openssl():
        pytest.skip('no PQC-aware openssl on PATH')
    p = probe_endpoint('cloudflare.com', 443, timeout=10)
    assert p['pqc_probe_supported'] is True
    assert p['pqc_hybrid_supported'] is True
    assert 'mlkem' in (p['pqc_group'] or '').lower()


@needs_net
def test_live_probe_produces_inventory_artifacts():
    p = probe_endpoint('github.com', 443, timeout=8)
    arts = probe_to_artifacts(p)
    assert arts
    analyze(arts, crqc_year=2033)
    for a in arts:
        assert a.evidence.file_path.startswith('tls://')
        assert 0.0 <= a.risk_score <= 10.0
