"""Live TLS endpoint probe.

Source scanning tells you what the code intends. A handshake tells you what the
estate actually negotiates, which is frequently different -- a load balancer or
CDN in front of the app decides the real cipher suite. The problem statement asks
for "internal and external facing" discovery, and this is the external half.

Uses only the standard library ssl/socket plus `cryptography` for certificate
parsing, so it works on an analyst laptop with no extra tooling.
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa

from .models import Artifact, ArtifactType, DiscoverySource, Evidence
from .knowledge_base import canonical_algorithm

# TLS versions we attempt, strongest first. Probing each individually is how you
# learn the real floor: a server that accepts TLS 1.0 is a finding even when it
# prefers 1.3.
TLS_VERSIONS = [
    ('TLSv1.3', ssl.TLSVersion.TLSv1_3),
    ('TLSv1.2', ssl.TLSVersion.TLSv1_2),
    ('TLSv1.1', ssl.TLSVersion.TLSv1_1),
    ('TLSv1.0', ssl.TLSVersion.TLSv1),
]

# Hybrid PQC groups worth asking for, best first. If the server picks one, the
# endpoint is already quantum-resistant for key agreement and that is worth
# recording as good news rather than only cataloguing failures.
PQC_GROUPS = ['X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024',
              'X25519Kyber768Draft00']

DEFAULT_TIMEOUT = 6.0

# Python's ssl module exposes no way to select TLS 1.3 key-exchange groups
# (no SSL_CTX_set1_groups binding), so PQC-group negotiation has to go through
# the openssl CLI. Requires OpenSSL 3.5+; on anything older the probe reports
# `pqc_probe: unavailable` rather than silently claiming "no PQC support".
_OPENSSL_CANDIDATES = [
    '/opt/homebrew/opt/openssl@3.6/bin/openssl',
    '/opt/homebrew/opt/openssl@3.5/bin/openssl',
    '/opt/homebrew/opt/openssl@3/bin/openssl',
    '/usr/local/opt/openssl@3/bin/openssl',
]


def find_pqc_capable_openssl() -> str | None:
    """Locate an openssl binary that knows about ML-KEM hybrid groups."""
    candidates = [p for p in _OPENSSL_CANDIDATES if os.path.exists(p)]
    which = shutil.which('openssl')
    if which:
        candidates.append(which)
    for path in candidates:
        try:
            out = subprocess.run([path, 'list', '-tls1_3-groups'],
                                 capture_output=True, text=True, timeout=5)
            listing = (out.stdout or '') + (out.stderr or '')
            if 'mlkem' in listing.lower():
                return path
            # Older 3.5 builds do not implement `list -tls1_3-groups`; fall back
            # to a version check.
            ver = subprocess.run([path, 'version'], capture_output=True,
                                 text=True, timeout=5).stdout
            m = re.search(r'OpenSSL\s+(\d+)\.(\d+)', ver)
            if m and (int(m.group(1)), int(m.group(2))) >= (3, 5):
                return path
        except (OSError, subprocess.SubprocessError):
            continue
    return None


_OPENSSL_BIN: str | None | bool = False   # False = not yet resolved


def _openssl_bin() -> str | None:
    global _OPENSSL_BIN
    if _OPENSSL_BIN is False:
        _OPENSSL_BIN = find_pqc_capable_openssl()
    return _OPENSSL_BIN


def probe_groups(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Ask the endpoint which key-exchange group it picks, including PQC hybrids.

    Returns {'default_group', 'pqc_group', 'pqc_probe', 'tested'}. `pqc_probe`
    is 'ok' when we could actually test, 'unavailable' when no PQC-aware openssl
    exists on this machine -- the distinction matters because "we did not test"
    is not the same finding as "the server said no".
    """
    result = {'default_group': None, 'pqc_group': None,
              'pqc_probe': 'unavailable', 'tested': []}
    binary = _openssl_bin()
    if not binary:
        return result
    result['pqc_probe'] = 'ok'

    def s_client(extra: list[str]) -> str:
        try:
            proc = subprocess.run(
                [binary, 's_client', '-connect', f'{host}:{port}',
                 '-servername', host, '-brief', *extra],
                input='', capture_output=True, text=True, timeout=timeout + 4)
            return (proc.stdout or '') + (proc.stderr or '')
        except (OSError, subprocess.SubprocessError):
            return ''

    # What does it choose unprompted?
    out = s_client([])
    m = re.search(r'Negotiated TLS1\.3 group:\s*(\S+)', out)
    if m:
        result['default_group'] = m.group(1)
    else:
        m = re.search(r'Server Temp Key:\s*\w+,\s*(\S+)', out)
        if m:
            result['default_group'] = m.group(1).rstrip(',')

    # Will it do a hybrid PQC group if we insist?
    if result['default_group'] and 'mlkem' in result['default_group'].lower():
        result['pqc_group'] = result['default_group']
        return result
    for group in PQC_GROUPS:
        result['tested'].append(group)
        out = s_client(['-groups', group])
        m = re.search(r'Negotiated TLS1\.3 group:\s*(\S+)', out)
        if m and 'mlkem' in m.group(1).lower():
            result['pqc_group'] = m.group(1)
            break
    return result


def _base_context(min_v, max_v) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # We are inventorying, not authenticating: a self-signed internal cert is
    # exactly the kind of thing we need to see rather than reject.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = min_v
        ctx.maximum_version = max_v
    except (ValueError, OSError):
        # OpenSSL builds compiled without TLS 1.0/1.1 refuse to set them.
        raise
    try:
        ctx.set_ciphers('ALL:@SECLEVEL=0')
    except ssl.SSLError:
        try:
            ctx.set_ciphers('ALL')
        except ssl.SSLError:
            pass
    return ctx


def probe_endpoint(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT,
                   server_name: str | None = None) -> dict:
    """Handshake with one endpoint and report everything observable.

    Returns a dict with `reachable`, the negotiated parameters, the accepted
    protocol versions, and the leaf certificate details. Never raises for network
    conditions -- an unreachable endpoint is a result, not an error.
    """
    sni = server_name or host
    out: dict = {
        'host': host, 'port': port, 'sni': sni, 'reachable': False,
        'accepted_versions': [], 'rejected_versions': [], 'error': None,
        'negotiated': None, 'certificate': None, 'pqc_group': None,
        'default_group': None, 'pqc_probe': 'unavailable', 'groups_tested': [],
    }

    # Best handshake the server will give us, plus certificate.
    try:
        ctx = _base_context(ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_3)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ss:
                out['reachable'] = True
                cipher = ss.cipher()          # (name, protocol, secret_bits)
                out['negotiated'] = {
                    'version': ss.version(),
                    'cipher_suite': cipher[0] if cipher else None,
                    'secret_bits': cipher[2] if cipher else None,
                }
                der = ss.getpeercert(binary_form=True)
                if der:
                    out['certificate'] = _describe_cert(der)
    except (socket.timeout, TimeoutError):
        out['error'] = 'timeout'
        return _flatten(out)
    except socket.gaierror as e:
        out['error'] = f'dns: {e}'
        return _flatten(out)
    except (ConnectionRefusedError, OSError) as e:
        out['error'] = f'connect: {e}'
        return _flatten(out)
    except ssl.SSLError as e:
        out['error'] = f'tls: {e}'
        return _flatten(out)

    # Which protocol versions does it still accept? Each needs its own handshake.
    for label, version in TLS_VERSIONS:
        try:
            ctx = _base_context(version, version)
        except (ValueError, OSError):
            continue    # this Python/OpenSSL cannot speak that version at all
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni):
                    out['accepted_versions'].append(label)
        except Exception:
            out['rejected_versions'].append(label)

    # Key-exchange group, including hybrid PQC. Needs the openssl CLI.
    if 'TLSv1.3' in out['accepted_versions']:
        groups = probe_groups(host, port, timeout=timeout)
        out['default_group'] = groups['default_group']
        out['pqc_group'] = groups['pqc_group']
        out['pqc_probe'] = groups['pqc_probe']
        out['groups_tested'] = groups['tested']
        if out['negotiated'] and groups['default_group']:
            out['negotiated']['group'] = groups['default_group']

    return _flatten(out)


def _flatten(out: dict) -> dict:
    """Add flat aliases for the nested negotiated block.

    The nested shape is the honest record of one handshake; the flat keys are
    what the console and the CLI table read. Both are emitted so neither has to
    reach into the other's structure and guess.
    """
    neg = out.get('negotiated') or {}
    out['negotiated_version'] = neg.get('version')
    out['cipher'] = neg.get('cipher_suite')
    out['secret_bits'] = neg.get('secret_bits')

    probe_state = out.get('pqc_probe', 'unavailable')
    out['pqc_probe_supported'] = probe_state == 'ok'
    if probe_state != 'ok':
        # Either we never got far enough to test, or this machine has no
        # PQC-aware openssl. Unknown is not the same finding as "server said no".
        out['pqc_hybrid_supported'] = None
    else:
        out['pqc_hybrid_supported'] = bool(out.get('pqc_group'))

    notes = []
    if not out.get('reachable'):
        notes.append('handshake did not complete; nothing was observed on the wire')
    elif probe_state == 'unavailable':
        if 'TLSv1.3' not in out.get('accepted_versions', []):
            notes.append('key-exchange group not tested: endpoint does not accept TLS 1.3')
        else:
            notes.append('hybrid PQC key exchange could not be tested: no openssl '
                         'binary on PATH supports TLS 1.3 group selection')
    if out.get('groups_tested'):
        notes.append('offered ' + ', '.join(out['groups_tested']))
    out['probe_notes'] = notes
    return out


def _describe_cert(der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        alg, size, curve = 'RSA', pub.key_size, None
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        alg, size, curve = 'ECDSA', pub.curve.key_size, pub.curve.name
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        alg, size, curve = 'Ed25519', 256, 'ed25519'
    elif isinstance(pub, ed448.Ed448PublicKey):
        alg, size, curve = 'Ed448', 448, 'ed448'
    elif isinstance(pub, dsa.DSAPublicKey):
        alg, size, curve = 'DSA', pub.key_size, None
    else:
        alg, size, curve = type(pub).__name__, None, None

    not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') \
        else cert.not_valid_after.replace(tzinfo=timezone.utc)
    not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') \
        else cert.not_valid_before.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'public_key_algorithm': alg,
        'key_size': size,
        'curve': curve,
        'signature_algorithm': cert.signature_algorithm_oid._name,
        'not_before': not_before.isoformat(),
        'not_after': not_after.isoformat(),
        'expired': not_after < now,
        'days_remaining': (not_after - now).days,
        'lifetime_days': (not_after - not_before).days,
        'self_signed': cert.subject == cert.issuer,
        'serial': format(cert.serial_number, 'x'),
    }


def probe_to_artifacts(probe: dict) -> list[Artifact]:
    """Convert one probe result into inventory artifacts.

    Everything emitted here carries network-probe provenance so the UI can
    distinguish "the code says" from "the wire says".
    """
    if not probe.get('reachable'):
        return []

    endpoint = f"{probe['host']}:{probe['port']}"
    out: list[Artifact] = []

    def ev(detail: str) -> Evidence:
        return Evidence(file_path=f'tls://{endpoint}', snippet=detail)

    neg = probe.get('negotiated') or {}

    # Negotiated protocol version.
    if neg.get('version'):
        canon, _ = canonical_algorithm(neg['version'])
        out.append(Artifact(
            artifact_type=ArtifactType.TLS_ENDPOINT.value,
            name=canon, category='protocol',
            source=DiscoverySource.NETWORK.value,
            evidence=ev(f"negotiated {neg['version']} with {neg.get('cipher_suite')}"),
            properties={'endpoint': endpoint, 'setting': 'negotiated-version',
                        'observed': True}))

    # Every version still accepted below TLS 1.2 is its own finding.
    for label in probe.get('accepted_versions', []):
        if label in ('TLSv1.3',):
            continue
        canon, entry = canonical_algorithm(label)
        if not entry:
            continue
        out.append(Artifact(
            artifact_type=ArtifactType.TLS_ENDPOINT.value,
            name=canon, category='protocol',
            source=DiscoverySource.NETWORK.value,
            evidence=ev(f'server completed a {label} handshake'),
            properties={'endpoint': endpoint, 'setting': 'accepted-version',
                        'observed': True}))

    # Negotiated cipher suite -> its weakest component.
    if neg.get('cipher_suite'):
        canon, entry = canonical_algorithm(neg['cipher_suite'])
        if entry:
            out.append(Artifact(
                artifact_type=ArtifactType.TLS_ENDPOINT.value,
                name=canon, category='cipher-suite',
                source=DiscoverySource.NETWORK.value,
                evidence=ev(f"cipher suite {neg['cipher_suite']}"),
                properties={'endpoint': endpoint, 'raw': neg['cipher_suite'],
                            'setting': 'negotiated-cipher',
                            'secret_bits': neg.get('secret_bits'), 'observed': True}))

    # Key-exchange group, when the runtime exposes it.
    if neg.get('group'):
        canon, entry = canonical_algorithm(neg['group'])
        if entry:
            out.append(Artifact(
                artifact_type=ArtifactType.TLS_ENDPOINT.value,
                name=canon, category='key-agreement',
                source=DiscoverySource.NETWORK.value,
                evidence=ev(f"key-exchange group {neg['group']}"),
                properties={'endpoint': endpoint, 'setting': 'negotiated-group',
                            'observed': True}))

    # Hybrid PQC support is good news and belongs in the inventory too.
    if probe.get('pqc_group'):
        canon, _ = canonical_algorithm(probe['pqc_group'])
        out.append(Artifact(
            artifact_type=ArtifactType.TLS_ENDPOINT.value,
            name=canon, category='kem',
            source=DiscoverySource.NETWORK.value,
            evidence=ev(f"server accepted hybrid group {probe['pqc_group']}"),
            properties={'endpoint': endpoint, 'setting': 'pqc-capable', 'observed': True}))

    # Leaf certificate.
    cert = probe.get('certificate')
    if cert:
        out.append(Artifact(
            artifact_type=ArtifactType.CERTIFICATE.value,
            name=f"{cert['public_key_algorithm']} certificate", category='certificate',
            source=DiscoverySource.NETWORK.value,
            evidence=ev(f"served by {endpoint}: {cert['subject']}"),
            properties={**cert, 'endpoint': endpoint, 'observed': True}))

    return out


class TLSEndpointScanner:
    """Engine-compatible scanner wrapper for network targets.

    Target paths arrive as `host:port` or `host`, matching how the CLI and API
    pass them, so nothing else in the engine needs to know this is a network
    scan rather than a filesystem walk.
    """

    def __init__(self, emit, count_file, timeout: float = DEFAULT_TIMEOUT):
        self._emit = emit
        self._count_file = count_file
        self.timeout = timeout
        self.probes: list[dict] = []

    def scan(self, root, kind: str):
        spec = str(root)
        host, _, port_s = spec.rpartition(':')
        if not host:
            host, port = spec, 443
        else:
            try:
                port = int(port_s)
            except ValueError:
                host, port = spec, 443
        probe = probe_endpoint(host, port, timeout=self.timeout)
        self.probes.append(probe)
        self._count_file()
        for a in probe_to_artifacts(probe):
            self._emit(a)
        return probe
