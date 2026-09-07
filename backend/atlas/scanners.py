"""Discovery engines: source, certificates, keys, libraries, containers, binaries, configs."""
from __future__ import annotations

import os
import re
import warnings
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

from .models import Artifact, ArtifactType, DiscoverySource, Evidence
from .knowledge_base import canonical_algorithm, extract_mode, UNAUTHENTICATED_MODES
from .crypto_services import lookup_library

SOURCE_LANGUAGES = {'.py', '.java', '.js', '.ts', '.jsx', '.tsx', '.go', '.c', '.h', '.cpp', '.cc', '.hpp', '.cs', '.rb', '.php', '.rs'}

# (regex, literal algorithm name or None, pattern_class or None)
SOURCE_PATTERNS = [
    # Python
    (r'RSA\.generate|RSA\.construct', 'RSA', None),
    (r'generate_private_key\(', None, 'key-generation'),
    (r'ec\.EllipticCurve|SECP256R1|SECP384R1|SECP521R1', 'ECDSA', None),
    (r'Ed25519PrivateKey|Ed448PrivateKey', 'Ed25519', None),
    (r'X25519PrivateKey|Curve25519', 'X25519', None),
    (r'AESGCM\(', 'AES', 'aes-gcm'),
    (r'ChaCha20Poly1305\(', 'ChaCha20', None),
    (r'algorithms\.AES|Cipher\(algorithms\.AES', 'AES', None),
    (r'modes\.CBC', 'AES-CBC', None),
    (r'modes\.ECB', 'AES-ECB', None),
    (r'algorithms\.DES3', '3DES', None),
    (r'algorithms\.DES\b', 'DES', None),
    (r'algorithms\.Blowfish', 'Blowfish', None),
    (r'algorithms\.ARC4', 'RC4', None),
    (r'padding\.PKCS7', None, 'pkcs7'),
    (r'MD5\(|algorithms\.MD5|hashlib\.md5', 'MD5', None),
    (r'hashlib\.sha1|SHA1\(', 'SHA-1', None),
    (r'pbkdf2_hmac|PBKDF2HMAC', 'PBKDF2', None),
    (r'scrypt\(', 'scrypt', None),
    (r'bcrypt\.', 'bcrypt', None),
    (r'Fernet\(', 'Fernet', None),
    (r'hmac\.new|HMAC\(', 'HMAC', None),
    (r'ML[-_]KEM', 'ML-KEM', None),
    (r'ML[-_]DSA', 'ML-DSA', None),
    # Java
    (r'KeyPairGenerator\.getInstance\("RSA', 'RSA', None),
    (r'KeyPairGenerator\.getInstance\("EC', 'ECDSA', None),
    (r'KeyPairGenerator\.getInstance\("DSA', 'DSA', None),
    (r'Cipher\.getInstance\("AES', 'AES', None),
    (r'Cipher\.getInstance\("DES', 'DES', None),
    (r'Cipher\.getInstance\("RSA', 'RSA', None),
    (r'Signature\.getInstance\("SHA1withRSA', 'SHA-1', None),
    (r'Signature\.getInstance\("MD5', 'MD5', None),
    (r'MessageDigest\.getInstance\("MD5"', 'MD5', None),
    (r'MessageDigest\.getInstance\("SHA-?1"', 'SHA-1', None),
    (r'KeyGenerator\.getInstance\("AES', 'AES', None),
    (r'SecretKeyFactory.*PBKDF2', 'PBKDF2', None),
    # JavaScript / TypeScript
    (r'generateKeyPairSync\("rsa', 'RSA', None),
    (r'generateKeyPairSync\("ec', 'ECDSA', None),
    (r'generateKeyPairSync\("ed25519', 'Ed25519', None),
    (r'createCipheriv\("des', 'DES', None),
    (r'NodeRSA|nodeRsa', 'RSA', None),
    (r'createHash\("md5"', 'MD5', None),
    (r'createHash\("sha1"', 'SHA-1', None),
    (r'aes-?128-?cbc|aes-?128-?ecb', 'AES-128', None),
    (r'jsencrypt|JSEncrypt', 'RSA', None),
    # Go
    (r'rsa\.GenerateKey|rsa\.EncryptOAEP', 'RSA', None),
    (r'ecdsa\.GenerateKey|ecdsa\.Sign', 'ECDSA', None),
    (r'ed25519\.GenerateKey', 'Ed25519', None),
    (r'aes\.NewCipher', 'AES', None),
    (r'des\.NewCipher|tripleDES', 'DES', None),
    (r'sha1\.New\(', 'SHA-1', None),
    (r'md5\.New\(', 'MD5', None),
    (r'chacha20poly1305', 'ChaCha20', None),
    # C / C++
    (r'RSA_generate_key_ex|RSA_new|EVP_PKEY_RSA', 'RSA', None),
    (r'EC_KEY_generate_key|EC_GROUP_new_curve', 'ECDSA', None),
    (r'X25519_keypair|X25519\(', 'X25519', None),
    (r'EVP_aes_128_cbc', 'AES-128', None),
    (r'EVP_aes_256_gcm', 'AES-256', None),
    (r'EVP_des_ede', '3DES', None),
    (r'MD5_Init|EVP_md5', 'MD5', None),
    (r'SHA1_Init|EVP_sha1', 'SHA-1', None),
    # C#
    (r'RSACryptoServiceProvider|RSA\.Create', 'RSA', None),
    (r'ECDsa\.Create', 'ECDSA', None),
    (r'AesManaged|Aes\.Create', 'AES', None),
    (r'TripleDESCryptoServiceProvider', '3DES', None),
    (r'MD5CryptoServiceProvider|MD5\.Create', 'MD5', None),
    (r'SHA1CryptoServiceProvider|SHA1\.Create', 'SHA-1', None),
    # Ruby / PHP
    (r'OpenSSL::PKey::RSA\.generate', 'RSA', None),
    (r'OpenSSL::PKey::EC\.generate', 'ECDSA', None),
    (r'openssl_pkey_new|openssl_encrypt', None, 'openssl-api'),
]

# (regex with one capture group, finding kind). Every entry must be a 2-tuple
# with exactly one capturing group: the scanner reads m.group(1).
CONFIG_PATTERNS = [
    # nginx / Apache TLS
    (r'ssl_protocols\s+([^;]+);', 'tls-protocols'),
    (r'ssl_ciphers\s+([^;]+);', 'tls-ciphers'),
    (r'SSLProtocol\s+([^\n]+)', 'tls-protocols'),
    (r'SSLCipherSuite\s+([^\n]+)', 'tls-ciphers'),
    (r'Protocols?\s+([-+]?(?:TLSv[0-9.]+|SSLv[0-9]+)[^\n]*)', 'tls-protocols'),
    # OpenSSL / .NET / Java config
    (r'MinProtocol\s*=\s*(TLSv[0-9.]+)', 'tls-min-version'),
    (r'MaxProtocol\s*=\s*(TLSv[0-9.]+)', 'tls-max-version'),
    (r'CipherString\s*=\s*([^\n]+)', 'tls-ciphers'),
    (r'CipherSuites?\s*=\s*([^\n]+)', 'tls-ciphers'),
    (r'default_md\s*=\s*(\w+)', 'signature-digest'),
    (r'default_bits\s*=\s*(\d+)', 'key-size'),
    # OpenSSH
    (r'KexAlgorithms\s+([^\n]+)', 'ssh-kex'),
    (r'^\s*Ciphers\s+([^\n]+)', 'ssh-ciphers'),
    (r'^\s*MACs\s+([^\n]+)', 'ssh-macs'),
    (r'HostKeyAlgorithms\s+([^\n]+)', 'ssh-hostkey'),
    (r'HostKey\s+\S*ssh_host_(\w+)_key', 'ssh-hostkey'),
    # Cloud / IaC
    (r'ssl_policy\s*=\s*"([^"]+)"', 'lb-ssl-policy'),
    (r'customer_master_key_spec\s*=\s*"([^"]+)"', 'kms-key-spec'),
    (r'minimum_protocol_version\s*=\s*"([^"]+)"', 'tls-min-version'),
    (r'signature_algorithm\s*=\s*"([^"]+)"', 'signature-algorithm'),
]

# AWS ELB security policy names encode the TLS floor they permit.
LB_POLICY_PROTOCOLS = {
    'ELBSecurityPolicy-TLS-1-0-2015-04': ['TLSv1.0', 'TLSv1.1', 'TLSv1.2'],
    'ELBSecurityPolicy-TLS-1-1-2017-01': ['TLSv1.1', 'TLSv1.2'],
    'ELBSecurityPolicy-TLS-1-2-2017-01': ['TLSv1.2'],
    'ELBSecurityPolicy-2016-08': ['TLSv1.0', 'TLSv1.1', 'TLSv1.2'],
    'ELBSecurityPolicy-FS-1-2-Res-2020-10': ['TLSv1.2'],
    'ELBSecurityPolicy-TLS13-1-2-2021-06': ['TLSv1.2', 'TLSv1.3'],
}

# KMS key specs map straight onto algorithms.
KMS_KEY_SPECS = {
    'RSA_2048': 'RSA', 'RSA_3072': 'RSA', 'RSA_4096': 'RSA',
    'ECC_NIST_P256': 'ECDSA-P256', 'ECC_NIST_P384': 'ECDSA-P384',
    'ECC_NIST_P521': 'ECDSA-P521', 'ECC_SECG_P256K1': 'ECDSA',
    'SYMMETRIC_DEFAULT': 'AES-256', 'HMAC_256': 'HMAC', 'HMAC_384': 'HMAC',
    'ML_DSA_44': 'ML-DSA-44', 'ML_DSA_65': 'ML-DSA-65', 'ML_DSA_87': 'ML-DSA-87',
}

CERT_EXTS = {'.pem', '.crt', '.cer', '.der', '.p7b', '.p7c'}
KEY_EXTS = {'.pem', '.key', '.ppk', '.pk8'}
KEY_MARKERS = [
    b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----',
    b'-----BEGIN EC PRIVATE KEY-----', b'-----BEGIN OPENSSH PRIVATE KEY-----',
    b'-----BEGIN ENCRYPTED PRIVATE KEY-----', b'-----BEGIN DSA PRIVATE KEY-----',
]
CERT_MARKERS = [b'-----BEGIN CERTIFICATE-----']
MANIFEST_FILES = {'requirements.txt', 'package.json', 'pom.xml', 'build.gradle', 'go.mod',
                  'Cargo.toml', 'composer.json', 'Gemfile', 'Pipfile'}
SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build', 'target'}


def _oid_from_error(exc: Exception) -> str:
    """Pull the dotted OID out of an UnsupportedAlgorithm message.

    `cryptography` raises "Unknown key type: 1.2.643.2.2.19" without exposing the
    OID structurally, so this is the only way to keep the identifier.
    """
    m = re.search(r'(\d+(?:\.\d+){3,})', str(exc))
    return m.group(1) if m else str(exc)[:120]


class Scanner:
    """Base scanner with artifact emit helper."""

    def __init__(self, emit, count_file):
        self._emit = emit
        self._count_file = count_file

    def emit_algo(self, name, path, line, snippet, source=DiscoverySource.SOURCE_CODE.value,
                  atype=ArtifactType.ALGORITHM_USE.value, properties=None):
        canon, entry = canonical_algorithm(name)
        family = (entry or {}).get('family', 'unknown')
        a = Artifact(
            artifact_type=atype, name=name, category=family, source=source,
            evidence=Evidence(file_path=str(path), line=line, snippet=snippet.strip()[:160] if snippet else None),
            properties=properties or {})
        self._emit(a)

    def emit_config_finding(self, kind_tag: str, value: str, ev: Evidence,
                            source: str = DiscoverySource.CONFIGURATION.value):
        """Turn one configuration directive into artifacts.

        Shared by the filesystem ConfigScanner and the in-container config
        scan so both produce identical findings for identical input.
        """
        for artifact in config_finding_artifacts(kind_tag, value, ev, source):
            self._emit(artifact)

    def scan(self, root: Path, kind: str):
        raise NotImplementedError


def config_finding_artifacts(kind_tag: str, value: str, ev: Evidence,
                             source: str = DiscoverySource.CONFIGURATION.value) -> list[Artifact]:
    """Expand a configuration directive into zero or more artifacts.

    Pure function of its inputs so it can be unit-tested directly against
    real nginx/sshd/Apache/Terraform lines.
    """
    out: list[Artifact] = []

    def add(name: str, category: str, atype: str, props: dict):
        out.append(Artifact(artifact_type=atype, name=name, category=category,
                            source=source, evidence=ev, properties=props))

    if kind_tag in ('tls-protocols', 'tls-min-version', 'tls-max-version'):
        # `SSLProtocol -all +TLSv1 +TLSv1.2` — a leading '-' means disabled.
        for token in re.split(r'[\s,:]+', value):
            token = token.strip()
            if not token or token.startswith('-') or token.lower() in ('all', 'none'):
                continue
            token = token.lstrip('+')
            m = re.fullmatch(r'(TLSv?[0-9.]+|SSLv?[0-9]+)', token, re.I)
            if not m:
                continue
            canon, entry = canonical_algorithm(token)
            if entry is None:
                continue
            add(canon, 'protocol', ArtifactType.PROTOCOL.value,
                {'setting': kind_tag, 'raw': token})

    elif kind_tag in ('tls-ciphers', 'ssh-ciphers', 'ssh-kex', 'ssh-macs',
                      'ssh-hostkey', 'signature-algorithm'):
        for token in re.split(r'[:\s,]+', value):
            token = token.strip()
            # '!aNULL' and '-CBC' are exclusions, not usages.
            if not token or token[0] in '!-' or token.upper() in (
                    'DEFAULT', 'HIGH', 'MEDIUM', 'ALL', 'ON', 'OFF'):
                continue
            # `DEFAULT@SECLEVEL=1` weakens the whole policy; flag it as such.
            if 'SECLEVEL' in token.upper():
                m = re.search(r'SECLEVEL=(\d)', token, re.I)
                if m and int(m.group(1)) <= 1:
                    add('OpenSSL SECLEVEL=' + m.group(1), 'configuration-weakness',
                        ArtifactType.CONFIGURATION.value,
                        {'setting': kind_tag, 'raw': token,
                         'note': 'SECLEVEL 0/1 permits SHA-1 signatures and <2048-bit keys'})
                continue
            canon, entry = canonical_algorithm(token)
            if entry is None:
                continue
            category = 'cipher-suite' if kind_tag in ('tls-ciphers', 'ssh-ciphers') else \
                       'key-agreement' if kind_tag == 'ssh-kex' else \
                       'mac' if kind_tag == 'ssh-macs' else 'signature'
            props = {'setting': kind_tag, 'raw': token}
            mode = extract_mode(token)
            if mode:
                props['mode'] = mode
                if mode in UNAUTHENTICATED_MODES:
                    props['unauthenticated_mode'] = True
            add(canon, category, ArtifactType.PROTOCOL.value, props)

    elif kind_tag == 'signature-digest':
        # openssl.cnf default_md
        canon, entry = canonical_algorithm(value.strip())
        if entry is not None:
            add(canon, 'hash', ArtifactType.CONFIGURATION.value,
                {'setting': kind_tag, 'raw': value.strip(),
                 'note': 'default signature digest for certificates issued from this config'})

    elif kind_tag == 'key-size':
        # openssl.cnf default_bits — a 1024-bit default is a real finding.
        try:
            bits = int(value.strip())
        except ValueError:
            return out
        if bits < 2048:
            add(f'RSA-{bits}', 'asymmetric-encryption', ArtifactType.CONFIGURATION.value,
                {'setting': kind_tag, 'key_size': bits,
                 'note': f'{bits}-bit RSA default is below the NIST 2048-bit floor'})

    elif kind_tag == 'lb-ssl-policy':
        policy = value.strip()
        protocols = LB_POLICY_PROTOCOLS.get(policy)
        if protocols is None:
            add(policy, 'configuration-weakness', ArtifactType.CLOUD_SERVICE.value,
                {'setting': kind_tag, 'raw': policy,
                 'note': 'unrecognised load-balancer TLS policy; verify manually'})
        else:
            for proto in protocols:
                canon, entry = canonical_algorithm(proto)
                if entry is None:
                    continue
                add(canon, 'protocol', ArtifactType.PROTOCOL.value,
                    {'setting': kind_tag, 'lb_policy': policy,
                     'note': f'permitted by load-balancer policy {policy}'})

    elif kind_tag == 'kms-key-spec':
        spec = value.strip()
        algo = KMS_KEY_SPECS.get(spec)
        if algo:
            canon, entry = canonical_algorithm(algo)
            add(canon, (entry or {}).get('family', 'unknown'),
                ArtifactType.CLOUD_SERVICE.value,
                {'setting': kind_tag, 'key_spec': spec,
                 'note': f'cloud KMS key material: {spec}'})

    return out


class SourceScanner(Scanner):
    """Scan source files for cryptographic API usage."""

    def scan(self, root: Path, kind: str):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                if fn in MANIFEST_FILES or p.suffix.lower() in CERT_EXTS:
                    continue
                if p.suffix.lower() not in SOURCE_LANGUAGES:
                    continue
                self._count_file()
                try:
                    text = p.read_text(errors='ignore')
                except OSError:
                    continue
                for lineno, line in enumerate(text.splitlines(), 1):
                    for pat, algo, family_hint in SOURCE_PATTERNS:
                        try:
                            hit = re.search(pat, line)
                        except re.error:
                            hit = pat in line
                        if hit:
                            name = algo or family_hint or 'crypto-api'
                            props = {'language': p.suffix.lstrip('.')}
                            if family_hint:
                                props['pattern_class'] = family_hint
                            self.emit_algo(name, p, lineno, line, properties=props)


class CertificateScanner(Scanner):
    """Parse X.509 certificates (PEM chains and DER).

    Real-world certificate corpora contain deliberately malformed test vectors
    (negative serials, non-conforming name encodings, unknown key OIDs). A
    discovery tool that crashes on the first bad certificate is useless against
    exactly the estates that need it, so every parse step is individually
    tolerant and failures are recorded rather than fatal.
    """

    def scan(self, root: Path, kind: str):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                if p.suffix.lower() not in CERT_EXTS and p.name.lower() not in (
                        'cert.pem', 'ca.pem', 'server.pem', 'fullchain.pem', 'chain.pem', 'certs.pem'):
                    continue
                self._count_file()
                try:
                    data = p.read_bytes()
                except OSError:
                    continue
                certs = self._parse_pem_chain(data)
                if not certs:
                    certs = self._parse_der(data)
                for i, cert in enumerate(certs):
                    try:
                        self._emit_cert(cert, p, i)
                    except Exception:
                        # Unparseable beyond recovery: record its existence so the
                        # count is honest, without inventing any detail.
                        self._emit(Artifact(
                            artifact_type=ArtifactType.CERTIFICATE.value,
                            name='Unparseable certificate', category='certificate',
                            source=DiscoverySource.CERTIFICATE.value,
                            evidence=Evidence(file_path=str(p),
                                              snippet='certificate present but not parseable'),
                            properties={'parse_error': True, 'index': i}))

    def _parse_pem_chain(self, data: bytes):
        import base64
        certs = []
        begin = b'-----BEGIN CERTIFICATE-----'
        end = b'-----END CERTIFICATE-----'
        idx = 0
        while True:
            s = data.find(begin, idx)
            if s < 0:
                break
            e = data.find(end, s)
            if e < 0:
                break
            b64 = data[s + len(begin):e]
            try:
                der = base64.b64decode(re.sub(rb'\s+', b'', b64))
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    certs.append(x509.load_der_x509_certificate(der))
            except Exception:
                pass
            idx = e + len(end)
        return certs

    def _parse_der(self, data):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                return [x509.load_der_x509_certificate(data)]
        except Exception:
            return []

    @staticmethod
    def _safe_name(name) -> str:
        """RFC4514 string, or a marker. Non-conforming DN encodings exist."""
        try:
            return name.rfc4514_string()
        except Exception:
            return '<unparseable DN>'

    @staticmethod
    def _safe_serial(cert) -> str | None:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                return format(cert.serial_number, 'x')
        except Exception:
            return None

    def emit_parsed_cert(self, cert, evidence, lifetime_years=None):
        """Emit an artifact from an already-parsed cert object.

        A certificate signed with an algorithm `cryptography` cannot instantiate
        (GOST, obscure national curves, experimental PQC OIDs) still belongs in
        the inventory -- arguably more so. Key parsing failure degrades to
        recording the raw OID rather than dropping the certificate.
        """
        try:
            pk = cert.public_key()
            alg_name, key_size, curve = self._key_info(pk)
            unsupported_oid = None
        except Exception as exc:
            alg_name, key_size, curve = 'Unknown', None, None
            unsupported_oid = _oid_from_error(exc)

        try:
            sig = cert.signature_algorithm_oid._name
        except Exception:
            sig = None
        subject = self._safe_name(cert.subject)
        issuer = self._safe_name(cert.issuer)
        try:
            not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
        except Exception:
            not_before = None
        try:
            not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
        except Exception:
            not_after = None
        now = datetime.now(timezone.utc)
        expired = (not_after < now) if not_after else None
        lifetime_days = (not_after - not_before).days if (not_after and not_before) else None
        props = {
            'subject': subject, 'issuer': issuer,
            'not_before': not_before.isoformat() if not_before else None,
            'not_after': not_after.isoformat() if not_after else None,
            'expired': expired, 'lifetime_days': lifetime_days,
            'key_size': key_size, 'curve': curve, 'signature_algorithm': sig,
            'serial': self._safe_serial(cert),
            'self_signed': subject == issuer,
        }
        props = {k: v for k, v in props.items() if v is not None}
        if unsupported_oid:
            props['unsupported_key_oid'] = unsupported_oid
            props['note'] = ('Public key algorithm is not implemented by this runtime; '
                             'recorded by OID so it is not silently dropped.')
        if expired:
            props['expiry_note'] = 'EXPIRED'
        a = Artifact(
            artifact_type=ArtifactType.CERTIFICATE.value,
            name=f'{alg_name} certificate', category='certificate',
            source=evidence.container_layer and DiscoverySource.CONTAINER_IMAGE.value or DiscoverySource.CERTIFICATE.value,
            evidence=evidence, properties=props)
        # Note: lifetime_years is deliberately left unset. risk.estimate_lifetime
        # owns that decision so a root CA gets the shelf-life of what it signs,
        # not merely its own validity window.
        if lifetime_years:
            a.lifetime_years = lifetime_years
        self._emit(a)

    def _emit_cert(self, cert, p, index):
        subj = self._safe_name(cert.subject)
        self.emit_parsed_cert(cert, Evidence(file_path=str(p), snippet=subj[:120]))

    def _key_info(self, pk):
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
        if isinstance(pk, rsa.RSAPublicKey):
            return 'RSA', pk.key_size, None
        if isinstance(pk, ec.EllipticCurvePublicKey):
            return 'ECDSA', pk.curve.key_size, pk.curve.name
        if isinstance(pk, ed25519.Ed25519PublicKey):
            return 'Ed25519', 256, None
        if isinstance(pk, ed448.Ed448PublicKey):
            return 'Ed448', 456, None
        if isinstance(pk, dsa.DSAPublicKey):
            return 'DSA', pk.key_size, None
        return 'Unknown', None, None


class KeyScanner(Scanner):
    """Detect private keys in PEM / PKCS / OpenSSH formats."""

    def scan(self, root: Path, kind: str):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                if p.suffix.lower() not in (KEY_EXTS | CERT_EXTS | {'.pub'}) and p.suffix != '':
                    continue
                try:
                    data = p.read_bytes()
                except OSError:
                    continue
                if not any(m in data for m in KEY_MARKERS):
                    continue
                self._count_file()
                text = data.decode(errors='ignore')
                for lineno, line in enumerate(text.splitlines(), 1):
                    for m in KEY_MARKERS:
                        marker = m.decode()
                        if line.strip() == marker:
                            kind_name = marker.replace('-----BEGIN ', '').replace(' PRIVATE KEY-----', '').strip()
                            props = self._inspect(data)
                            a = Artifact(
                                artifact_type=ArtifactType.KEY.value,
                                name=f'{kind_name} private key', category='private-key',
                                source=DiscoverySource.KEY_STORE.value,
                                evidence=Evidence(file_path=str(p), line=lineno, snippet=line.strip()),
                                properties=props)
                            self._emit(a)
                            break

    def _inspect(self, data) -> dict:
        props = {}
        text = data.decode(errors='ignore')
        m = re.search(r'ssh-(rsa|ed25519|ecdsa-sha2-nistp\d+)', text)
        if m:
            props['openssh_type'] = m.group(1)
        props['encrypted'] = b'ENCRYPTED' in data or 'Proc-Type: 4,ENCRYPTED' in text
        props['size_bytes'] = len(data)
        return props


class LibraryScanner(Scanner):
    """Detect crypto libraries from dependency manifests."""

    def scan(self, root: Path, kind: str):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                if fn not in MANIFEST_FILES:
                    continue
                self._count_file()
                try:
                    text = p.read_text(errors='ignore')
                except OSError:
                    continue
                for lib, version, lineno, line in self._scan_manifest(fn, text):
                    key, entry = lookup_library(lib)
                    props = {'version': version, 'manifest': fn}
                    if entry:
                        props['pqc'] = entry.get('pqc', False)
                        props['pqc_note'] = entry.get('pqc_note')
                        props['lib_category'] = entry.get('category')
                        if entry.get('min_pqc_version') and version:
                            props['pqc_outdated'] = self._version_lt(version, entry['min_pqc_version'])
                    a = Artifact(
                        artifact_type=ArtifactType.LIBRARY.value,
                        name=key, category='library',
                        source=DiscoverySource.LIBRARY_MANIFEST.value,
                        evidence=Evidence(file_path=str(p), line=lineno, snippet=line.strip()[:160]),
                        properties=props)
                    self._emit(a)

    def _version_tuple(self, v):
        try:
            parts = re.findall(r'\d+', v)
            return tuple(int(x) for x in (parts[:3] or ['0']))
        except Exception:
            return (0,)

    def _version_lt(self, a, b):
        return self._version_tuple(a) < self._version_tuple(b)

    def _scan_manifest(self, fn, text):
        lines = text.splitlines()
        found = []
        if fn in ('requirements.txt', 'Pipfile'):
            for lineno, line in enumerate(lines, 1):
                m = re.match(r'^\s*([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]+\s*([0-9][^,;\s#]*))?', line)
                if m:
                    found.append((m.group(1), m.group(2), lineno, line))
        elif fn == 'package.json':
            import json as _json
            try:
                data = _json.loads(text)
            except Exception:
                data = {}
            deps = {}
            for section in ('dependencies', 'devDependencies'):
                deps.update(data.get(section, {}) or {})
            for lib, ver in deps.items():
                lineno = next((i for i, l in enumerate(lines, 1) if f'"{lib}"' in l), None)
                found.append((lib, ver, lineno, f'"{lib}": "{ver}"'))
        elif fn == 'pom.xml':
            pending_artifact = None
            for lineno, line in enumerate(lines, 1):
                m = re.search(r'<artifactId>([^<]+)</artifactId>', line)
                if m:
                    pending_artifact = (m.group(1), lineno, line.strip())
                    continue
                if pending_artifact:
                    vm = re.search(r'<version>([^<]+)</version>', line)
                    if vm:
                        found.append((pending_artifact[0], vm.group(1), pending_artifact[1], pending_artifact[2]))
                        pending_artifact = None
        elif fn == 'build.gradle':
            for lineno, line in enumerate(lines, 1):
                m = re.search(r'[\'"]([\w.\-]+):([\w.\-]+):([\w.+\-]+)[\'"]', line)
                if m:
                    found.append((m.group(2), m.group(3), lineno, line.strip()))
        elif fn == 'go.mod':
            for lineno, line in enumerate(lines, 1):
                m = re.match(r'\s*[\w./\-]+\s+([\w./\-]+)\s+v([\w.\-]+)', line)
                if m:
                    found.append((m.group(1).rsplit('/', 1)[-1], m.group(2), lineno, line.strip()))
        elif fn == 'Cargo.toml':
            for lineno, line in enumerate(lines, 1):
                m = re.match(r'\s*([\w\-]+)\s*=\s*["\']?([\w.+\-]+)', line)
                if m and m.group(1) not in ('name', 'version', 'edition'):
                    found.append((m.group(1), m.group(2), lineno, line.strip()))
        elif fn == 'composer.json':
            for lineno, line in enumerate(lines, 1):
                m = re.search(r'"([\w/\-]+)"\s*:\s*"([^"]+)"', line)
                if m and m.group(1) not in ('description', 'name', 'license'):
                    found.append((m.group(1), m.group(2), lineno, line.strip()))
        return [(lib, ver, lineno, line) for (lib, ver, lineno, line) in found if lookup_library(lib)[1] is not None]
