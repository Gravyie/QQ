"""Container image, binary, and configuration scanners."""
from __future__ import annotations

import os
import re
import tarfile
from pathlib import Path

from .models import Artifact, ArtifactType, DiscoverySource, Evidence
from .knowledge_base import canonical_algorithm
from .crypto_services import lookup_library
from .scanners import (SOURCE_PATTERNS, SOURCE_LANGUAGES, CONFIG_PATTERNS, CERT_EXTS,
                       KEY_MARKERS, MANIFEST_FILES, SKIP_DIRS, CertificateScanner, Scanner)

# Version strings embedded in compiled crypto libraries. One table, used by
# both the container scanner and the standalone binary scanner, so a library
# found inside an image and the same library on disk produce identical names.
BINARY_LIB_MARKERS = [
    (rb'OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)', 'openssl'),
    (rb'GnuTLS\s+(\d+\.\d+\.\d+)', 'gnutls'),
    (rb'mbed ?TLS\s+(\d+\.\d+\.\d+)', 'mbedtls'),
    (rb'wolfSSL\s+(\d+\.\d+\.\d+)', 'wolfssl'),
    (rb'BoringSSL', 'boringssl'),
    (rb'libgcrypt\s+(\d+\.\d+\.\d+)', 'libgcrypt'),
    (rb'libsodium\s+(\d+\.\d+\.\d+)', 'libsodium'),
    (rb'libsodium', 'libsodium'),
    (rb'NSS\s+(\d+\.\d+)', 'nss'),
    (rb'LibreSSL\s+(\d+\.\d+\.\d+)', 'libressl'),
    (rb'liboqs\s+(\d+\.\d+\.\d+)', 'liboqs'),
    (rb'Botan\s+(\d+\.\d+\.\d+)', 'botan'),
]

# Executable/shared-object magic numbers: ELF, PE, Mach-O (thin and fat).
BINARY_MAGIC = (b'\x7fELF', b'MZ', b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe',
                b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca')


class ContainerScanner(Scanner):
    """Scan a docker-save tarball layer by layer. No Docker daemon needed.

    Reading the tar directly rather than shelling out to `docker` means the
    scan works on a build agent, an air-gapped analyst workstation, or a
    machine with no container runtime at all — which is the realistic case
    for the estates this tool is aimed at.
    """

    TEXT_SUFFIXES = SOURCE_LANGUAGES | {'.sh', '.conf', '.cnf', '.cfg', '.yaml', '.yml',
                                        '.json', '.txt', '.env', '.service', '.properties',
                                        '.ini', '.tf'}
    CONFIG_BASENAMES = {'nginx.conf', 'sshd_config', 'ssh_config', 'openssl.cnf',
                        'httpd.conf', 'ssl.conf', 'apache2.conf', 'haproxy.cfg'}
    MAX_TEXT_BYTES = 512 * 1024
    MAX_BINARY_BYTES = 4 * 1024 * 1024

    def scan(self, root: Path, kind: str):
        tars = []
        if root.is_file() and (root.suffix == '.tar' or root.name.endswith('.tar.gz') or root.name.endswith('.tgz')):
            tars.append(root)
        elif root.is_dir():
            for dirpath, dirnames, filenames in os.walk(root):
                for fn in filenames:
                    if fn.endswith(('.tar', '.tar.gz', '.tgz')):
                        tars.append(Path(dirpath) / fn)
        for t in tars:
            self._scan_tarball(t)

    def _scan_tarball(self, tar_path: Path):
        self._count_file()
        try:
            tf = tarfile.open(tar_path, 'r:*')
        except (tarfile.TarError, OSError):
            return
        with tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                fobj = tf.extractfile(member)
                if fobj is None:
                    continue
                name = member.name
                base = Path(name).name
                suffix = Path(name).suffix.lower()
                try:
                    if suffix in CERT_EXTS or base in ('cert.pem', 'server.pem', 'ca.pem', 'fullchain.pem'):
                        data = fobj.read(262144)
                        self._scan_cert_blob(data, name, tar_path)
                    elif base in MANIFEST_FILES:
                        data = fobj.read(262144)
                        self._scan_manifest_text(data.decode(errors='ignore'), base, name, tar_path)
                    elif suffix in self.TEXT_SUFFIXES:
                        data = fobj.read(262144)
                        text = data.decode(errors='ignore')
                        self._scan_text_as_source(text, name, tar_path)
                        self._scan_config_text(text, name, tar_path)
                    else:
                        data = fobj.read(self.MAX_BINARY_BYTES)
                        if data.startswith(BINARY_MAGIC):
                            self._scan_binary_blob(data, name, tar_path)
                except (tarfile.TarError, OSError):
                    continue

    def _scan_cert_blob(self, data, member_name, tar_path):
        cert_scanner = CertificateScanner(self._emit, self._count_file)
        begin = b'-----BEGIN CERTIFICATE-----'
        end = b'-----END CERTIFICATE-----'
        idx = 0
        count = 0
        while count < 4:
            s = data.find(begin, idx)
            if s < 0:
                break
            e = data.find(end, s)
            if e < 0:
                break
            import base64
            try:
                der = base64.b64decode(re.sub(rb'\s+', b'', data[s + len(begin):e]))
                cert = cert_scanner._parse_der(der)
                if cert:
                    cert_scanner.emit_parsed_cert(
                        cert[0],
                        Evidence(file_path=str(tar_path), container_layer=member_name))
                    count += 1
            except Exception:
                pass
            idx = e + len(end)

    def _scan_text_as_source(self, text, member_name, tar_path):
        lang = Path(member_name).suffix.lstrip('.')
        for lineno, line in enumerate(text.splitlines(), 1):
            for pat, algo, family_hint in SOURCE_PATTERNS:
                try:
                    hit = re.search(pat, line)
                except re.error:
                    hit = pat in line
                if hit:
                    name = algo or family_hint or 'crypto-api'
                    canon, entry = canonical_algorithm(name)
                    a = Artifact(
                        artifact_type=ArtifactType.ALGORITHM_USE.value,
                        name=name, category=(entry or {}).get('family', 'unknown'),
                        source=DiscoverySource.CONTAINER_IMAGE.value,
                        evidence=Evidence(file_path=str(tar_path), line=lineno,
                                          snippet=line.strip()[:160], container_layer=member_name),
                        properties={'language': lang})
                    self._emit(a)

    def _scan_config_text(self, text, member_name, tar_path):
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped[0] in '#;':
                continue
            for pattern, kind_tag in CONFIG_PATTERNS:
                m = re.search(pattern, line, re.MULTILINE)
                if m:
                    self.emit_config_finding(
                        kind_tag, m.group(1)[:400],
                        Evidence(file_path=str(tar_path), line=lineno,
                                 snippet=stripped[:160], container_layer=member_name),
                        source=DiscoverySource.CONTAINER_IMAGE.value)

    def _scan_manifest_text(self, text, manifest_name, member_name, tar_path):
        for lineno, line in enumerate(text.splitlines(), 1):
            m = re.match(r'^\s*([A-Za-z0-9_.\-]+)\s*[=<>!~]+\s*([0-9][^,;\s#]*)', line)
            if m and lookup_library(m.group(1))[1]:
                a = Artifact(
                    artifact_type=ArtifactType.LIBRARY.value,
                    name=m.group(1), category='library',
                    source=DiscoverySource.CONTAINER_IMAGE.value,
                    evidence=Evidence(file_path=str(tar_path), line=lineno,
                                      snippet=line.strip()[:160], container_layer=member_name),
                    properties={'version': m.group(2), 'manifest': manifest_name})
                self._emit(a)

    def _scan_binary_blob(self, data, member_name, tar_path):
        for pattern, libname in BINARY_LIB_MARKERS:
            m = re.search(pattern, data)
            if m:
                ver = m.group(1).decode() if m.groups() else None
                _, entry = lookup_library(libname)
                props = {'version': ver}
                if entry:
                    props['pqc'] = entry.get('pqc', False)
                    props['pqc_note'] = entry.get('pqc_note')
                a = Artifact(
                    artifact_type=ArtifactType.BINARY.value,
                    name=libname, category='library-binary',
                    source=DiscoverySource.CONTAINER_IMAGE.value,
                    evidence=Evidence(file_path=str(tar_path), container_layer=member_name,
                                      binary_section='string table',
                                      snippet=f'{libname} {ver or ""}'.strip()),
                    properties=props)
                self._emit(a)


class BinaryScanner(Scanner):
    """Scan compiled binaries on disk for embedded crypto library strings."""

    def scan(self, root: Path, kind: str):
        paths = [root] if root.is_file() else []
        if root.is_dir():
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                paths.extend(Path(dirpath) / fn for fn in filenames)

        for p in paths:
            if p.suffix.lower() in SOURCE_LANGUAGES or p.suffix.lower() in CERT_EXTS:
                continue
            try:
                data = p.read_bytes()[:8_000_000]
            except OSError:
                continue
            if len(data) < 64 or not data.startswith(BINARY_MAGIC):
                continue
            self._count_file()
            for pattern, libname in BINARY_LIB_MARKERS:
                m = re.search(pattern, data)
                if m:
                    ver = m.group(1).decode(errors='ignore') if m.groups() else None
                    _, entry = lookup_library(libname)
                    props = {'version': ver}
                    if entry:
                        props['pqc'] = entry.get('pqc', False)
                        props['pqc_note'] = entry.get('pqc_note')
                    a = Artifact(
                        artifact_type=ArtifactType.BINARY.value,
                        name=libname, category='library-binary',
                        source=DiscoverySource.BINARY.value,
                        evidence=Evidence(file_path=str(p), binary_section='string table',
                                          snippet=f'{libname} {ver or ""}'.strip()),
                        properties=props)
                    self._emit(a)


class ConfigScanner(Scanner):
    """Scan server, service, and infrastructure-as-code configuration.

    Covers nginx/Apache/sshd/openssl.cnf plus Terraform and Kubernetes
    manifests, because in a real estate the TLS floor is just as often set in
    IaC (a load-balancer policy, a KMS key spec) as in a server config.
    """

    CONFIG_NAMES = {
        'nginx.conf', 'sshd_config', 'ssh_config', 'openssl.cnf', 'openssl.conf',
        'httpd.conf', 'ssl.conf', 'apache2.conf', 'my.cnf', 'postgresql.conf',
        'redis.conf', 'haproxy.cfg', 'stunnel.conf',
    }
    CONFIG_SUFFIXES = {'.conf', '.cnf', '.cfg', '.tf', '.tfvars', '.ini', '.properties'}
    # YAML/JSON are only read when the name suggests infrastructure, to avoid
    # walking every fixture file in a large repository.
    MANIFEST_HINTS = ('ingress', 'service', 'deployment', 'values', 'chart',
                      'k8s', 'kube', 'helm', 'istio', 'gateway')

    def _is_candidate(self, path: Path) -> bool:
        name = path.name.lower()
        if name in self.CONFIG_NAMES:
            return True
        if path.suffix.lower() in self.CONFIG_SUFFIXES:
            return True
        if path.suffix.lower() in ('.yaml', '.yml'):
            return any(hint in name for hint in self.MANIFEST_HINTS)
        return False

    def scan(self, root: Path, kind: str):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                if not self._is_candidate(p):
                    continue
                self._count_file()
                try:
                    text = p.read_text(errors='ignore')
                except OSError:
                    continue
                self._scan_config_text(text, p)

    def _scan_config_text(self, text: str, path: Path):
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            # Skip comments so a commented-out weak cipher is not a finding.
            if not stripped or stripped[0] in '#;':
                continue
            for pattern, kind_tag in CONFIG_PATTERNS:
                m = re.search(pattern, line, re.MULTILINE)
                if m:
                    self.emit_config_finding(
                        kind_tag, m.group(1)[:400],
                        Evidence(file_path=str(path), line=lineno,
                                 snippet=stripped[:160]))
