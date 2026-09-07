"""Scan orchestration: run scanners, analyse, produce CBOM + SARIF + report.

The engine is the single code path. The CLI, the HTTP API and the console UI all
drive this same class, so what a reviewer sees in the browser is what a CI job
sees at the exit code.
"""
from __future__ import annotations

import re
import time
import uuid
from pathlib import Path
from typing import Callable

from .models import (ScanConfig, ScanResult, ScanSummary, Artifact, ArtifactType,
                     DiscoverySource, Evidence, utcnow_iso)
from .scanners import SourceScanner, CertificateScanner, KeyScanner, LibraryScanner
from .scanners2 import ContainerScanner, BinaryScanner, ConfigScanner
from .network import TLSEndpointScanner
from .risk import analyze
from .planner import build_plan, exposure_matrix, algorithm_rollup
from .cbom import write_cbom, write_report, write_sarif

# Cloud KMS, HSM and secret-store markers. (pattern, label, id, is_service)
SERVICE_PATTERNS = [
    (r'boto3|aioboto3|botocore', 'AWS KMS', 'aws-kms', True),
    (r'@aws-sdk/client-kms|aws-sdk.*KMS|AWSKMS', 'AWS KMS', 'aws-kms', True),
    (r'google\.cloud\.kms|google-cloud-kms|KeyManagementServiceClient',
     'Google Cloud KMS', 'google-cloud-kms', True),
    (r'azure\.keyvault|azure-keyvault|Azure\.Security\.KeyVault',
     'Azure Key Vault', 'azure-keyvault', True),
    (r'\bhvac\b|hashicorp/vault|vault\.api|VaultClient',
     'HashiCorp Vault', 'hashicorp-vault', True),
    (r'aws_kms_key|aws_kms_alias', 'AWS KMS (Terraform)', 'aws-kms', True),
    (r'pkcs11|PKCS11|libpkcs11|CK_MECHANISM', 'PKCS#11 HSM interface', 'pkcs11', False),
    (r'CloudHSM|cloudhsm', 'AWS CloudHSM', 'cloudhsm', False),
    (r'LunaHSM|luna_hsm|Chrystoki', 'Thales Luna HSM', 'luna-hsm', False),
    (r'nShield|nshield', 'Entrust nShield HSM', 'nshield', False),
    (r'YubiHSM|yubihsm', 'YubiHSM', 'yubihsm', False),
    (r'SoftHSM|softhsm', 'SoftHSM (software, test-only)', 'softhsm', False),
    (r'\bTPM2?_|tpm2_|/dev/tpm', 'TPM 2.0', 'tpm', False),
    (r'kSecClass|SecItemAdd|SecKeyCreateRandomKey', 'Apple Keychain', 'keychain', True),
]

SERVICE_SUFFIXES = {'.py', '.java', '.js', '.ts', '.tsx', '.jsx', '.go', '.cs', '.rb',
                    '.php', '.rs', '.c', '.cpp', '.h', '.yaml', '.yml', '.json',
                    '.toml', '.cfg', '.conf', '.tf', '.env', '.properties'}
SERVICE_SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', '__pycache__',
                     'dist', 'build', 'target'}


class ScanEngine:
    """Runs all scanners over configured targets with live event streaming."""

    def __init__(self, config: ScanConfig, results_dir: Path,
                 on_event: Callable[[dict], None] | None = None):
        self.config = config
        self.results_dir = results_dir
        self.on_event = on_event or (lambda e: None)
        self.artifacts: list[Artifact] = []
        self.seen_ids: set[str] = set()
        self.files_scanned = 0
        self.probes: list[dict] = []
        self._cancel = False

    def log(self, msg: str, level: str = 'info'):
        self.on_event({'type': 'log', 'level': level, 'message': msg, 'ts': utcnow_iso()})

    def _emit(self, a: Artifact):
        if a.id in self.seen_ids:
            return
        self.seen_ids.add(a.id)
        self.artifacts.append(a)
        self.on_event({'type': 'artifact', 'artifact': a.to_dict()})

    def _count_file(self):
        self.files_scanned += 1
        if self.files_scanned % 25 == 0:
            self.on_event({'type': 'progress', 'files_scanned': self.files_scanned,
                           'artifacts': len(self.artifacts)})

    def cancel(self):
        self._cancel = True

    def _detect_services(self, root: Path):
        """Cloud KMS / HSM / secret-store markers from any text file."""
        import os
        compiled = [(re.compile(p), label, sid, is_svc)
                    for p, label, sid, is_svc in SERVICE_PATTERNS]
        for dirpath, dirnames, filenames in os.walk(root):
            if self._cancel:
                return
            dirnames[:] = [d for d in dirnames if d not in SERVICE_SKIP_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                if p.suffix.lower() not in SERVICE_SUFFIXES:
                    continue
                try:
                    text = p.read_text(errors='ignore')
                except OSError:
                    continue
                for lineno, line in enumerate(text.splitlines(), 1):
                    for rx, label, sid, is_svc in compiled:
                        if rx.search(line):
                            self._emit(Artifact(
                                artifact_type=(ArtifactType.CLOUD_SERVICE.value if is_svc
                                               else ArtifactType.HARDWARE.value),
                                name=label,
                                category='service' if is_svc else 'hardware',
                                source=DiscoverySource.SOURCE_CODE.value,
                                evidence=Evidence(file_path=str(p), line=lineno,
                                                  snippet=line.strip()[:160]),
                                properties={'service_id': sid}))

    def _scanners_for(self, kind: str):
        if kind == 'container':
            return [ContainerScanner(self._emit, self._count_file)]
        if kind == 'binary':
            return [BinaryScanner(self._emit, self._count_file)]
        if kind == 'endpoint':
            return [TLSEndpointScanner(self._emit, self._count_file)]
        return [SourceScanner(self._emit, self._count_file),
                CertificateScanner(self._emit, self._count_file),
                KeyScanner(self._emit, self._count_file),
                LibraryScanner(self._emit, self._count_file),
                ConfigScanner(self._emit, self._count_file)]

    def run(self) -> ScanResult:
        scan_id = str(uuid.uuid4())
        summary = ScanSummary(scan_id=scan_id, started_at=utcnow_iso(),
                              targets=len(self.config.targets))
        result = ScanResult(scan_id=scan_id, config=self.config, summary=summary, events=[])
        self.log(f'Atlas scan {scan_id[:8]} starting — {len(self.config.targets)} target(s), '
                 f'CRQC horizon {self.config.crqc_year}')

        t0 = time.time()
        for target in self.config.targets:
            if self._cancel:
                self.log('scan cancelled', level='warn')
                break
            kind = target.get('kind', 'source')
            raw = target['path']

            if kind == 'endpoint':
                self.log(f'probing [endpoint] {raw}')
                for sc in self._scanners_for(kind):
                    probe = sc.scan(raw, kind)
                    if probe:
                        self.probes.append(probe)
                        if probe.get('reachable'):
                            neg = probe.get('negotiated') or {}
                            self.log(f'{raw}: {neg.get("version")} / '
                                     f'{neg.get("cipher_suite")}'
                                     + (f' — accepts {", ".join(probe["accepted_versions"])}'
                                        if probe.get('accepted_versions') else ''))
                        else:
                            self.log(f'{raw}: unreachable ({probe.get("error")})', level='warn')
                continue

            path = Path(raw)
            if not path.exists():
                self.log(f'target not found: {path}', level='warn')
                continue
            self.log(f'scanning [{kind}] {path}')
            before = len(self.artifacts)
            for sc in self._scanners_for(kind):
                if self._cancel:
                    break
                sc.scan(path, kind)
            if kind == 'source':
                self._detect_services(path)
            self.log(f'{path.name}: {len(self.artifacts) - before} artefacts')

        elapsed = time.time() - t0
        self.log(f'discovery complete — {len(self.artifacts)} artefacts from '
                 f'{self.files_scanned} files in {elapsed:.2f}s; running risk analysis')

        analyze(self.artifacts, crqc_year=self.config.crqc_year,
                default_lifetime=self.config.data_lifetime_default_years,
                default_migration_months=self.config.migration_months_default)

        # The engine owns the artifact list during discovery; hand it to the
        # result object before anything serialises it. Without this the CBOM and
        # the scan JSON both come out with zero components.
        result.artifacts = self.artifacts
        result.probes = self.probes

        by_sev: dict[str, int] = {}
        by_type: dict[str, int] = {}
        by_impact: dict[str, int] = {}
        vulnerable = mosca = 0
        for a in self.artifacts:
            by_sev[a.severity] = by_sev.get(a.severity, 0) + 1
            by_type[a.artifact_type] = by_type.get(a.artifact_type, 0) + 1
            by_impact[a.quantum_impact] = by_impact.get(a.quantum_impact, 0) + 1
            if a.quantum_impact in ('shor_broken', 'grover'):
                vulnerable += 1
            if a.mosca_violated:
                mosca += 1

        summary.by_severity = by_sev
        summary.by_type = by_type
        summary.by_impact = by_impact
        summary.artifacts_found = len(self.artifacts)
        summary.files_scanned = self.files_scanned
        summary.quantum_vulnerable_pct = round(
            100.0 * vulnerable / max(1, len(self.artifacts)), 1)
        summary.mosca_violations = mosca
        summary.duration_seconds = round(elapsed, 2)
        summary.finished_at = utcnow_iso()
        summary.status = 'cancelled' if self._cancel else 'complete'

        plan = build_plan(self.artifacts, self.config.crqc_year)
        result.plan = plan
        summary.migration_effort_days = plan['total_effort_days']

        d = self.results_dir
        cbom_path = write_cbom(result, d / f'{scan_id}.cbom.json')
        sarif_path = write_sarif(result, d / f'{scan_id}.sarif.json')
        report_path = write_report(result, d / f'{scan_id}.report.md')
        result.cbom_path = str(cbom_path)
        result.sarif_path = str(sarif_path)
        result.report_path = str(report_path)
        self.log(f'exports written — CBOM, SARIF and report for scan {scan_id[:8]}')
        result.save(d)

        self.on_event({'type': 'complete', 'scan_id': scan_id,
                       'summary': summary.__dict__, 'plan': plan,
                       'cbom': result.cbom_path, 'sarif': result.sarif_path,
                       'report': result.report_path})
        return result
