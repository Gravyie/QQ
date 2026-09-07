"""ECDAT core data models."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class QuantumImpact(str, Enum):
    SHOR_BROKEN = "shor_broken"        # broken by Shor's algorithm (factoring/discrete log)
    GROVER_WEAKENED = "grover"         # key-size halved by Grover (symmetric/hash)
    PQ_SAFE = "pq_safe"                # post-quantum algorithm
    CLASSICAL_OK = "classical_ok"      # symmetric/hash with adequate parameters
    BROKEN_CLASSICALLY = "broken_classically"   # already exploitable, no quantum needed
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ArtifactType(str, Enum):
    ALGORITHM_USE = "algorithm-use"      # crypto API call in source
    CERTIFICATE = "certificate"
    KEY = "key"
    PROTOCOL = "protocol"
    LIBRARY = "library"
    HARDWARE = "hardware"
    CLOUD_SERVICE = "cloud-service"
    CONTAINER_IMAGE = "container-image"
    BINARY = "binary"
    CONFIGURATION = "configuration"
    TLS_ENDPOINT = "tls-endpoint"        # observed on a live network handshake


class DiscoverySource(str, Enum):
    SOURCE_CODE = "source-code"
    CERTIFICATE = "certificate"
    KEY_STORE = "key-store"
    LIBRARY_MANIFEST = "library-manifest"
    CONTAINER_IMAGE = "container-image"
    BINARY = "binary"
    CONFIGURATION = "configuration"
    NETWORK = "network-probe"


@dataclass
class Evidence:
    """Where exactly the artifact was found."""
    file_path: str
    line: Optional[int] = None
    snippet: Optional[str] = None
    container_layer: Optional[str] = None
    binary_section: Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Artifact:
    """A discovered cryptographic artifact."""
    artifact_type: str            # ArtifactType value
    name: str                     # e.g. "RSA", "AES-256-CBC", "openssl", "AWS KMS"
    category: str                 # e.g. "asymmetric-encryption", "symmetric-cipher", "library", "service"
    source: str                   # DiscoverySource value
    evidence: Evidence
    properties: dict = field(default_factory=dict)
    # risk fields (filled by risk engine)
    quantum_impact: str = QuantumImpact.UNKNOWN.value
    quantum_year: Optional[int] = None       # estimated year it falls to quantum attack
    severity: str = Severity.INFO.value
    risk_score: float = 0.0
    mosca_violated: Optional[bool] = None
    mosca_margin_years: Optional[float] = None   # negative = already past the deadline
    migration_months: Optional[int] = None       # Y in Mosca's inequality
    hndl_exposure: Optional[float] = None
    recommendation: Optional[dict] = None
    business_criticality: str = "medium"     # low/medium/high/critical
    lifetime_years: Optional[int] = None
    id: str = ""

    def __post_init__(self):
        if not self.id:
            basis = f"{self.artifact_type}|{self.name}|{self.evidence.file_path}|{self.evidence.line or ''}"
            self.id = "ecdat-" + hashlib.sha1(basis.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = self.evidence.to_dict()
        return d


@dataclass
class ScanConfig:
    targets: list = field(default_factory=list)          # list of {path, kind}
    crqc_year: int = 2033                                # user-adjustable CRQC horizon
    organization: str = "Enterprise"
    data_lifetime_default_years: int = 5
    migration_months_default: int = 18


@dataclass
class ScanSummary:
    scan_id: str
    started_at: str
    finished_at: Optional[str] = None
    targets: int = 0
    files_scanned: int = 0
    artifacts_found: int = 0
    by_severity: dict = field(default_factory=dict)
    by_type: dict = field(default_factory=dict)
    by_impact: dict = field(default_factory=dict)
    quantum_vulnerable_pct: float = 0.0
    mosca_violations: int = 0
    migration_effort_days: int = 0
    duration_seconds: float = 0.0
    status: str = "running"          # running | complete | cancelled | failed


@dataclass
class ScanResult:
    scan_id: str
    config: ScanConfig
    summary: ScanSummary
    artifacts: list = field(default_factory=list)
    events: list = field(default_factory=list)   # scan log lines
    probes: list = field(default_factory=list)   # raw TLS probe results
    plan: dict = field(default_factory=dict)     # migration wave plan
    cbom_path: Optional[str] = None
    sarif_path: Optional[str] = None
    report_path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "config": asdict(self.config),
            "summary": asdict(self.summary),
            "artifacts": [a.to_dict() for a in self.artifacts],
            "events": self.events,
            "probes": self.probes,
            "plan": self.plan,
            "cbom_path": self.cbom_path,
            "sarif_path": self.sarif_path,
            "report_path": self.report_path,
        }

    def save(self, results_dir: Path) -> Path:
        results_dir.mkdir(parents=True, exist_ok=True)
        out = results_dir / f"{self.scan_id}.json"
        out.write_text(json.dumps(self.to_dict(), indent=2))
        return out

    @staticmethod
    def load(path: Path) -> "ScanResult":
        data = json.loads(path.read_text())
        cfg = ScanConfig(**data["config"])
        summ = ScanSummary(**data["summary"])
        res = ScanResult(scan_id=data["scan_id"], config=cfg, summary=summ,
                         events=data.get("events", []),
                         probes=data.get("probes", []),
                         plan=data.get("plan", {}),
                         cbom_path=data.get("cbom_path"),
                         sarif_path=data.get("sarif_path"),
                         report_path=data.get("report_path"))
        from .risk import hydrate_artifact
        res.artifacts = [hydrate_artifact(a) for a in data.get("artifacts", [])]
        return res
