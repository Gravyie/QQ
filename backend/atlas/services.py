"""Per-service rollup: which application in the estate is worst.

Severity ranking answers "what is the worst finding". A programme manager needs
the other cut: "which team owns the most of this, and what does their slice cost
me". The problem statement is explicitly about cataloguing across applications,
products and infrastructure, so attribution is part of the deliverable rather
than a nicety.

Attribution rules, in order:

  tls-endpoint       the host, taken from `properties['endpoint']` (network.py
                     records evidence as `tls://host:port`, so the host is
                     available without parsing a path).
  container-image    the image tarball's basename, minus its extension.
  binary             the binary's own filename — a compiled artefact is its own
                     deployable unit and rarely shares a directory with source.
  filesystem         the first path segment beneath the scanned target root.
                     Infrastructure directories are kept at two levels
                     (`infra/pki`, `infra/openssl`) because "infra" on its own
                     would collapse the PKI, the TLS config and the bastion into
                     one row and hide exactly the distinction an operator needs.
  anything else      'unattributed', which is emitted as a row rather than
                     dropped. A silently discarded artefact is worse than an
                     ugly bucket name.

Effort is deduplicated the same way `planner.build_plan` does it — by
(file, replacement target) — because migrating one call site fixes every finding
on that line. `planner.work_unit_effort` is the shared implementation, so the
per-service numbers and the wave numbers cannot drift apart.
"""
from __future__ import annotations

import os
import posixpath
from collections import defaultdict

from .models import Artifact
from .planner import work_unit_effort

SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

CRITICALITY_ORDER = ['critical', 'high', 'medium', 'low']
CRITICALITY_RANK = {c: i for i, c in enumerate(CRITICALITY_ORDER)}

# Directories that are meaningful only one level deeper. Keeping these at two
# segments is a judgement call, documented in the module docstring.
_TWO_LEVEL_DIRS = {'infra', 'infrastructure', 'deploy', 'deployment', 'ops',
                   'config', 'configs', 'etc', 'charts', 'k8s', 'terraform'}

_EXT_LANGUAGE = {
    '.py': 'python', '.java': 'java', '.cs': 'c#', '.go': 'go',
    '.ts': 'typescript', '.tsx': 'typescript', '.js': 'javascript',
    '.mjs': 'javascript', '.rs': 'rust', '.c': 'c', '.h': 'c',
    '.cc': 'c++', '.cpp': 'c++', '.hpp': 'c++', '.rb': 'ruby',
    '.php': 'php', '.kt': 'kotlin', '.swift': 'swift', '.scala': 'scala',
    '.sh': 'shell', '.bash': 'shell', '.pl': 'perl', '.ex': 'elixir',
    '.erl': 'erlang', '.dart': 'dart', '.m': 'objective-c',
    '.tf': 'terraform', '.yaml': 'yaml', '.yml': 'yaml', '.toml': 'toml',
    '.json': 'json', '.xml': 'xml', '.cnf': 'config', '.conf': 'config',
    '.pem': 'pki', '.crt': 'pki', '.cer': 'pki', '.key': 'pki',
    '.p12': 'pki', '.pfx': 'pki', '.jks': 'pki',
}

# Artifact types that identify their own kind regardless of where they sit.
_KIND_BY_TYPE = {
    'tls-endpoint': 'endpoint',
    'container-image': 'container',
    'binary': 'binary',
    'cloud-service': 'cloud',
    'hardware': 'hardware',
}


def _target_roots(targets: list[dict] | None) -> list[str]:
    """Scanned filesystem roots, longest first so the most specific one wins."""
    roots: list[str] = []
    for t in targets or []:
        path = t.get('path') if isinstance(t, dict) else str(t)
        if not path:
            continue
        # Kind-prefixed targets ("container:image.tar") are not filesystem roots.
        if ':' in path and not os.path.isabs(path.split(':', 1)[1] or ''):
            head, _, tail = path.partition(':')
            if head in ('container', 'binary', 'image', 'source'):
                path = tail or path
        roots.append(path.rstrip('/'))
    return sorted({r for r in roots if r}, key=len, reverse=True)


def _service_from_path(file_path: str, roots: list[str]) -> str:
    """First meaningful segment beneath whichever scanned root contains this file."""
    norm = file_path.replace('\\', '/')
    for root in roots:
        rn = root.replace('\\', '/')
        if norm == rn:
            return posixpath.basename(rn) or 'unattributed'
        if norm.startswith(rn + '/'):
            rel = norm[len(rn) + 1:]
            parts = [p for p in rel.split('/') if p]
            if not parts:
                return posixpath.basename(rn) or 'unattributed'
            if len(parts) == 1:
                # A file sitting directly in the target root belongs to the root.
                return posixpath.basename(rn) or 'unattributed'
            first = parts[0]
            if first.lower() in _TWO_LEVEL_DIRS and len(parts) > 2:
                return f'{first}/{parts[1]}'
            return first
    return ''


def _endpoint_service(a: Artifact) -> str:
    props = a.properties or {}
    endpoint = props.get('endpoint')
    if isinstance(endpoint, str) and endpoint:
        return endpoint.split(':')[0]
    path = (a.evidence.file_path or '')
    if path.startswith('tls://'):
        return path[len('tls://'):].split(':')[0]
    return 'unattributed'


def _image_service(a: Artifact) -> str:
    base = posixpath.basename((a.evidence.file_path or '').replace('\\', '/'))
    for ext in ('.tar.gz', '.tgz', '.tar'):
        if base.endswith(ext):
            return base[: -len(ext)]
    return base or 'unattributed'


def attribute(a: Artifact, roots: list[str]) -> tuple[str, str]:
    """(service, kind) for one artifact."""
    if a.artifact_type == 'tls-endpoint':
        return _endpoint_service(a), 'endpoint'
    if a.artifact_type == 'container-image':
        return _image_service(a), 'container'
    if a.artifact_type == 'binary':
        base = posixpath.basename((a.evidence.file_path or '').replace('\\', '/'))
        return (base or 'unattributed'), 'binary'
    if a.artifact_type in ('cloud-service', 'hardware'):
        # These have no filesystem home of their own; keep them grouped by kind
        # so they do not masquerade as an application.
        label = 'cloud services' if a.artifact_type == 'cloud-service' else 'hardware modules'
        return label, _KIND_BY_TYPE[a.artifact_type]

    svc = _service_from_path(a.evidence.file_path or '', roots)
    if not svc:
        return 'unattributed', 'unknown'
    if svc.split('/')[0].lower() in _TWO_LEVEL_DIRS:
        return svc, 'infrastructure'
    return svc, 'source'


def service_rollup(artifacts: list[Artifact],
                   targets: list[dict] | None = None) -> list[dict]:
    """Group an inventory by owning service, worst first."""
    roots = _target_roots(targets)
    if not roots:
        # No target list supplied (a stored scan opened directly, a probe-only
        # run). Derive roots from the artifacts by finding the deepest common
        # ancestor of every filesystem path, so attribution still produces one
        # segment per service instead of one row per absolute path.
        paths = [(a.evidence.file_path or '').replace('\\', '/')
                 for a in artifacts
                 if a.artifact_type not in ('tls-endpoint', 'cloud-service', 'hardware')
                 and (a.evidence.file_path or '').startswith('/')]
        if paths:
            common = posixpath.dirname(posixpath.commonprefix(paths))
            if common and common != '/':
                roots = [common]

    groups: dict[str, dict] = {}
    for a in artifacts:
        svc, kind = attribute(a, roots)
        g = groups.get(svc)
        if g is None:
            g = groups[svc] = {
                'service': svc,
                'kind': kind,
                'artifacts': 0,
                'files': set(),
                'by_severity': defaultdict(int),
                'by_impact': defaultdict(int),
                'max_risk': 0.0,
                'risk_sum': 0.0,
                'mosca_violations': 0,
                'criticality': 'low',
                'algorithms': defaultdict(lambda: {'count': 0, 'impact': 'unknown'}),
                'pqc_present': False,
                'languages': set(),
                'worst_finding': None,
                '_items': [],
            }
        # A service that mixes source and infrastructure is source-owned; the
        # more specific kind wins only when it is the only kind seen.
        if g['kind'] != kind and kind == 'source':
            g['kind'] = 'source'

        g['artifacts'] += 1
        g['files'].add(a.evidence.file_path)
        g['by_severity'][a.severity] += 1
        g['by_impact'][a.quantum_impact] += 1
        g['max_risk'] = max(g['max_risk'], a.risk_score)
        g['risk_sum'] += a.risk_score
        if a.mosca_violated:
            g['mosca_violations'] += 1
        if CRITICALITY_RANK.get(a.business_criticality, 9) < CRITICALITY_RANK.get(g['criticality'], 9):
            g['criticality'] = a.business_criticality
        entry = g['algorithms'][a.name]
        entry['count'] += 1
        entry['impact'] = a.quantum_impact
        if a.quantum_impact == 'pq_safe':
            g['pqc_present'] = True
        ext = os.path.splitext(a.evidence.file_path or '')[1].lower()
        if ext in _EXT_LANGUAGE:
            g['languages'].add(_EXT_LANGUAGE[ext])
        g['_items'].append(a)

        cur = g['worst_finding']
        if cur is None or (a.risk_score, -SEVERITY_RANK.get(a.severity, 9)) > cur[0]:
            g['worst_finding'] = ((a.risk_score, -SEVERITY_RANK.get(a.severity, 9)), a)

    rows: list[dict] = []
    for g in groups.values():
        items = g.pop('_items')
        effort_days, work_units = work_unit_effort(items)
        worst = g.pop('worst_finding')
        worst_a = worst[1] if worst else None
        present = [s for s in SEVERITY_ORDER if g['by_severity'].get(s)]
        rows.append({
            'service': g['service'],
            'kind': g['kind'],
            'artifacts': g['artifacts'],
            'files': len(g['files']),
            'by_severity': {s: g['by_severity'][s] for s in SEVERITY_ORDER
                            if g['by_severity'].get(s)},
            'by_impact': dict(sorted(g['by_impact'].items(), key=lambda kv: -kv[1])),
            'worst_severity': present[0] if present else 'info',
            'max_risk': round(g['max_risk'], 1),
            'mean_risk': round(g['risk_sum'] / g['artifacts'], 2) if g['artifacts'] else 0.0,
            'mosca_violations': g['mosca_violations'],
            'effort_days': effort_days,
            'work_units': work_units,
            'business_criticality': g['criticality'],
            'top_algorithms': [
                {'name': n, 'count': v['count'], 'impact': v['impact']}
                for n, v in sorted(g['algorithms'].items(),
                                   key=lambda kv: -kv[1]['count'])[:5]
            ],
            'pqc_present': g['pqc_present'],
            'languages': sorted(g['languages']),
            'worst_finding': None if worst_a is None else {
                'id': worst_a.id,
                'name': worst_a.name,
                'severity': worst_a.severity,
                'risk_score': worst_a.risk_score,
                'location': worst_a.evidence.file_path,
                'line': worst_a.evidence.line,
                'target': (worst_a.recommendation or {}).get('target'),
            },
        })

    rows.sort(key=lambda r: (-r['max_risk'], -r['artifacts'], r['service']))
    for i, r in enumerate(rows, start=1):
        r['risk_rank'] = i
    return rows
