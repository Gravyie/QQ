#!/usr/bin/env python3
"""Quantum Atlas CLI.

    atlas scan <target>...            discover cryptographic artefacts
    atlas probe <host[:port]>...      handshake live endpoints
    atlas ci <target>... --fail-on    pipeline gate, non-zero exit on violation
    atlas simulate <scan-id>          re-run Mosca under new assumptions
    atlas plan <scan-id>              migration wave programme
    atlas kb [--resolve NAME...]      knowledge base
    atlas show <scan-id> | list       stored scans
    atlas export <scan-id> --format   cbom | sarif | report

The CLI is the ground truth for the backend: the HTTP API and the console UI
drive the same ScanEngine through the same code path, so a green pipeline and a
green dashboard mean the same thing.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas.engine import ScanEngine
from atlas.models import ScanConfig, ScanResult
from atlas import knowledge_base as kb
from atlas.planner import simulate as run_simulate, build_plan, algorithm_rollup
from atlas.network import probe_endpoint, probe_to_artifacts

RESULTS = Path(__file__).resolve().parent.parent / 'results'

B, D, R = '\033[1m', '\033[2m', '\033[0m'
RED, YEL, CYA, GRN, MAG = '\033[31m', '\033[33m', '\033[36m', '\033[32m', '\033[35m'
SEV_COLOR = {'critical': RED, 'high': YEL, 'medium': CYA, 'low': D, 'info': D}
SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']


# ---------------------------------------------------------------------------
def build_targets(specs: list[str], default_kind: str) -> list[dict]:
    targets = []
    for spec in specs:
        kind, path = default_kind, spec
        if ':' in spec:
            head, _, tail = spec.partition(':')
            if head in ('source', 'container', 'binary', 'endpoint'):
                kind, path = head, tail
        if kind == 'endpoint':
            targets.append({'path': path, 'kind': kind})
        else:
            targets.append({'path': str(Path(path).expanduser().resolve()), 'kind': kind})
    return targets


def run_scan(args, quiet: bool = False) -> ScanResult:
    config = ScanConfig(targets=build_targets(args.target, args.kind),
                        crqc_year=args.crqc, organization=args.org,
                        data_lifetime_default_years=args.lifetime,
                        migration_months_default=args.migration)

    def on_event(event: dict):
        if quiet:
            return
        if event['type'] == 'log':
            colour = YEL if event['level'] == 'warn' else D
            print(f'{colour}[{event["level"]}]{R} {event["message"]}', flush=True)
        elif event['type'] == 'artifact' and getattr(args, 'verbose', False):
            a = event['artifact']
            loc = Path(a['evidence']['file_path']).name
            if a['evidence'].get('line'):
                loc += f':{a["evidence"]["line"]}'
            print(f'  {D}+{R} {a["name"]:<26} {a["artifact_type"]:<16} {D}{loc}{R}', flush=True)

    return ScanEngine(config, RESULTS, on_event=on_event).run()


def cmd_scan(args) -> int:
    result = run_scan(args)
    print_summary(result)
    print_plan(result.plan or build_plan(result.artifacts, result.config.crqc_year))
    print(f'\n{D}scan   {R} {RESULTS / (result.scan_id + ".json")}')
    print(f'{D}cbom   {R} {result.cbom_path}')
    print(f'{D}sarif  {R} {result.sarif_path}')
    print(f'{D}report {R} {result.report_path}')
    return 0


def cmd_ci(args) -> int:
    """Pipeline gate. Exits non-zero when the estate breaches the policy."""
    result = run_scan(args, quiet=not args.verbose)
    s = result.summary
    counts = {sev: s.by_severity.get(sev, 0) for sev in SEV_ORDER}

    threshold_index = SEV_ORDER.index(args.fail_on) if args.fail_on != 'none' else None
    breaching = 0
    if threshold_index is not None:
        breaching = sum(counts[sev] for sev in SEV_ORDER[:threshold_index + 1])

    mosca_breach = args.max_mosca is not None and s.mosca_violations > args.max_mosca

    print(f'{B}atlas ci{R}  scan {result.scan_id[:8]}  '
          f'{s.artifacts_found} artefacts  {s.files_scanned} files  {s.duration_seconds}s')
    print(f'  severity   ' + '  '.join(
        f'{SEV_COLOR[sev]}{sev}={counts[sev]}{R}' for sev in SEV_ORDER if counts[sev]))
    print(f'  mosca      {s.mosca_violations} violation(s)'
          + (f' (limit {args.max_mosca})' if args.max_mosca is not None else ''))
    print(f'  exposure   {s.quantum_vulnerable_pct}% quantum-vulnerable')
    print(f'  sarif      {result.sarif_path}')

    if args.fail_on != 'none' and breaching:
        print(f'\n{RED}FAIL{R} {breaching} finding(s) at or above "{args.fail_on}"')
        for a in sorted(result.artifacts, key=lambda x: -x.risk_score)[:10]:
            if SEV_ORDER.index(a.severity) <= threshold_index:
                loc = a.evidence.file_path + (f':{a.evidence.line}' if a.evidence.line else '')
                print(f'  {SEV_COLOR[a.severity]}{a.severity:<9}{R} {a.name:<24} {D}{loc}{R}')
        return 1
    if mosca_breach:
        print(f'\n{RED}FAIL{R} {s.mosca_violations} Mosca violations exceed limit {args.max_mosca}')
        return 1
    print(f'\n{GRN}PASS{R} estate within policy')
    return 0


def cmd_probe(args) -> int:
    for spec in args.endpoint:
        host, _, port_s = spec.rpartition(':')
        if not host:
            host, port = spec, 443
        else:
            try:
                port = int(port_s)
            except ValueError:
                host, port = spec, 443
        print(f'{B}{host}:{port}{R}')
        probe = probe_endpoint(host, port, timeout=args.timeout)
        if not probe['reachable']:
            print(f'  {RED}unreachable{R} {probe["error"]}')
            continue
        neg = probe['negotiated']
        print(f'  negotiated   {neg["version"]}  {neg["cipher_suite"]}  '
              f'{neg.get("secret_bits")} bits'
              + (f'  group={neg["group"]}' if neg.get('group') else ''))
        if probe['accepted_versions']:
            print(f'  accepts      {", ".join(probe["accepted_versions"])}')
        if probe['rejected_versions']:
            print(f'  {D}rejects      {", ".join(probe["rejected_versions"])}{R}')
        if probe.get('default_group'):
            print(f'  kex group    {probe["default_group"]}')
        if probe.get('pqc_probe') == 'unavailable':
            print(f'  pqc group    {D}not tested (needs OpenSSL 3.5+ CLI){R}')
        elif probe['pqc_group']:
            print(f'  pqc group    {GRN}{probe["pqc_group"]}{R}  '
                  f'{D}quantum-resistant key agreement{R}')
        else:
            tested = ", ".join(probe.get('groups_tested', [])) or 'none'
            print(f'  pqc group    {YEL}declined{R}  {D}(offered {tested}){R}')
        cert = probe['certificate']
        if cert:
            print(f'  certificate  {cert["public_key_algorithm"]}'
                  f'{"-" + str(cert["key_size"]) if cert["key_size"] else ""}'
                  f'  sig={cert["signature_algorithm"]}'
                  f'  expires in {cert["days_remaining"]}d')
            print(f'  {D}subject      {cert["subject"]}{R}')
        artifacts = probe_to_artifacts(probe)
        print(f'  {D}-> {len(artifacts)} artefact(s) for the inventory{R}\n')
    return 0


def cmd_simulate(args) -> int:
    result = load_scan(args.scan_id)
    sim = run_simulate([a.to_dict() for a in result.artifacts],
                       crqc_year=args.crqc, data_lifetime_years=args.lifetime,
                       migration_months=args.migration, engineers=args.engineers)
    a, s = sim['assumptions'], sim['summary']
    print(f'{B}simulation{R} scan {args.scan_id[:8]}')
    print(f'  assumptions  CRQC {a["crqc_year"]} (Z={a["years_until_crqc"]}y), '
          f'lifetime {a["data_lifetime_years"]}y, migration {a["migration_months"]}mo')
    print(f'  artefacts    {s["artifacts"]}')
    print(f'  vulnerable   {s["quantum_vulnerable"]} ({s["quantum_vulnerable_pct"]}%)')
    print(f'  mosca        {s["mosca_violations"]} ({s["mosca_violation_pct"]}%)')
    if s['mean_hndl_exposure'] is not None:
        print(f'  mean HNDL    {s["mean_hndl_exposure"]}')
    print(f'  severity     ' + '  '.join(
        f'{SEV_COLOR[k]}{k}={v}{R}' for k, v in sorted(
            s['by_severity'].items(), key=lambda kv: SEV_ORDER.index(kv[0]))))
    print_plan(sim['plan'])
    return 0


def cmd_plan(args) -> int:
    result = load_scan(args.scan_id)
    # Rebuilt rather than read from the stored file so the CLI and the API can
    # never disagree about the programme.
    print_plan(build_plan(result.artifacts, args.crqc or result.config.crqc_year,
                          engineers=args.engineers), detailed=True)
    return 0


def cmd_algorithms(args) -> int:
    result = load_scan(args.scan_id)
    rows = algorithm_rollup(result.artifacts)
    print(f'{B}{"algorithm":<24}{"impact":<20}{"n":>4} {"files":>6} {"risk":>6}  '
          f'{"replacement":<22}{R}')
    for g in rows[:args.limit]:
        colour = RED if g['max_risk'] >= 8.5 else YEL if g['max_risk'] >= 6.5 else D
        print(f'{g["name"]:<24}{g["impact"]:<20}{g["count"]:>4} {g["file_count"]:>6} '
              f'{colour}{g["max_risk"]:>6.1f}{R}  {(g["target"] or "-"):<22}')
    return 0


def print_summary(result: ScanResult) -> None:
    s = result.summary
    print(f'\n{B}scan {result.scan_id}{R}   {D}{s.duration_seconds}s{R}')
    print(f'  artefacts        {s.artifacts_found}')
    print(f'  files scanned    {s.files_scanned}')
    print(f'  quantum-exposed  {s.quantum_vulnerable_pct}%')
    print(f'  mosca violations {s.mosca_violations}')
    print(f'  migration effort {s.migration_effort_days} engineer-days')
    print(f'\n  {B}severity{R}')
    for sev in SEV_ORDER:
        n = s.by_severity.get(sev, 0)
        if n:
            print(f'    {SEV_COLOR[sev]}{sev:<9}{R} {n}')
    print(f'\n  {B}quantum impact{R}')
    for impact, n in sorted(s.by_impact.items(), key=lambda kv: -kv[1]):
        print(f'    {impact:<20} {n}')
    print(f'\n  {B}artefact type{R}')
    for t, n in sorted(s.by_type.items(), key=lambda kv: -kv[1]):
        print(f'    {t:<18} {n}')

    top = sorted(result.artifacts, key=lambda a: -a.risk_score)[:12]
    print(f'\n  {B}highest risk{R}')
    for a in top:
        loc = Path(a.evidence.file_path).name
        if a.evidence.line:
            loc += f':{a.evidence.line}'
        col = SEV_COLOR.get(a.severity, '')
        target = (a.recommendation or {}).get('target') or '-'
        flag = f' {RED}MOSCA{R}' if a.mosca_violated else ''
        print(f'    {col}{a.risk_score:>4.1f}{R}  {a.name:<24} {D}{loc:<30}{R} -> {target}{flag}')


def print_plan(plan: dict, detailed: bool = False) -> None:
    if not plan or not plan.get('waves'):
        return
    sched = plan['schedule']
    print(f'\n  {B}migration programme{R}  {plan["total_effort_days"]} engineer-days, '
          f'{sched["total_months"]} months at '
          f'{sched.get("engineers", sched.get("engineers_assumed"))} engineers')
    verdict = (f'{GRN}finishes {sched.get("finish_label", sched["finish_year"])}, '
               f'{sched["slack_years"]}y before CRQC{R}'
               if sched['meets_deadline']
               else f'{RED}finishes {sched.get("finish_label", sched["finish_year"])}, '
                    f'MISSES the {sched["crqc_year"]} CRQC horizon{R}')
    print(f'  {verdict}')
    for w, row in zip(plan['waves'], sched['rows']):
        print(f'\n    {B}wave {w["wave"]}{R}  {w["title"]}')
        print(f'      {w["artifact_count"]} artefacts, {w["work_units"]} work units, '
              f'{w["effort_days"]}d  {D}months {row["start_month"]}-{row["end_month"]}{R}')
        if w['targets']:
            print(f'      {D}targets: {", ".join(w["targets"][:5])}{R}')
        if detailed:
            print(f'      {D}{w["rationale"]}{R}')
            for f in w['top_findings']:
                loc = Path(f['location']).name + (f':{f["line"]}' if f['line'] else '')
                print(f'        {SEV_COLOR.get(f["severity"], "")}{f["risk_score"]:>4.1f}{R} '
                      f'{f["name"]:<22} {D}{loc:<28}{R} -> {f["target"] or "-"}')


def load_scan(scan_id: str) -> ScanResult:
    path = RESULTS / f'{scan_id}.json'
    if not path.exists():
        matches = [p for p in RESULTS.glob(f'{scan_id}*.json')
                   if not p.name.endswith(('.cbom.json', '.sarif.json'))]
        if len(matches) == 1:
            path = matches[0]
        else:
            print(f'no such scan: {scan_id}', file=sys.stderr)
            sys.exit(1)
    return ScanResult.load(path)


def cmd_kb(args) -> int:
    stats = kb.stats()
    print(f'{B}knowledge base{R}')
    print(f'  algorithms {stats["algorithms"]}')
    print(f'  aliases    {stats["aliases"]}')
    print(f'\n  {B}by quantum impact{R}')
    for k, v in sorted(stats['by_impact'].items(), key=lambda kv: -kv[1]):
        print(f'    {k:<22} {v}')
    print(f'\n  {B}by primitive{R}')
    for k, v in sorted(stats['by_primitive'].items(), key=lambda kv: -kv[1]):
        print(f'    {k:<22} {v}')
    if args.resolve:
        print(f'\n  {B}resolution{R}')
        for raw in args.resolve:
            canon, entry = kb.canonical_algorithm(raw)
            impact = (entry or {}).get('impact', f'{RED}UNRECOGNISED{R}')
            mode = kb.extract_mode(raw)
            print(f'    {raw:<36} -> {canon:<22} {impact}'
                  + (f'  mode={mode}' if mode else ''))
    return 0


def cmd_show(args) -> int:
    result = load_scan(args.scan_id)
    print_summary(result)
    print_plan(result.plan or build_plan(result.artifacts, result.config.crqc_year))
    return 0


def cmd_list(args) -> int:
    scans = sorted((p for p in RESULTS.glob('*.json')
                    if not p.name.endswith(('.cbom.json', '.sarif.json'))),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    print(f'{B}{"scan":<38}{"started":<22}{"artefacts":>10}{"exposed":>9}{"mosca":>7}{R}')
    for p in scans[:args.limit]:
        try:
            data = json.loads(p.read_text())
        except json.JSONDecodeError:
            continue
        s = data['summary']
        print(f'{p.stem:<38}{s["started_at"]:<22}{s["artifacts_found"]:>10}'
              f'{s["quantum_vulnerable_pct"]:>8}%{s["mosca_violations"]:>7}')
    return 0


def cmd_export(args) -> int:
    suffix = {'cbom': '.cbom.json', 'sarif': '.sarif.json', 'report': '.report.md'}[args.format]
    path = RESULTS / f'{args.scan_id}{suffix}'
    if not path.exists():
        print(f'not found: {path}', file=sys.stderr)
        return 1
    if args.out:
        Path(args.out).write_text(path.read_text())
        print(f'written: {args.out}')
    else:
        print(path.read_text())
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog='atlas',
                                description='Quantum Atlas — Enterprise Cryptographic '
                                            'Discovery & Analysis Tool (ECDAT)')
    sub = ap.add_subparsers(dest='command', required=True)

    def add_scan_args(p):
        p.add_argument('target', nargs='+',
                       help='path, or kind:path where kind is source|container|binary|endpoint')
        p.add_argument('--kind', default='source',
                       choices=['source', 'container', 'binary', 'endpoint'])
        p.add_argument('--crqc', type=int, default=2033, help='assumed CRQC arrival year')
        p.add_argument('--org', default='Enterprise')
        p.add_argument('--lifetime', type=int, default=5,
                       help='default data shelf-life in years (X)')
        p.add_argument('--migration', type=int, default=18,
                       help='default migration time in months (Y)')
        p.add_argument('-v', '--verbose', action='store_true')

    sc = sub.add_parser('scan', help='discover cryptographic artefacts')
    add_scan_args(sc)
    sc.set_defaults(func=cmd_scan)

    ci = sub.add_parser('ci', help='pipeline gate: non-zero exit on policy breach')
    add_scan_args(ci)
    ci.add_argument('--fail-on', default='critical',
                    choices=['critical', 'high', 'medium', 'low', 'info', 'none'],
                    help='fail when any finding is at or above this severity')
    ci.add_argument('--max-mosca', type=int, default=None,
                    help='also fail when Mosca violations exceed this count')
    ci.set_defaults(func=cmd_ci)

    pr = sub.add_parser('probe', help='handshake live TLS endpoints')
    pr.add_argument('endpoint', nargs='+', help='host or host:port')
    pr.add_argument('--timeout', type=float, default=6.0)
    pr.set_defaults(func=cmd_probe)

    si = sub.add_parser('simulate', help='re-run Mosca under new assumptions')
    si.add_argument('scan_id')
    si.add_argument('--crqc', type=int, default=2033)
    si.add_argument('--lifetime', type=int, default=5)
    si.add_argument('--migration', type=int, default=18)
    si.add_argument('--engineers', type=int, default=4,
                    help='team size used for the schedule')
    si.set_defaults(func=cmd_simulate)

    pl = sub.add_parser('plan', help='migration wave programme')
    pl.add_argument('scan_id')
    pl.add_argument('--crqc', type=int, default=None,
                    help='override the CRQC year stored with the scan')
    pl.add_argument('--engineers', type=int, default=4)
    pl.set_defaults(func=cmd_plan)

    al = sub.add_parser('algorithms', help='per-algorithm rollup for a scan')
    al.add_argument('scan_id')
    al.add_argument('--limit', type=int, default=40)
    al.set_defaults(func=cmd_algorithms)

    kbp = sub.add_parser('kb', help='knowledge-base statistics and name resolution')
    kbp.add_argument('--resolve', nargs='*', default=[], metavar='NAME')
    kbp.set_defaults(func=cmd_kb)

    sh = sub.add_parser('show', help='reprint a stored scan')
    sh.add_argument('scan_id')
    sh.set_defaults(func=cmd_show)

    ls = sub.add_parser('list', help='list stored scans')
    ls.add_argument('--limit', type=int, default=20)
    ls.set_defaults(func=cmd_list)

    ex = sub.add_parser('export', help='print or write a stored export')
    ex.add_argument('scan_id')
    ex.add_argument('--format', required=True, choices=['cbom', 'sarif', 'report'])
    ex.add_argument('--out')
    ex.set_defaults(func=cmd_export)

    args = ap.parse_args()
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
