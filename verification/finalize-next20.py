"""Bind merged next20 source to its own gate, fuzz and Linux race evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next20'
OUT = STAGE / 'verification/r9-next20'
DIRS = ('adapter', 'classification', 'cmd', 'gateway', 'internal',
        'obfuscation', 'protocol', 'scheduler', 'security', 'session', 'tests')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def manifest(stage):
    paths = [stage / 'go.mod', stage / 'go.sum']
    for name in DIRS:
        paths.extend((stage / name).rglob('*.go'))
    return [{'path': p.relative_to(stage).as_posix(),
             'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(paths)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--race-result', required=True)
    parser.add_argument('--local-attempt', choices=('01', '02'), default='02')
    args = parser.parse_args()
    gate_dir = OUT / ('local-gate-attempt' + args.local_attempt)
    fuzz_dir = OUT / ('fuzz-attempt' + args.local_attempt)
    frozen = read(gate_dir / 'source-manifest.json')
    local = read(gate_dir / 'local-summary.json')
    fuzz = read(fuzz_dir / 'summary.json')
    race = read(args.race_result)
    merge = read(STAGE / 'verification/merge/three-way-merge.json')
    resolution = read(STAGE / 'verification/merge/resolution.json')
    factory_fix = read(STAGE / 'verification/merge/factory-fix-integration.json')
    linux = next(b for b in local['binaries'] if b['platform'] == 'linux')
    gates = {
        'current_source_matches_frozen': manifest(STAGE) == frozen['source_manifest'],
        'local_checks_pass': local.get('local_checks_pass') is True,
        'fuzz_pass': fuzz.get('pass') is True and fuzz.get('source_unchanged') is True,
        'fuzz_manifest_matches': fuzz['source_manifest_sha256'] == frozen['manifest_sha256'],
        'race_strict_pass': race.get('pass') is True,
        'race_source_matches': [{'path': r['path'], 'sha256': r['sha256']}
                                for r in race['source_manifest']] == frozen['source_manifest'],
        'race_related_binary_matches': race['related_binary_sha256'] == linux['sha256'],
        'binary_unchanged': all(hashlib.sha256((ROOT / b['path']).read_bytes()).hexdigest() == b['sha256']
                                for b in local['binaries']),
        'merge_conflicts_resolved': resolution.get('conflicts_resolved') is True,
        'factory_fix_matches_frozen': factory_fix['incoming_manifest'] == frozen['source_manifest'],
        'factory_fix_source_unchanged': manifest(ROOT / '.staging/r9-next20-factoryfix') == factory_fix['incoming_manifest'],
        'first_gate_source_preserved': manifest(OUT / 'local-gate-attempt01/source') == read(OUT / 'local-gate-attempt01/source-manifest.json')['source_manifest'],
    }
    for key, directory in (('next19', 'r9-next19'), ('client', 'r9-next20-client'),
                           ('carrier', 'r9-next20-carrier')):
        gates[key + '_source_unchanged'] = manifest(ROOT / '.staging' / directory) == merge['source_before'][key]
    prior = ROOT / '.staging/r9-next19/verification/r9-next19/evidence-index.json'
    prior_report = read(prior)
    prior_wan = Path(prior_report['wan']['result_path'])
    prior_binding = read(prior_wan.parent / 'next19-experiment-binding.json')
    gates['next19_wan_unchanged'] = hashlib.sha256(prior_wan.read_bytes()).hexdigest() == prior_binding['raw_result_sha256']
    report = {
        'revision': 'v0.1-r9-next20', 'source_manifest_sha256': frozen['manifest_sha256'],
        'source_file_count': frozen['file_count'], 'gates': gates,
        'source_bound_local_fuzz_and_race_pass': all(gates.values()),
        'local_packages_passed': local['checks']['go_test']['packages_passed'],
        'local_top_level_tests_passed': local['checks']['go_test']['top_level_tests_passed'],
        'binaries': local['binaries'],
        'local_gate': str(gate_dir / 'local-summary.json'),
        'bounded_parser_fuzz': str(fuzz_dir / 'summary.json'),
        'independent_linux_race': {'run_id': race['run_id'], 'strict_pass': race['pass'],
                                   'result_path': str(Path(args.race_result).resolve())},
        'merge': str(STAGE / 'verification/merge/three-way-merge.json'),
        'merge_resolution': str(STAGE / 'verification/merge/resolution.json'),
        'factory_fix_integration': str(STAGE / 'verification/merge/factory-fix-integration.json'),
        'prior_next19_wan': {'status': 'strict_fail_preserved', 'path': str(prior_wan)},
        'wan': {'status': 'not_run', 'singapore_uploads_in_this_revision': 0,
                'scope': 'no prior WAN evidence reused for this merged source'},
        'four_categories': {'core_implemented': 2, 'partially_implemented': 2, 'finally_accepted': 0},
        'acceptance_complete': False, 'production_ready': False, 'released': False,
        'pending': ['client DNS interception and correct Session owner/TTL handoff',
                    'UDP authenticated administrative shutdown notification',
                    'pause old UDP business on suspect and track uncommitted datagram lifecycle',
                    'native Mihomo/sing-box registry and actual builds with TUN/DNS/IPv6 tests',
                    'mixed-class/FEC WAN performance and long resource stability',
                    'independent security review and cross-implementation interoperability'],
    }
    with (OUT / 'evidence-index.json').open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'path': str(OUT / 'evidence-index.json'),
                      'source_bound_checks_pass': all(gates.values()), 'acceptance_complete': False}))
    return 0 if all(gates.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
