"""Bind final next21 local/race evidence without erasing prior strict failures."""
from pathlib import Path
import argparse
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next21'
OUT = STAGE / 'verification/r9-next21'
DIRS = ('adapter', 'classification', 'cmd', 'gateway', 'internal',
        'obfuscation', 'protocol', 'scheduler', 'security', 'session', 'tests')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def manifest(stage):
    paths = [stage / 'go.mod', stage / 'go.sum']
    for directory in DIRS:
        paths.extend((stage / directory).rglob('*.go'))
    return [{'path': p.relative_to(stage).as_posix(),
             'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(paths)]


def row_map(rows):
    return {r['path']: r['sha256'] for r in rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--race-result', required=True)
    args = parser.parse_args()
    frozen = read(OUT / 'local-gate-attempt01/source-manifest.json')
    local = read(OUT / 'local-gate-attempt01/local-summary.json')
    fuzz = read(OUT / 'fuzz-attempt01/summary.json')
    race = read(args.race_result)
    merge = read(STAGE / 'verification/merge/three-way-merge.json')
    linux = next(b for b in local['binaries'] if b['platform'] == 'linux')
    gates = {
        'source_unchanged': manifest(STAGE) == frozen['source_manifest'],
        'local_checks_pass': local.get('local_checks_pass') is True,
        'fuzz_pass': fuzz.get('pass') is True and fuzz.get('source_unchanged') is True,
        'fuzz_manifest_matches': fuzz['source_manifest_sha256'] == frozen['manifest_sha256'],
        'race_strict_pass': race.get('pass') is True,
        'race_source_matches': row_map(race['source_manifest']) == row_map(frozen['source_manifest']),
        'race_binary_matches': race['related_binary_sha256'] == linux['sha256'],
        'binaries_unchanged': all(hashlib.sha256((ROOT / b['path']).read_bytes()).hexdigest() == b['sha256'] for b in local['binaries']),
        'initial_merge_no_conflicts': not merge['conflicts'],
    }
    for key, branch in (('next20', 'r9-next20'), ('datagram', 'r9-next21-datagram'), ('dns', 'r9-next21-dns')):
        gates[key + '_unchanged'] = row_map(manifest(ROOT / '.staging' / branch)) == row_map(merge['source_before'][key])
    for correction in ('connect-cancel-fix', 'close-fixture-fix'):
        record = read(STAGE / 'verification/merge' / (correction + '.json'))
        gates[correction + '_no_conflicts'] = not record['conflicts']
        gates[correction + '_branch_unchanged'] = row_map(manifest(Path(record['branch']))) == row_map(record['incoming_source'])
    next20_failure = read(ROOT / '.staging/r9-next20/verification/r9-next20/local-gate-attempt02/local-summary.json')
    old_index = read(ROOT / '.staging/r9-next19/verification/r9-next19/evidence-index.json')
    old_wan = Path(old_index['wan']['result_path'])
    old_binding = read(old_wan.parent / 'next19-experiment-binding.json')
    gates['next19_wan_preserved'] = hashlib.sha256(old_wan.read_bytes()).hexdigest() == old_binding['raw_result_sha256']
    report = {
        'revision': 'v0.1-r9-next21', 'source_manifest_sha256': frozen['manifest_sha256'],
        'source_file_count': frozen['file_count'], 'gates': gates,
        'source_bound_local_fuzz_and_race_pass': all(gates.values()),
        'local_packages_passed': local['checks']['go_test']['packages_passed'],
        'local_top_level_tests_passed': local['checks']['go_test']['top_level_tests_passed'],
        'local_gate': str(OUT / 'local-gate-attempt01/local-summary.json'),
        'bounded_parser_fuzz': str(OUT / 'fuzz-attempt01/summary.json'),
        'race': {'run_id': race['run_id'], 'strict_pass': race['pass'], 'result_path': str(Path(args.race_result).resolve())},
        'binaries': local['binaries'],
        'next20_attempt02': {'status': 'strict_fail_preserved', 'local_checks_pass': next20_failure['local_checks_pass'],
                             'reason': 'simultaneous-close ACK observation; original fixture and output retained'},
        'prior_wan': {'run_id': old_index['wan']['run_id'], 'status': 'strict_fail_preserved', 'path': str(old_wan)},
        'wan': {'status': 'not_run', 'singapore_uploads_in_this_revision': 0},
        'four_categories': {'core_implemented': 2, 'partially_implemented': 2, 'finally_accepted': 0},
        'acceptance_complete': False, 'production_ready': False, 'released': False,
        'pending': ['DNS recursion, EDNS and IPv6 support plus system resolver/TUN wiring',
                    'authenticated UDP administrative shutdown notification',
                    'actual Mihomo and sing-box native registration, build and runtime matrices',
                    'new message-level WAN observability and full recovery/failure matrix',
                    'mixed-class/FEC performance, long resource stability, independent security audit and interoperability'],
    }
    with (OUT / 'evidence-index.json').open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'path': str(OUT / 'evidence-index.json'), 'source_bound_checks_pass': all(gates.values())}))
    return 0 if all(gates.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
