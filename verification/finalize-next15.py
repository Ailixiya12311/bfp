"""Index next15 evidence and binding; never rewrite raw results or older gates."""
from pathlib import Path
import argparse
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next15'
OUT = STAGE / 'verification/r9-next15'

def read(path):
    return json.loads(path.read_text(encoding='utf-8'))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-id')
    args = parser.parse_args()
    if args.run_id and not re.fullmatch('[a-f0-9]{32}', args.run_id):
        raise ValueError('invalid race run ID')
    frozen = read(OUT / 'local-gate-attempt03/source-manifest.json')
    local = read(OUT / 'local-gate-attempt03/local-summary.json')
    first = read(OUT / 'local-gate/local-summary.json')
    second = read(OUT / 'local-gate-attempt02/local-summary.json')
    parent = read(STAGE / 'verification/parent-source-manifest.json')
    expected = frozen['source_manifest']
    source = [STAGE / 'go.mod', STAGE / 'go.sum']
    for directory in ('adapter', 'classification', 'cmd', 'gateway', 'internal', 'obfuscation', 'protocol', 'scheduler', 'security', 'session', 'tests'):
        source.extend((STAGE / directory).rglob('*.go'))
    live = [{'path': p.relative_to(STAGE).as_posix(), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(source)]
    parent_unchanged = all(hashlib.sha256((ROOT / '.staging/r9-next14' / row['path']).read_bytes()).hexdigest() == row['sha256'] for row in parent['copied_source_manifest'])
    focused = {}
    for name, path in (
        ('owner_attempt02', OUT / 'focused/owner-attempt02.jsonl'),
        ('admission_attempt02', OUT / 'focused/fec-admission-attempt02.jsonl'),
        ('admission_attempt03', OUT / 'focused/fec-admission-attempt03.jsonl'),
        ('budget_regression_after_fix', OUT / 'focused/budget-regression-after-fix.jsonl'),
        ('encrypted_udp_attempt01', OUT / 'focused/fec-runtime-attempt01.jsonl'),
        ('close_order_attempt01', OUT / 'focused/close-order-attempt01.jsonl'),
        ('close_order_attempt02', OUT / 'focused/close-order-attempt02.jsonl'),
        ('simultaneous_close_initial_fix', OUT / 'focused/simultaneous-close-after-fix.jsonl'),
        ('simultaneous_close_cadence_fix', OUT / 'focused/simultaneous-close-cadence-fix.jsonl'),
    ):
        events = []
        for line in path.read_text(encoding='utf-8-sig').splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                pass
        focused[name] = {'path': str(path.resolve()),
                         'raw_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                         'scope': 'focused source iteration; final frozen source is verified by the full gate and race separately',
                         'top_level_tests_passed': sum(e.get('Action') == 'pass' and 'Test' in e and '/' not in e['Test'] for e in events),
                         'failed_events': [e for e in events if e.get('Action') == 'fail'],
                         'package_pass': any(e.get('Action') == 'pass' and 'Test' not in e for e in events)}
    report = {'revision': 'v0.1-r9-next15',
              'source_manifest_sha256': frozen['manifest_sha256'], 'source_file_count': len(expected),
              'current_source_matches_frozen': live == expected, 'parent_next14_source_unchanged': parent_unchanged,
              'local_checks_pass': local['local_checks_pass'],
              'local_packages_passed': local['checks']['go_test']['packages_passed'],
              'local_top_level_tests_passed': local['checks']['go_test']['top_level_tests_passed'],
              'local_gate_attempts': [
                  {'name': 'attempt01', 'source_manifest_sha256': first['source_manifest_sha256'],
                   'local_checks_pass': first['local_checks_pass'], 'failed_tests': first['checks']['go_test']['failed_tests'],
                   'path': str((OUT / 'local-gate/local-summary.json').resolve())},
                  {'name': 'attempt02', 'source_manifest_sha256': second['source_manifest_sha256'],
                   'local_checks_pass': second['local_checks_pass'], 'failed_tests': second['checks']['go_test']['failed_tests'],
                   'path': str((OUT / 'local-gate-attempt02/local-summary.json').resolve())},
                  {'name': 'attempt03', 'source_manifest_sha256': local['source_manifest_sha256'],
                   'local_checks_pass': local['local_checks_pass'], 'failed_tests': local['checks']['go_test']['failed_tests'],
                   'path': str((OUT / 'local-gate-attempt03/local-summary.json').resolve())}],
              'focused': focused, 'independent_linux_race': {'status': 'not_run'},
              'bounded_parser_fuzz': {'status': 'not_run'},
              'preserved_initial_owner_failure': {'path': str((OUT / 'focused/owner-attempt01-summary.json').resolve()),
                                                 'raw_available': False, 'scope': 'tool output observation; truncated raw; not frozen source evidence'},
              'wan': {'status': 'not_run', 'singapore_transfer_or_business': 'none_in_this_revision'},
              'four_categories': {'core_implemented': 2, 'partially_implemented': 2, 'finally_accepted': 0},
              'acceptance_complete': False, 'production_ready': False, 'released': False,
              'pending': ['FEC policy integration with existing classification CLI and SOCKS domain metadata; trusted external rule tag/application identity bridge',
                          'mixed-class fairness/FEC overhead and tail latency on WAN',
                          'complete close/recovery/READY fault matrix',
                          'original 8s UDP recovery stability and repeated gate diagnostics',
                          'client DNS/fake-IP/TUN/IPv6 integration',
                          'long-term allocator/RSS/CPU/kernel socket resource measurements',
                          'extended parser fuzz, independent security review and cross-implementation interoperability']}
    fuzz_path = OUT / 'fuzz/summary.json'
    if fuzz_path.exists():
        fuzz = read(fuzz_path)
        report['bounded_parser_fuzz'] = {
            'status': 'pass' if fuzz['pass'] else 'fail',
            'exit_code': fuzz['exit_code'], 'source_unchanged': fuzz['source_unchanged'],
            'source_matches_local_manifest': fuzz['source_manifest_sha256'] == frozen['manifest_sha256'],
            'scope': fuzz['scope'], 'result_path': str(fuzz_path.resolve()), 'raw_log': fuzz['raw_log']}
    if args.run_id:
        run = STAGE / 'lab/runs' / args.run_id
        race = read(run / 'race-result.json')
        log = read(run / 'race-log.json')['text']
        linux = next(row for row in local['binaries'] if row['platform'] == 'linux')
        rows = [{'path': row['path'], 'sha256': row['sha256']} for row in race['source_manifest']]
        report['independent_linux_race'] = {
            'status': 'pass' if race['pass'] else 'fail', 'run_id': args.run_id,
            'strict_pass': race['pass'], 'program_exit_code': race['execution']['exit_code'],
            'packages_passed': len(re.findall(r'^ok\s+', log, re.MULTILINE)),
            'race_report_present': 'DATA RACE' in log,
            'source_matches_local_manifest': rows == expected,
            'related_binary_matches': race['related_binary_sha256'] == linux['sha256'] == hashlib.sha256((ROOT / linux['path']).read_bytes()).hexdigest(),
            'binary_binding_scope': 'associated local build metadata; race recompiles frozen source, not the prebuilt binary',
            'owned_container_removed': race['execution']['owned_container_removed'],
            'owned_directory_removed': race['cleanup']['directory_removed'],
            'snapshot_unchanged': race['snapshot_comparison']['unchanged'],
            'result_path': str((run / 'race-result.json').resolve())}
    bound = report['independent_linux_race']
    report['source_bound_local_and_race_pass'] = all((live == expected, parent_unchanged, local['local_checks_pass'],
        bound.get('strict_pass', False), bound.get('source_matches_local_manifest', False), bound.get('related_binary_matches', False)))
    parser_fuzz = report['bounded_parser_fuzz']
    report['source_bound_local_fuzz_and_race_pass'] = all((report['source_bound_local_and_race_pass'],
        parser_fuzz.get('status') == 'pass', parser_fuzz.get('source_unchanged', False),
        parser_fuzz.get('source_matches_local_manifest', False)))
    with (OUT / 'evidence-index.json').open('x', encoding='utf-8') as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write('\n')
    print(json.dumps(report, ensure_ascii=False), flush=True)

if __name__ == '__main__':
    main()
