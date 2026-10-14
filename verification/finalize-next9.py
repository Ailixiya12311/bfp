"""Bind next9's source, local gate, targeted results and one offline race run."""
from pathlib import Path
import argparse
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next9'
OUT = STAGE / 'verification/r9-next9'


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def save(path, value):
    if path.exists():
        if read(path) != value:
            raise ValueError('existing evidence differs: ' + str(path))
        return
    with path.open('x', encoding='utf-8') as destination:
        json.dump(value, destination, ensure_ascii=False, indent=2)
        destination.write('\n')


def unchanged(root, rows):
    return all(hashlib.sha256((root / row['path']).read_bytes()).hexdigest() == row['sha256'] for row in rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{32}', args.run_id):
        raise ValueError('invalid run ID')
    frozen = read(OUT / 'local-gate/source-manifest.json')
    local = read(OUT / 'local-gate/local-summary.json')
    parent_root = ROOT / '.staging/r9-next8'
    parent = read(parent_root / 'verification/r9-next8/local-gate/source-manifest.json')
    current = {row['path']: row['sha256'] for row in frozen['source_manifest']}
    prior = {row['path']: row['sha256'] for row in parent['source_manifest']}
    current_ok = unchanged(STAGE, frozen['source_manifest'])
    parent_ok = unchanged(parent_root, parent['source_manifest'])
    live_paths = {'go.mod', 'go.sum'}
    for name in ('adapter', 'classification', 'cmd', 'gateway', 'internal', 'obfuscation', 'protocol', 'scheduler', 'security', 'session', 'tests'):
        live_paths.update(p.relative_to(STAGE).as_posix() for p in (STAGE / name).rglob('*.go'))
    current_ok = current_ok and live_paths == set(current)
    diff = {'parent_revision': 'r9-next8', 'revision': 'r9-next9',
            'parent_frozen_source_unchanged': parent_ok, 'current_frozen_source_unchanged': current_ok,
            'parent_source_file_count': len(prior), 'source_file_count': len(current),
            'added': sorted(set(current) - set(prior)), 'removed': sorted(set(prior) - set(current)),
            'changed': sorted(name for name in set(current) & set(prior) if current[name] != prior[name])}
    save(OUT / 'source-diff.json', diff)
    run = STAGE / 'lab/runs' / args.run_id
    race = read(run / 'race-result.json')
    race_source = {row['path']: row['sha256'] for row in race['source_manifest']}
    linux = next(row for row in local['binaries'] if row['platform'] == 'linux')
    log = read(run / 'race-log.json')['text']
    binding = {'run_id': args.run_id, 'raw_race_pass': race['pass'],
               'source_manifest_matches': current == race_source,
               'source_file_count': len(current), 'current_source_unchanged': current_ok,
               'parent_source_unchanged': parent_ok,
               'related_linux_binary_matches': race['related_binary_sha256'] == linux['sha256'] == hashlib.sha256((ROOT / linux['path']).read_bytes()).hexdigest(),
               'related_binary_binding_scope': 'race compiles frozen source; associated Linux build SHA is metadata binding, not execution of that binary',
               'packages_passed': len(re.findall(r'^ok\s+\S+', log, flags=re.MULTILINE)),
               'data_race_report_present': 'WARNING: DATA RACE' in log,
               'owned_container_removed': race.get('execution', {}).get('owned_container_removed') is True,
               'directory_removed': race.get('cleanup', {}).get('directory_removed') is True,
               'receiver_snapshot_unchanged': race.get('snapshot_comparison', {}).get('unchanged') is True,
               'elapsed_seconds': race['elapsed_seconds'],
               'result': (run / 'race-result.json').relative_to(ROOT).as_posix(),
               'raw_log': (run / 'race-log.json').relative_to(ROOT).as_posix()}
    binding['binding_and_cleanup_pass'] = all(binding[key] for key in (
        'raw_race_pass', 'source_manifest_matches', 'current_source_unchanged', 'parent_source_unchanged',
        'related_linux_binary_matches', 'owned_container_removed', 'directory_removed', 'receiver_snapshot_unchanged'))
    save(OUT / 'race-binding.json', binding)
    listener_summary = STAGE / 'verification/listener-allocation/targeted-summary-attempt-01.json'
    dns_summary = STAGE / 'verification/dns-termination/targeted-summary-attempt-01.json'
    listener, dns = read(listener_summary), read(dns_summary)
    skipped = []
    for line in (OUT / 'local-gate/go_test.log').read_text(encoding='utf-8').splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get('Action') == 'skip' and 'Test' in event:
            skipped.append({'package': event['Package'], 'test': event['Test']})
    index = {'revision': 'v0.1-r9-next9', 'date': '2026-10-09', 'goal_status': 'active',
             'wire_version': 3, 'profile': 'class-announcement-v1', 'capabilities': 1,
             'parent_revision': 'r9-next8', 'parent_source_file_count': len(prior),
             'parent_proof': '.staging/r9-next9/verification/parent-source-manifest.json',
             'source_freeze': 'frozen', 'source_file_count': len(current),
             'source_manifest_sha256': frozen['manifest_sha256'],
             'source_manifest': '.staging/r9-next9/verification/r9-next9/local-gate/source-manifest.json',
             'source_diff': '.staging/r9-next9/verification/r9-next9/source-diff.json',
             'production_source_changed': True, 'binaries': local['binaries'],
             'local_gate': {'summary': '.staging/r9-next9/verification/r9-next9/local-gate/local-summary.json',
                            'checks': local['checks'], 'source_unchanged': current_ok,
                            'elapsed_seconds': local['elapsed_seconds'], 'skipped_tests': skipped,
                            'original_summary_not_rewritten': True},
             'independent_linux_race': {**binding, 'binding': '.staging/r9-next9/verification/r9-next9/race-binding.json'},
             'targeted_checks': {
                 'listener_allocation': {'summary': listener_summary.relative_to(ROOT).as_posix(), 'result': listener},
                 'actual_session_dns_termination': {'summary': dns_summary.relative_to(ROOT).as_posix(), 'result': dns}},
             'implementation': {
                 'ephemeral_shared_listener_candidates': 16,
                 'successful_sockets_continuously_held': True,
                 'only_requested_ephemeral_second_protocol_collision_searches': True,
                 'fixed_port_search': False, 'tcp_listen_error_search': False,
                 'platform_errno_classification': {'unix': ['EADDRINUSE'], 'windows': [10048, 10013]},
                 'windows_10013_cause_proved': False,
                 'configuration_validation_before_sockets': True,
                 'three_fixture_release_and_rebind_windows_removed': True,
                 'actual_dns_terminal_tests': ['device revocation', 'immutable lifetime expiry', 'Serve parent cancellation'],
                 'runtime_dns_answers': 'controlled loopback; actual encrypted UDP and numeric TCP sockets',
                 'per_case_business_context_seconds': 5, 'terminal_resource_observation_seconds': 1,
                 'test_immutable_lifetime_seconds': 0.25,
                 'revocation_and_server_cancel_client_read_timeout_is_terminal_proof': False,
                 'wire_or_close_control_semantics_changed': False,
                 'bounded_close_control_state_machine_implemented': False,
                 'production_udp_watchdog_seconds': 15, 'production_retain_seconds': 30,
                 'original_operation_seconds': 8, 'original_wan_probe_seconds': 35},
             'retained_parent_failure': {
                 'revision': 'r9-next8', 'race_run_id': 'c0d872535db2d5bc4515e8720cfc4410',
                 'pass': False, 'failure': 'classification TCP fixture bind address already in use',
                 'exact_preflight_or_constructor_stage_known': False, 'overridden_by_this_revision': False},
             'wan': {'status': 'not_run', 'singapore_business_load_added': False},
             'missing_gates': ['bounded close-control state machine and loss/budget/late-frame/restore rejection matrix',
                               'fixed-deadline WAN diagnostics and short-lived network lifecycle evidence',
                               'classification convergence and mixed-load performance',
                               'original eight-second recovery stability, independent security, client DNS/fake-IP/TUN/IPv6'],
             'local_checks_pass': local.get('local_checks_pass') is True,
             'selected_checks_pass': bool(local.get('local_checks_pass') and binding['binding_and_cleanup_pass']),
             'acceptance_complete': False, 'pass': False, 'production_ready': False,
             'released': False, 'release_zip_created': False}
    if not binding['binding_and_cleanup_pass']:
        index['missing_gates'].insert(0, 'independent Linux race does not pass; preserve this original result')
    save(OUT / 'evidence-index.json', index)
    print(json.dumps({'source_count': len(current), 'added': diff['added'], 'changed': diff['changed'],
                      'local_checks_pass': index['local_checks_pass'], 'race_binding_pass': binding['binding_and_cleanup_pass'],
                      'acceptance_complete': False}, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
