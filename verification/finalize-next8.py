"""Bind next8's frozen local and Linux race evidence without changing raw results."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next8'
OUT = STAGE / 'verification/r9-next8'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def save_new(path, value):
    with path.open('x', encoding='utf-8') as destination:
        json.dump(value, destination, ensure_ascii=False, indent=2)
        destination.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{32}', args.run_id):
        raise ValueError('invalid race run ID')
    frozen = read(OUT / 'local-gate/source-manifest.json')
    local = read(OUT / 'local-gate/local-summary.json')
    source = {row['path']: row['sha256'] for row in frozen['source_manifest']}
    current_matches = all(hashlib.sha256((STAGE / name).read_bytes()).hexdigest() == digest
                          for name, digest in source.items())
    parent_root = ROOT / '.staging/r9-next7'
    parent = read(parent_root / 'verification/r9-next7/local-gate/source-manifest.json')
    parent_source = {row['path']: row['sha256'] for row in parent['source_manifest']}
    parent_unchanged = all(hashlib.sha256((parent_root / name).read_bytes()).hexdigest() == digest
                           for name, digest in parent_source.items())
    diff = {'parent_revision': 'r9-next7', 'revision': 'r9-next8',
            'parent_frozen_source_unchanged': parent_unchanged,
            'next8_frozen_source_unchanged': current_matches,
            'parent_source_file_count': len(parent_source), 'source_file_count': len(source),
            'added': sorted(set(source) - set(parent_source)),
            'removed': sorted(set(parent_source) - set(source)),
            'changed': sorted(name for name in set(source) & set(parent_source)
                              if source[name] != parent_source[name])}
    save_new(OUT / 'source-diff.json', diff)
    run = STAGE / 'lab/runs' / args.run_id
    race = read(run / 'race-result.json')
    race_source = {row['path']: row['sha256'] for row in race['source_manifest']}
    linux = next(row for row in local['binaries'] if row['platform'] == 'linux')
    binary_matches = (race['related_binary_sha256'] == linux['sha256'] ==
                      hashlib.sha256((ROOT / linux['path']).read_bytes()).hexdigest())
    log = read(run / 'race-log.json')['text']
    binding = {'run_id': args.run_id, 'pass': bool(race['pass']),
               'source_manifest_matches': source == race_source,
               'source_file_count': len(source), 'current_source_unchanged': current_matches,
               'parent_source_unchanged': parent_unchanged,
               'related_linux_binary_matches': binary_matches,
               'related_binary_binding_scope': 'race compiles frozen source; matching SHA binds associated local Linux build metadata, not execution of that binary',
               'packages_passed': len(re.findall(r'^ok\s+\S+', log, flags=re.MULTILINE)),
               'owned_container_removed': race.get('execution', {}).get('owned_container_removed') is True,
               'directory_removed': race.get('cleanup', {}).get('directory_removed') is True,
               'receiver_snapshot_unchanged': race.get('snapshot_comparison', {}).get('unchanged') is True,
               'elapsed_seconds': race['elapsed_seconds'],
               'result': (run / 'race-result.json').relative_to(ROOT).as_posix()}
    binding['binding_and_cleanup_pass'] = all(binding[key] for key in (
        'pass', 'source_manifest_matches', 'current_source_unchanged', 'parent_source_unchanged',
        'related_linux_binary_matches', 'owned_container_removed', 'directory_removed',
        'receiver_snapshot_unchanged'))
    save_new(OUT / 'race-binding.json', binding)
    index_path = OUT / 'evidence-index.json'
    index = read(index_path)
    index['source_freeze'] = {'status': 'frozen', 'source_unchanged': current_matches,
                              'manifest': '.staging/r9-next8/verification/r9-next8/local-gate/source-manifest.json',
                              'diff': '.staging/r9-next8/verification/r9-next8/source-diff.json',
                              'parent_frozen_source_unchanged': parent_unchanged}
    index['source_manifest_sha256'] = frozen['manifest_sha256']
    index['source_file_count'] = len(source)
    index['binaries'] = local['binaries']
    index['local_gate'] = {'status': 'pass' if local['local_checks_pass'] else 'fail',
                           'summary': '.staging/r9-next8/verification/r9-next8/local-gate/local-summary.json',
                           'source_unchanged': current_matches, 'checks': local['checks'],
                           'elapsed_seconds': local['elapsed_seconds'],
                           'windows_symlink_test_skipped': True,
                           'original_summary_not_rewritten': True}
    for platform in ('windows', 'linux'):
        index['build_' + platform] = {'status': 'pass' if local['checks']['build_' + platform]['pass'] else 'fail',
                                      **next(row for row in local['binaries'] if row['platform'] == platform)}
    index['independent_linux_race'] = {'status': 'pass' if binding['binding_and_cleanup_pass'] else 'fail',
                                     **binding, 'binding': '.staging/r9-next8/verification/r9-next8/race-binding.json'}
    runtime_base = '.staging/r9-next8/verification/backend-scope/runtime-dns/'
    first = read(ROOT / (runtime_base + 'targeted-summary-attempt-01.json'))
    second = read(ROOT / (runtime_base + 'targeted-summary-attempt-02.json'))
    index['targeted_checks']['session_dns_actual_runtime'] = {
        'first_attempt_pass': first['pass'], 'first_failure_preserved': True,
        'first_summary': runtime_base + 'targeted-summary-attempt-01.json',
        'first_raw_log': runtime_base + 'targeted-go-test-attempt-01.jsonl',
        'changed_source_attempt_pass': second['pass'],
        'changed_source_summary': runtime_base + 'targeted-summary-attempt-02.json',
        'changed_source_raw_log': runtime_base + 'targeted-go-test-attempt-02.jsonl',
        'test_source_unchanged': second['test_source_unchanged'],
        'business_context_seconds': 5, 'scope_cleanup_observation_seconds': 1,
        'fresh_sessions': 2, 'dns_lookups': 2, 'numeric_tcp_target_sockets': 3,
        'real_encrypted_udp_flows': True, 'dns_answers': 'controlled loopback only',
        'wan_or_udp_close_loss_matrix': False}
    index['implementation']['client_close'] = {
        'source': '.staging/r9-next8/session/client.go',
        'operation_context_separate_from_session_parent': True,
        'order': 'cancel connect/recovery; current Session.Close attempts notification and terminates; cancel Session parent; wait recovery workers',
        'late_connect_or_recovery_success_rejected_during_close': True,
        'new_ack_wait_or_retransmit_added': False,
        'udp_close_delivery_guaranteed': False}
    index['wan'] = {'status': 'not_run', 'scope': 'next8 production source not WAN accepted'}
    index['missing_gates'] = [
        'fixed deadline next8 WAN diagnostics and Session DNS lifecycle evidence',
        'UDP close loss/budget blockage and full short-lived network owned-state destruction acceptance',
        'client DNS query proxy, DoH, fake-IP, TUN and IPv6 acceptance matrix',
        'mixed-class performance, retry exhaustion, original eight-second recovery stability and independent security gates']
    if not binding['binding_and_cleanup_pass']:
        index['missing_gates'].insert(0, 'independent Linux race failed; preserve frozen failure and resolve fixture allocation on a new source boundary')
    index['local_checks_pass'] = local['local_checks_pass']
    index['selected_checks_pass'] = bool(local['local_checks_pass'] and binding['binding_and_cleanup_pass'])
    index['acceptance_complete'] = index['pass'] = index['production_ready'] = index['released'] = False
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'source_file_count': len(source), 'added': diff['added'], 'changed': diff['changed'],
                      'local_checks_pass': local['local_checks_pass'], 'race_binding_pass': binding['binding_and_cleanup_pass'],
                      'acceptance_complete': False}), flush=True)


if __name__ == '__main__':
    main()
