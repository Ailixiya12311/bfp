"""Explain frozen host listener drift without overriding the original strict result."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next9'
OUT = STAGE / 'verification/r9-next9'
RUN = STAGE / 'lab/runs/63f9747669ffb30743736296cd72cf5c'
raw_path = RUN / 'race-result.json'
raw_hash = hashlib.sha256(raw_path.read_bytes()).hexdigest()
result = json.loads(raw_path.read_text(encoding='utf-8'))
comparison = result['snapshot_comparison']
canonical = lambda line: re.sub(r'users:.*$', '', line).strip()
before, after = (result['snapshots']['receiver'][phase]['snapshot']['listeners'] for phase in ('before', 'after'))
rows = {'before': {canonical(line): line for line in before}, 'after': {canonical(line): line for line in after}}
changed = {'removed': sorted(set(rows['before']) - set(rows['after'])),
           'added': sorted(set(rows['after']) - set(rows['before']))}
evidence = {}
for direction, phase in (('removed', 'before'), ('added', 'after')):
    evidence[direction] = []
    for normalized in changed[direction]:
        line = rows[phase][normalized]
        owners = [{'name': name, 'pid': int(pid), 'fd': int(fd)}
                  for name, pid, fd in re.findall(r'\("([^"\n]+)",pid=(\d+),fd=(\d+)\)', line)]
        evidence[direction].append({'listener': normalized, 'owners': owners})
all_changed = evidence['removed'] + evidence['added']
report = {'run_id': result['run_id'], 'raw_result_sha256': raw_hash,
          'original_strict_pass': result['pass'], 'original_snapshot_unchanged': comparison['unchanged'],
          'race_execution_exit_code': result['execution']['exit_code'],
          'race_test_program_pass': result['execution']['exit_code'] == 0,
          'only_listener_comparison_changed': set(comparison['changes']) == {'listeners'},
          'only_udp_rows_changed': bool(all_changed) and all(row['listener'].startswith('udp ') for row in all_changed),
          'all_changed_rows_single_xray_owner': bool(all_changed) and all(len(row['owners']) == 1 and row['owners'][0]['name'] == 'xray' for row in all_changed),
          'observed_xray_pids': sorted({owner['pid'] for row in all_changed for owner in row['owners']}),
          'removed_count': len(evidence['removed']), 'added_count': len(evidence['added']),
          'owner_evidence': evidence,
          'fixed_tcp_listeners_unchanged': sorted(line for line in rows['before'] if line.startswith('tcp ')) == sorted(line for line in rows['after'] if line.startswith('tcp ')),
          'containers_routes_firewall_nft_comparison_unchanged': not any(key != 'listeners' for key in comparison['changes']),
          'owned_container_removed': result['execution']['owned_container_removed'],
          'owned_directory_removed': result['cleanup']['directory_removed'],
          'remote_test_network': 'none; test sockets are in the isolated container network namespace',
          'same_pid_proves_same_process_start_time_or_executable': False,
          'service_config_hashes_were_in_original_snapshot': False,
          'does_not_override_original_strict_result': True,
          'no_remote_refresh_or_test_rerun': True,
          'boundary': 'Original snapshots prove ownership of changed rows at those observation times, not the cause of socket churn or continuous process/config identity.'}
with (OUT / 'host-listener-drift-audit.json').open('x', encoding='utf-8') as destination:
    json.dump(report, destination, ensure_ascii=False, indent=2)
    destination.write('\n')
index_path = OUT / 'evidence-index.json'
index = json.loads(index_path.read_text(encoding='utf-8'))
index['independent_linux_race']['race_test_program_pass'] = report['race_test_program_pass']
index['independent_linux_race']['host_listener_drift_audit'] = '.staging/r9-next9/verification/r9-next9/host-listener-drift-audit.json'
index['independent_linux_race']['strict_environment_gate_pass'] = False
index['missing_gates'][0] = 'strict host snapshot equality failed on existing Xray UDP socket changes; original overall false retained and owner drift separately audited'
index['metadata_initial_error_record'] = '.staging/r9-next9/verification/r9-next9/finalization-initial-error.txt'
index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
assert hashlib.sha256(raw_path.read_bytes()).hexdigest() == raw_hash
print(json.dumps({key: report[key] for key in ('race_test_program_pass', 'original_strict_pass', 'only_udp_rows_changed', 'all_changed_rows_single_xray_owner', 'observed_xray_pids', 'removed_count', 'added_count', 'owned_container_removed', 'owned_directory_removed')}))
