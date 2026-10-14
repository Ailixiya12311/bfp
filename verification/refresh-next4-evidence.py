"""Refresh the next4 index from frozen evidence, preserving prior failures.

This script performs no remote operation, build, or test. Local failure facts
come from the preceding turn's recorded tool output; remote facts and hashes
are checked against on-disk artifacts before the index can be written.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next4'
OUT = STAGE / 'verification/r9-next4'
RACE = '2b0740497fdd21fb4608fe5f61bc580b'
WAN = '9922a59b0ae25b39f216220989e9e805'
TICKET = 'a8dffd05d5bb86469e148f7ddbbaea22'


def read(path: Path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def write(path: Path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def sha(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    report = read(OUT / 'local-summary.json')
    original = copy.deepcopy(report)
    manifest = read(OUT / 'source-manifest.json')
    rows = manifest['source_manifest']
    canonical = hashlib.sha256((json.dumps(rows, sort_keys=True, indent=2) + '\n').encode()).hexdigest()
    assert canonical == manifest['manifest_sha256']
    assert len(rows) == manifest['file_count'] == 88
    for row in rows:
        assert sha(STAGE / row['path']) == row['sha256'], row['path']
    linux = sha(ROOT / 'bin/bfp-r9-next4-linux-amd64')
    windows = sha(ROOT / 'bin/bfp-r9-next4-windows.exe')
    assert linux == sha(STAGE / 'bfp-r9-next4-linux-amd64')
    assert windows == sha(STAGE / 'bfp-r9-next4-windows.exe')
    report['binaries'] = [
        {'path': 'bin/bfp-r9-next4-windows.exe', 'platform': 'windows', 'sha256': windows},
        {'path': 'bin/bfp-r9-next4-linux-amd64', 'platform': 'linux', 'sha256': linux},
    ]
    race = read(STAGE / 'lab/runs' / RACE / 'race-result.json')
    assert {r['path']: r['sha256'] for r in rows} == {r['path']: r['sha256'] for r in race['source_manifest']}
    assert race['related_binary_sha256'] == linux
    race_entry = {
        'run_id': RACE,
        'path': f'.staging/r9-next4/lab/runs/{RACE}/race-result.json',
        'command': 'go test -race -p 1 ./... -count=1 -timeout=180s',
        'pass': race['pass'], 'exit_code': race['execution']['exit_code'],
        'source_manifest_sha256': canonical, 'binary_sha256': linux,
        'owned_container_removed': race['execution']['owned_container_removed'],
        'snapshot_unchanged': race['snapshot_comparison']['unchanged'],
    }

    def wan_entry(run_id):
        raw = read(STAGE / 'lab/runs' / run_id / 'wan-result.json')
        assert raw['run_id'] == run_id and raw['binary_sha256'] == linux
        for role in ('sender', 'receiver'):
            assert raw['staged'][role]['sha256'] == linux
        return {
            'run_id': run_id, 'path': f'.staging/r9-next4/lab/runs/{run_id}/wan-result.json',
            'pass': raw['pass'], 'binary_sha256': linux,
            'roles': {'sender': 'Singapore 198.51.100.20', 'receiver_exit_test': 'Los Angeles 192.0.2.10'},
            'scenarios': {name: {
                'pass': item['pass'], 'tcp_completed': item['result']['tcp_completed'],
                'udp_completed': item['result']['udp_completed'], 'udp_failed': item['result']['udp_failed'],
                'failure': item['result']['failure'], 'same_session': item['result']['same_session'],
                'one_target_connection': item['one_target_connection'],
                'elapsed_ms': item['result']['elapsed_ms'],
                'ticket_refreshes': item['result']['final']['ticket_refreshes'],
                'ticket_lifecycle_gate_met': item['ticket_lifecycle_gate_met'],
            } for name, item in raw['scenarios'].items()},
            'random_probe_pass': raw['random_probe']['pass'],
            'cleanup': {role: item['directory_removed'] and all(p['stopped'] for p in item['processes']) for role, item in raw['cleanup'].items()},
            'snapshot_unchanged': {role: item['comparison']['unchanged'] for role, item in raw['snapshots'].items()},
        }, raw

    wan, _ = wan_entry(WAN)
    ticket, raw_ticket = wan_entry(TICKET)
    ticket['ticket_options'] = raw_ticket['ticket_lifecycle']['options']
    wan['strict_failed_baseline_sample_preserved'] = original['checks']['wan']['strict_failed_baseline_sample_preserved']
    ticket['strict_failed_short_sample_preserved'] = original['checks']['ticket_lifecycle_wan']['strict_failed_short_sample_preserved']
    for key, value in (('independent_linux_race', race_entry), ('wan', wan), ('ticket_lifecycle_wan', ticket)):
        report['checks'][key] = value
    report['checks']['go_test'] = {
        'command': 'go test -p 1 ./... -count=1 -timeout=180s',
        'exit_code': 1, 'pass': False,
        'failed_tests': ['TestRunningUDPBlackholeRecoversSameExitAndBytes'],
        'observed': {'deadline_seconds': 8, 'Carrier': 'udp', 'Generation': 1, 'Switches': 0, 'UDPPTODue': 3, 'UDPProbeSent': 3},
        'evidence_source': 'preceding turn tool-output handoff; original raw output has not been reconstructed',
        'subsequent_targeted_repeat': {
            'command': 'go test -p 1 ./tests/integration -run TestRunningUDPBlackholeRecoversSameExitAndBytes -count=3 -timeout=180s',
            'passed': 2, 'failed': 1, 'pass': False,
            'note': 'The repeat successes do not replace the original suite failure.',
        },
    }
    report['checks']['local_race']['reason'] = 'Windows CGO_ENABLED=0 and no gcc; independent Linux race on the current manifest passed.'
    report['remote_validation']['linux_race'] = copy.deepcopy(race_entry)
    report['remote_validation']['wan'] = copy.deepcopy(wan)
    report['remote_validation']['ticket_lifecycle_wan'] = copy.deepcopy(ticket)
    for key in ('canonical_manifest_sha256', 'source_manifest_sha256', 'manifest_sha256'):
        report[key] = canonical
    report['source_manifest'] = rows
    report['source_file_count'] = len(rows)
    report['source_unchanged'] = True
    report['pass'] = report['production_ready'] = report['released'] = False
    report['verification_note'] = (
        'Current 88-file source matches manifest and the independent Linux race frozen source. '
        'go vet and both builds passed. Latest full local suite failed at the unchanged 8s UDP blackhole deadline; '
        'a subsequent targeted repeat passed 2/3, so the local suite is not PASS. '
        f'Linux race {RACE} and base WAN {WAN} passed. '
        f'Latest Ticket lifecycle WAN {TICKET} strictly failed: UDP-to-TCP completed TCP20/20, UDP19/20. '
        'All three lifecycle gates were met with three installed refreshes per scenario; '
        'random probes, owned cleanup and baseline snapshots passed. '
        'Failures d1972af391309e251aa3dd57c1d89572 and 77eb5ff83504460b87839660d9ee04f6 remain retained. '
        'No release or production-readiness claim is made.'
    )
    history = OUT / 'local-summary.previous-c02964.json'
    if original['canonical_manifest_sha256'] != canonical and not history.exists():
        write(history, original)
    write(OUT / 'local-summary.json', report)
    print(json.dumps({'pass': report['pass'], 'manifest': canonical, 'files': len(rows), 'race': race_entry['pass'], 'base_wan': wan['pass'], 'ticket_wan': ticket['pass'], 'production_ready': False, 'released': False}))


if __name__ == '__main__':
    main()
