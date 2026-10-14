"""Supplement, never rewrite, the failed next10 summary's panic coverage."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
gate = ROOT / '.staging/r9-next10/verification/r9-next10/local-gate'
raw = (gate / 'go_test.log').read_bytes()
events = []
for line in raw.decode('utf-8', errors='replace').splitlines():
    try:
        events.append(json.loads(line))
    except ValueError:
        pass
running = set()
panics = []
for event in events:
    key = (event.get('Package'), event.get('Test'))
    if event.get('Action') == 'run' and key[1]:
        running.add(key)
    if event.get('Action') in ('pass', 'fail', 'skip') and key[1]:
        running.discard(key)
    if 'panic:' in event.get('Output', ''):
        panics.append({'package': key[0], 'active_test': key[1], 'output': event['Output'].strip()})
report = {
    'revision': 'v0.1-r9-next10',
    'original_summary_preserved': True,
    'go_test_log_sha256': hashlib.sha256(raw).hexdigest(),
    'panic_events': panics,
    'tests_without_terminal_event': [{'package': p, 'test': t} for p, t in sorted(running)],
    'failed_packages': [e['Package'] for e in events if e.get('Action') == 'fail' and 'Test' not in e],
    'coverage_incomplete': bool(panics or running),
    'interpretation': 'Session package aborted at nil RecordCipher.Seal during close cleanup; named failed_tests alone omits this package panic. The full close test matrix was not completed in this formal run.',
    'acceptance_complete': False, 'production_ready': False, 'released': False,
}
target = gate / 'failure-coverage-audit.json'
with target.open('x', encoding='utf-8') as output:
    output.write(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(report, ensure_ascii=False))
