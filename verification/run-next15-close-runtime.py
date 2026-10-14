"""Preserve a bounded simultaneous-close regression after the ordered pair fix."""
from pathlib import Path
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next15'
OUT = STAGE / 'verification/r9-next15/focused'
OUT.mkdir(parents=True, exist_ok=True)
log = OUT / 'simultaneous-close-cadence-fix.jsonl'
command = ['go', 'test', '-json', './session', '-run=^TestBoundedCloseSimultaneousRequests$', '-count=5', '-timeout=30s']
with log.open('xb') as output:
    result = subprocess.run(command, cwd=STAGE, stdout=output, stderr=subprocess.STDOUT,
                            env=dict(os.environ, GOTOOLCHAIN='local', CGO_ENABLED='0'), timeout=45)
events = []
for line in log.read_text(encoding='utf-8').splitlines():
    try:
        events.append(json.loads(line))
    except ValueError:
        pass
summary = {'command': command, 'exit_code': result.returncode,
           'pass': result.returncode == 0,
           'top_level_pass_events': sum(e.get('Action') == 'pass' and 'Test' in e and '/' not in e['Test'] for e in events),
           'fail_events': [e for e in events if e.get('Action') == 'fail'],
           'raw_log': str(log.resolve())}
with (OUT / 'simultaneous-close-cadence-fix-summary.json').open('x', encoding='utf-8') as output:
    json.dump(summary, output, indent=2)
    output.write('\n')
print(json.dumps(summary), flush=True)
raise SystemExit(result.returncode)
