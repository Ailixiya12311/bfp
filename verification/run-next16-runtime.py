"""Preserve real JSON/SOCKS/encrypted-carrier FEC policy verification."""
from pathlib import Path
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next16'
OUT = STAGE / 'verification/r9-next16/focused'
OUT.mkdir(parents=True, exist_ok=True)
log = OUT / 'cli-socks-runtime-attempt01.jsonl'
command = ['go', 'test', '-json', './cmd/bfp', '-run=^TestDatagramFECCLIRealSOCKSNext16$', '-count=1', '-timeout=45s']
with log.open('xb') as output:
    result = subprocess.run(command, cwd=STAGE, stdout=output, stderr=subprocess.STDOUT,
                            env=dict(os.environ, GOTOOLCHAIN='local', CGO_ENABLED='0'), timeout=60)
events = []
for line in log.read_text(encoding='utf-8').splitlines():
    try:
        events.append(json.loads(line))
    except ValueError:
        pass
summary = {'command': command, 'exit_code': result.returncode, 'pass': result.returncode == 0,
           'fail_events': [e for e in events if e.get('Action') == 'fail'],
           'raw_log': str(log.resolve())}
with (OUT / 'cli-socks-runtime-attempt01-summary.json').open('x', encoding='utf-8') as output:
    json.dump(summary, output, indent=2)
    output.write('\n')
print(json.dumps(summary), flush=True)
raise SystemExit(result.returncode)
