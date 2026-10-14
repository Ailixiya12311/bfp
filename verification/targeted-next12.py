"""Persist each selected run, including empty selections and failures."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next12'
label, package, selection = sys.argv[1:4]
OUT = STAGE / 'verification' / label
OUT.mkdir(parents=True, exist_ok=False)
def manifest():
    paths = [STAGE / 'go.mod', STAGE / 'go.sum']
    for directory in ('adapter','classification','cmd','gateway','internal','obfuscation','protocol','scheduler','security','session','tests'):
        paths.extend((STAGE / directory).rglob('*.go'))
    return [{'path': p.relative_to(STAGE).as_posix(), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(paths)]
rows = manifest()
command = ['go', 'test', '-json', package, '-run', selection, '-count=1', '-timeout=60s']
started = time.monotonic()
result = subprocess.run(command, cwd=STAGE, env=dict(os.environ, GOTOOLCHAIN='local', CGO_ENABLED='0'), capture_output=True, timeout=90)
(OUT / 'go-test.jsonl').write_bytes(result.stdout)
(OUT / 'stderr.txt').write_bytes(result.stderr)
events = []
for line in result.stdout.decode('utf-8', errors='replace').splitlines():
    try: events.append(json.loads(line))
    except ValueError: pass
ran = [e['Test'] for e in events if e.get('Action') == 'run' and 'Test' in e and '/' not in e['Test']]
passed = [e['Test'] for e in events if e.get('Action') == 'pass' and 'Test' in e and '/' not in e['Test']]
failed = [e['Test'] for e in events if e.get('Action') == 'fail' and 'Test' in e]
report = {'command': command, 'exit_code': result.returncode, 'elapsed_seconds': round(time.monotonic()-started,3), 'top_level_run':ran,'top_level_pass':passed,'failed':failed,'source_manifest_at_start':rows,'source_unchanged':rows==manifest(), 'scope':'selected_local_only','acceptance_complete':False,'production_ready':False,'released':False}
report['selected_tests_pass'] = bool(ran) and result.returncode == 0 and len(ran)==len(passed) and not failed and report['source_unchanged']
(OUT / 'summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps({k:v for k,v in report.items() if k != 'source_manifest_at_start'}))
