"""Bounded repair-parser fuzz, separate from the source-bound full gate."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next15'
OUT = STAGE / 'verification/r9-next15/fuzz'
gate = json.loads((STAGE / 'verification/r9-next15/local-gate-attempt03/local-summary.json').read_text(encoding='utf-8'))
frozen = json.loads((STAGE / 'verification/r9-next15/local-gate-attempt03/source-manifest.json').read_text(encoding='utf-8'))
if not gate['local_checks_pass']:
    raise RuntimeError('inspect failed full gate before fuzz')
matches = lambda: all(hashlib.sha256((STAGE / row['path']).read_bytes()).hexdigest() == row['sha256'] for row in frozen['source_manifest'])
if not matches():
    raise RuntimeError('source differs from frozen full gate')
OUT.mkdir(parents=True, exist_ok=False)
command = ['go', 'test', './protocol', '-run=^$', '-fuzz=^FuzzDatagramRepairDecodeCanonical$', '-fuzztime=5s', '-parallel=2']
with (OUT / 'repair-parser.log').open('xb') as output:
    result = subprocess.run(command, cwd=STAGE, stdout=output, stderr=subprocess.STDOUT,
                            env=dict(os.environ, GOTOOLCHAIN='local', CGO_ENABLED='0', GOMAXPROCS='2'), timeout=40)
report = {'command': command, 'exit_code': result.returncode, 'pass': result.returncode == 0 and matches(),
          'source_manifest_sha256': frozen['manifest_sha256'], 'source_unchanged': matches(),
          'raw_log': str((OUT / 'repair-parser.log').resolve()),
          'scope': 'bounded 5-second parser fuzz with 2 workers; not an independent security audit or complete fuzz campaign'}
(OUT / 'summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report), flush=True)
raise SystemExit(0 if report['pass'] else 1)
