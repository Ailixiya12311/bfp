"""Preserve the second failed gate before fixing simultaneous close ordering."""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
second = ROOT / '.staging/r9-next15/verification/r9-next15/local-gate-attempt02/local-summary.json'
report = json.loads(second.read_text(encoding='utf-8'))
if report['local_checks_pass'] or report['checks']['go_test']['failed_tests'] != [
    'TestBoundedCloseSimultaneousRequests/none', 'TestBoundedCloseSimultaneousRequests']:
    raise RuntimeError('inspect unexpected second gate before creating a successor')
content = (ROOT / 'verification/verify-next15-attempt02.py').read_text(encoding='utf-8').replace('attempt02', 'attempt03')
with (ROOT / 'verification/verify-next15-attempt03.py').open('x', encoding='utf-8') as output:
    output.write(content)
runner = ROOT / 'verification/run-next15-race.py'
runner.write_text(runner.read_text(encoding='utf-8').replace('local-gate-attempt02', 'local-gate-attempt03'), encoding='utf-8')
fuzz = ROOT / 'verification/fuzz-next15.py'
fuzz.write_text(fuzz.read_text(encoding='utf-8').replace('local-gate-attempt02', 'local-gate-attempt03'), encoding='utf-8')
print('next15 attempt03 helper created; all prior gate evidence and binaries retained')
