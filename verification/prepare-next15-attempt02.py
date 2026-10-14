"""Preserve the failed first gate and create a new source-bound attempt."""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
first = ROOT / '.staging/r9-next15/verification/r9-next15/local-gate/local-summary.json'
report = json.loads(first.read_text(encoding='utf-8'))
if report['local_checks_pass'] or report['checks']['go_test']['failed_tests'] != [
    'TestTransportUDPRejectedAdmissionDoesNotMutate/buffer-limit',
    'TestTransportUDPRejectedAdmissionDoesNotMutate']:
    raise RuntimeError('unexpected first gate; inspect before retry')
script = (ROOT / 'verification/verify-next15.py').read_text(encoding='utf-8')
script = script.replace("r9-next15/local-gate'", "r9-next15/local-gate-attempt02'")
script = script.replace('bfp-r9-next15-windows.exe', 'bfp-r9-next15-attempt02-windows.exe')
script = script.replace('bfp-r9-next15-linux-amd64', 'bfp-r9-next15-attempt02-linux-amd64')
with (ROOT / 'verification/verify-next15-attempt02.py').open('x', encoding='utf-8') as output:
    output.write(script)
# No remote run has started; point its single future freeze at the second
# complete gate. Both the summary and manifest must be from that same attempt.
runner = ROOT / 'verification/run-next15-race.py'
runner.write_text(runner.read_text(encoding='utf-8').replace('r9-next15/local-gate/',
                  'r9-next15/local-gate-attempt02/'), encoding='utf-8')
print('next15 attempt02 helper created; failed first gate and binaries preserved')
