"""Record the first merged DNS/datagram behavioral checks without a release claim."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next21'
OUT = STAGE / 'verification/combined-directed-attempt01'
DIRS = ('adapter', 'classification', 'cmd', 'gateway', 'internal',
        'obfuscation', 'protocol', 'scheduler', 'security', 'session', 'tests')


def manifest():
    paths = [STAGE / 'go.mod', STAGE / 'go.sum']
    for directory in DIRS:
        paths.extend((STAGE / directory).rglob('*.go'))
    return [{'path': p.relative_to(STAGE).as_posix(),
             'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(paths)]


OUT.mkdir(parents=True, exist_ok=False)
before = manifest()
(OUT / 'source-manifest.json').write_text(json.dumps(before, indent=2) + '\n', encoding='utf-8')
command = ['go', 'test', '-json', '-p', '1', './adapter/dns', './gateway', './session', './scheduler',
           '-run', '^TestDNSFrontend|^TestClientDNSFrontend|^TestLocalAddressLease|^TestDatagramTXNext21|^TestClientCarrierHooksAndAddressScopeCombinedRuntime|^TestClientAddressCreation',
           '-count=1', '-timeout=60s']
with (OUT / 'test.jsonl').open('xb') as output:
    result = subprocess.run(command, cwd=STAGE, env={**os.environ, 'GOTOOLCHAIN': 'local', 'CGO_ENABLED': '0'},
                            stdout=output, stderr=subprocess.STDOUT, timeout=120)
events = []
for line in (OUT / 'test.jsonl').read_text(encoding='utf-8', errors='replace').splitlines():
    try:
        events.append(json.loads(line))
    except ValueError:
        pass
report = {'command': command, 'exit_code': result.returncode,
          'source_unchanged': before == manifest(),
          'top_level_tests_passed': sum(e.get('Action') == 'pass' and 'Test' in e and '/' not in e['Test'] for e in events),
          'failed_tests': [e['Test'] for e in events if e.get('Action') == 'fail' and 'Test' in e],
          'failed_packages': [e['Package'] for e in events if e.get('Action') == 'fail' and 'Test' not in e],
          'scope': 'merged DNS/datagram/factory/hooks directed tests; not complete local gate, race or WAN',
          'acceptance_complete': False, 'production_ready': False, 'released': False}
(OUT / 'summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report), flush=True)
raise SystemExit(result.returncode)
