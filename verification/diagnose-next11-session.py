"""One streamed Session-only investigation; never an acceptance rerun."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next11'
OUT = STAGE / 'verification/session-timeout-diagnostic-attempt-01'
OUT.mkdir(parents=True, exist_ok=False)
frozen = json.loads((STAGE/'verification/r9-next11/local-gate/source-manifest.json').read_text(encoding='utf-8'))
def unchanged():
    return all(hashlib.sha256((STAGE/r['path']).read_bytes()).hexdigest()==r['sha256'] for r in frozen['source_manifest'])
if not unchanged():
    raise RuntimeError('frozen next11 source changed')
command = ['go','test','-json','-p','1','./session','-count=1','-timeout=180s']
report = {'purpose':'Diagnose which Session tests or cleanup consume time after the original full gate outer timeout. Not an acceptance rerun; original full gate remains incomplete/failed.',
          'command':command, 'source_manifest_sha256':frozen['manifest_sha256'], 'acceptance_complete':False,'production_ready':False,'released':False}
started=time.monotonic()
with (OUT/'go-test.jsonl').open('xb') as log:
    try:
        result=subprocess.run(command,cwd=STAGE,env=dict(os.environ,GOTOOLCHAIN='local',CGO_ENABLED='0'),stdout=log,stderr=subprocess.STDOUT,timeout=240)
        report['exit_code']=result.returncode
    except subprocess.TimeoutExpired:
        report['outer_timeout_seconds']=240
        report['exit_code']=None
events=[]
for line in (OUT/'go-test.jsonl').read_text(encoding='utf-8',errors='replace').splitlines():
    try: events.append(json.loads(line))
    except ValueError: pass
terminal={(e.get('Package'),e.get('Test')) for e in events if e.get('Action') in ('pass','fail','skip') and 'Test'in e}
report['tests_without_terminal_event']=[e['Test'] for e in events if e.get('Action')=='run' and 'Test'in e and (e.get('Package'),e['Test'])not in terminal]
report['failed_tests']=[e['Test'] for e in events if e.get('Action')=='fail' and 'Test'in e]
report['panic_events']=[e['Output'].strip() for e in events if 'panic:'in e.get('Output','')]
report['top_level_tests_passed']=sum(e.get('Action')=='pass' and 'Test'in e and '/'not in e['Test'] for e in events)
report['elapsed_seconds']=round(time.monotonic()-started,3)
report['source_unchanged']=unchanged()
with (OUT/'summary.json').open('x',encoding='utf-8') as output: output.write(json.dumps(report,indent=2)+'\n')
print(json.dumps(report),flush=True)
