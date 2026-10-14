"""Recover the original run evidence without re-executing any Go tests."""
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next13'
sys.path.insert(0, str(ROOT / 'lab'))
import remote

RID = '8149b7472a8938a6105c3bd313d6547c'
OUT = STAGE / 'verification/r9-next13/race01-recovery'
OUT.mkdir(parents=True, exist_ok=False)
host = remote.load_hosts(inventory=Path(r'C:\Users\developer\Desktop\cold\servers-unredacted.md'))['receiver']
report = {'run_id': RID, 'original_exception': 'SSH session not active during final after snapshot',
          'original_execution_exit_code': None, 'strict_pass': False,
          'scope': 'recover original artifacts and exact owned resources only; no test rerun',
          'acceptance_complete': False, 'production_ready': False, 'released': False}
with remote.Remote(host) as receiver:
    run = remote.RemoteRun(receiver, RID)
    state = receiver.python("import pathlib,json\np=pathlib.Path(%r)\nprint(json.dumps({'directory_present':p.exists(),'symlink':p.is_symlink()}))" % run.directory)
    report['owned_directory_observation'] = state
    if state['directory_present']:
        inspection = receiver.python(run._check() + """
import subprocess
name='bfp-race-'+rid
v=subprocess.run(['docker','inspect',name],capture_output=True,text=True,timeout=5)
state={'container_present':v.returncode==0,'log_present':(p/'race.log').exists()}
if v.returncode==0:
 data=json.loads(v.stdout)[0]
 if data.get('Config',{}).get('Labels',{}).get('bfp.run')!=rid:raise RuntimeError('owner mismatch')
 state['running']=bool(data.get('State',{}).get('Running'))
 state['exit_code']=data.get('State',{}).get('ExitCode')
print(json.dumps(state))
""")
        report['owned_state'] = inspection
        if inspection.get('log_present'):
            log = run.read('race.log', limit=2097152)
            remote.write_public(OUT / 'recovered-log.json', {'run_id': RID, 'text': log})
            report['recovered_log_bytes'] = len(log.encode('utf-8'))
        if not inspection.get('running'):
            report['cleanup'] = run.cleanup()
        else:
            report['cleanup'] = {'directory_removed': False, 'status': 'confirmed container still running; left intact'}
    report['delayed_receiver_snapshot'] = receiver.snapshot()
remote.write_public(OUT / 'recovery-summary.json', report)
print(json.dumps({k: v for k, v in report.items() if k != 'delayed_receiver_snapshot'}), flush=True)
