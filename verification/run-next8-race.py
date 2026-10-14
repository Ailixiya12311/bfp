"""One independent offline Linux race gate for the frozen next8 source."""
from pathlib import Path
import json,sys
ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/'.staging/r9-next8'
sys.path.insert(0,str(ROOT/'lab'))
import remote,race
remote.WORKSPACE=race.WORKSPACE=STAGE
race.load_hosts=lambda:remote.load_hosts(inventory=Path(r'C:\Users\developer\Desktop\cold\servers-unredacted.md'))
summary=json.loads((STAGE/'verification/r9-next8/local-gate/local-summary.json').read_text())
digest=next(x['sha256'] for x in summary['binaries'] if x['platform']=='linux')
report,path=race.execute(digest)
print(json.dumps({'run_id':report['run_id'],'pass':report['pass'],'path':str(path)}),flush=True)
raise SystemExit(0 if report['pass'] else 1)
