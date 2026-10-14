"""Single source-bound Linux race; persist baselines before uploads/tests."""
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next19'
sys.path.insert(0, str(ROOT / 'lab'))
import remote
import race

remote.WORKSPACE = race.WORKSPACE = STAGE
race.load_hosts = lambda: remote.load_hosts(inventory=Path(r'C:\Users\developer\Desktop\cold\servers-unredacted.md'))
summary = json.loads((STAGE / 'verification/r9-next19/local-gate-attempt01/local-summary.json').read_text(encoding='utf-8'))
if not summary.get('local_checks_pass') or not summary.get('source_unchanged'):
    raise RuntimeError('next19 frozen full local gate must pass before remote race')
frozen = json.loads((STAGE / 'verification/r9-next19/local-gate-attempt01/source-manifest.json').read_text(encoding='utf-8'))
original_freeze = race.freeze_source
def bound_freeze(output):
    result = original_freeze(output)
    rows = [{'path': row['path'], 'sha256': row['sha256']} for row in result[1]]
    if rows != frozen['source_manifest']:
        raise RuntimeError('race source copy differs from frozen next19 local gate')
    return result
race.freeze_source = bound_freeze
OUT = STAGE / 'verification/r9-next19/race-snapshots-attempt01'
OUT.mkdir(parents=True, exist_ok=False)

# Only process identity/config fingerprints are returned, never command line
# or config contents. This explains endpoint observations, not continuous
# process/config identity or why unrelated dynamic UDP sockets changed.
IDENTITY = r'''
import os,json,hashlib,pathlib,re
records=[]
def digest_file(path,limit):
    try:
        with open(path,'rb') as f:
            data=f.read(limit+1)
        if len(data)>limit:return {'status':'size_limit'}
        return {'status':'ok','sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
    except (OSError,ValueError):return {'status':'unavailable'}
for name in os.listdir('/proc'):
    if not name.isdigit():continue
    p=pathlib.Path('/proc')/name
    try:
        if (p/'comm').read_text().strip()!='xray':continue
        stat=(p/'stat').read_text();tail=stat[stat.rfind(')')+2:].split()
        raw=(p/'cmdline').read_bytes();args=[s.decode('utf-8','replace') for s in raw.split(b'\0') if s]
        configs=[];directories=[]
        for i,arg in enumerate(args):
            if arg in ('-c','-config','--config') and i+1<len(args):configs.append(args[i+1])
            if arg in ('-confdir','--confdir') and i+1<len(args):directories.append(args[i+1])
            if arg.startswith(('-config=','--config=')):configs.append(arg.split('=',1)[1])
        for directory in directories:
            try:configs.extend(str(q) for q in sorted(pathlib.Path(directory).glob('*.json'))[:64])
            except OSError:pass
        cwd=os.readlink(p/'cwd');entries=[]
        for path in sorted(set(configs))[:64]:
            resolved=path if os.path.isabs(path) else os.path.join(cwd,path)
            entries.append({'path_sha256':hashlib.sha256(resolved.encode()).hexdigest(),**digest_file(resolved,2*1024*1024)})
        records.append({'pid':int(name),'start_ticks':int(tail[19]),'cmdline_sha256':hashlib.sha256(raw).hexdigest(),'executable':digest_file(p/'exe',64*1024*1024),'config_fingerprints':entries,'config_paths_discovered':len(configs)})
    except (OSError,ValueError,IndexError):records.append({'pid':int(name),'status':'unavailable'})
print(json.dumps({'processes':sorted(records,key=lambda x:x['pid']),'scope':'xray endpoint fingerprints only; no contents; no continuous identity proof'}))
'''

class AuditedRemote(remote.Remote):
    snapshots = 0
    def snapshot(self):
        value = super().snapshot()
        value['xray_identity_observation'] = self.python(IDENTITY, timeout=20)
        phase = 'before' if self.snapshots == 0 else 'after'
        self.snapshots += 1
        with (OUT / (phase + '.json')).open('x', encoding='utf-8') as output:
            json.dump(value, output, indent=2)
            output.write('\n')
        return value

race.Remote = AuditedRemote
digest = next(x['sha256'] for x in summary['binaries'] if x['platform'] == 'linux')
report, path = race.execute(digest)
print(json.dumps({'run_id': report['run_id'], 'pass': report['pass'], 'path': str(path)}), flush=True)
raise SystemExit(0 if report['pass'] else 1)





