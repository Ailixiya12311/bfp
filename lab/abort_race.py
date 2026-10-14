"""Stop only an exact owned race container; let its runner collect/clean up."""
import argparse
import json

from remote import Remote, RemoteRun, WORKSPACE, load_hosts, write_public

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    parser.add_argument('--reason',required=True)
    args=parser.parse_args()
    with Remote(load_hosts()['receiver']) as remote:
        run=RemoteRun(remote,args.run_id)
        result=remote.python(run._check()+r'''
import subprocess
m=json.loads((p/'race.container.json').read_text())
name='bfp-race-'+rid
if m.get('name')!=name or m.get('run_id')!=rid:raise RuntimeError('race marker mismatch')
inspect=subprocess.run(['docker','inspect',name],capture_output=True,text=True,timeout=5)
report={'run_id':rid,'container':name,'stopped':False}
if inspect.returncode==0:
    data=json.loads(inspect.stdout)[0]
    if data.get('Config',{}).get('Labels',{}).get('bfp.run')!=rid:raise RuntimeError('container owner mismatch')
    for mount in data.get('Mounts',[]):
        if mount.get('Type')=='bind' and not pathlib.Path(mount.get('Source','')).is_relative_to(p):raise RuntimeError('container mount mismatch')
    stop=subprocess.run(['docker','rm','-f',name],capture_output=True,text=True,timeout=10)
    report['stopped']=stop.returncode==0
else:report['already_exited']=True
print(json.dumps(report))
''')
    result['reason']=args.reason
    write_public(WORKSPACE/'lab'/'runs'/args.run_id/'aborted-attempt.json',result)
    print(json.dumps(result))

if __name__=='__main__':main()
