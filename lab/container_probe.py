"""Probe only an existing cached Go image in an owned bounded container."""
import json

from remote import Remote, SANITIZER, WORKSPACE, load_hosts, new_run_id, write_public, compare_snapshots


def main():
    run_id=new_run_id()
    image='ded31c68586d'
    name='bfp-runtime-'+run_id
    with Remote(load_hosts()['receiver']) as remote:
        before=remote.snapshot()
        result=remote.python(r'''
import subprocess,json
name=%r
rid=%r
image=%r
args=['docker','run','--pull=never','--name',name,'--label','bfp.run='+rid,'--rm','--network','none','--read-only','--memory','256m','--memory-swap','256m','--cpus','0.5','--pids-limit','64','--cap-drop','ALL','--security-opt','no-new-privileges','--tmpfs','/tmp:rw,noexec,nosuid,size=16m',image,'sh','-c','go version; gcc --version | head -n 1; go env GOOS GOARCH CGO_ENABLED GOVERSION']
try:
    p=subprocess.run(args,capture_output=True,text=True,timeout=15)
    report={'image':image,'exit_code':p.returncode,'stdout':p.stdout[:8192],'stderr':p.stderr[:2048]}
except subprocess.TimeoutExpired:
    report={'image':image,'error_type':'TimeoutExpired'}
finally:
    inspect=subprocess.run(['docker','inspect','--format','{{json .Config.Labels}}',name],capture_output=True,text=True,timeout=5)
    if inspect.returncode==0:
        labels=json.loads(inspect.stdout)
        if labels.get('bfp.run')!=rid:raise RuntimeError('container owner mismatch')
        stop=subprocess.run(['docker','rm','-f',name],capture_output=True,text=True,timeout=10)
        report['owned_container_removed']=stop.returncode==0
    else:report['owned_container_removed']=True
print(json.dumps(report))
''' % (name,run_id,image),timeout=40)
        after=remote.snapshot()
    result['baseline_comparison']=compare_snapshots(before,after)
    result['run_id']=run_id
    output=WORKSPACE/'lab'/'runs'/run_id/'container-runtime.json'
    write_public(output,result)
    print(json.dumps({'path':str(output),**result},ensure_ascii=False))


if __name__=='__main__':main()
