import hashlib,json,pathlib,subprocess,sys
sys.path.insert(0,'lab')
from remote import Remote,RemoteRun,load_hosts,new_run_id,write_public,compare_snapshots
root=pathlib.Path.cwd(); binary=root/'dist/BFP-0.1.0-preview.5/bin/bfp-linux-amd64'
run_id=new_run_id(); output=root/'lab/runs'/run_id; output.mkdir(parents=True,exist_ok=False)
report={'run_id':run_id,'scope':'exact packaged Linux binary; loopback demo and real CLI DNS/SOCKS TCP/UDP; no Singapore traffic','binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'pass':False}
with Remote(load_hosts()['receiver']) as remote:
    before=remote.snapshot(); run=RemoteRun(remote,run_id); report['created']=run.create()
    try:
        report['upload']=run.write('bfp',binary.read_bytes(),0o700)
        source=run._check()+"import subprocess,hashlib\nchecks=[]\nfor command in ('version','demo'):\n    result=subprocess.run([str(p/'bfp'),command],capture_output=True,text=True,timeout=20,cwd=p)\n    checks.append({'command':command,'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr})\nprint(json.dumps({'checks':checks,'binary_sha256':hashlib.sha256((p/'bfp').read_bytes()).hexdigest()}))\n"
        report['runtime']=remote.python(source,timeout=45)
        report['checker_upload']=run.write('packaged_dns_smoke.py',(root/'verification/product-edns/packaged_dns_smoke.py').read_bytes(),0o600)
        native=run._check()+r'''
import subprocess
(p/'runtime').mkdir(mode=0o700)
name='bfp-race-'+rid
fd=os.open(p/'product.container.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as stream:json.dump({'run_id':rid,'name':name},stream)
args=['docker','run','--pull=never','--name',name,'--label','bfp.run='+rid,'--rm','--network','none','--read-only','--memory','192m','--memory-swap','192m','--cpus','.50','--pids-limit','128','--cap-drop','ALL','--security-opt','no-new-privileges','--mount','type=bind,src='+str(p)+',dst=/artifact,readonly','--mount','type=bind,src='+str(p/'runtime')+',dst=/scratch','-e','GOMAXPROCS=1','ded31c68586d','python3','/artifact/packaged_dns_smoke.py','--binary','/artifact/bfp','--work-dir','/scratch']
obj={}
try:
    result=subprocess.run(args,capture_output=True,text=True,timeout=60)
    try:obj=json.loads(result.stdout)
    except ValueError:obj={'pass':False,'checker_error':result.stderr[-1024:]}
    obj['native_container_exit_code']=result.returncode
    obj['network_namespace']='owned network-none container; IPv4 and IPv6 loopback'
finally:
    inspected=subprocess.run(['docker','inspect','--format','{{json .Config.Labels}}',name],capture_output=True,text=True,timeout=5)
    if inspected.returncode==0:
        labels=json.loads(inspected.stdout)
        if labels.get('bfp.run')!=rid:raise RuntimeError('native container owner mismatch')
        removed=subprocess.run(['docker','rm','-f',name],capture_output=True,text=True,timeout=10)
        obj['native_container_removed']=removed.returncode==0
    else:obj['native_container_removed']=True
print(json.dumps(obj))
'''
        report['dns_runtime']=remote.python(native,timeout=80)
    finally:
        report['cleanup']=run.cleanup()
        after=remote.snapshot(); report['snapshot_comparison']=compare_snapshots(before,after)
    checks=report.get('runtime',{}).get('checks',[])
    demos=[json.loads(c['stdout']) for c in checks if c['command']=='demo' and c['exit_code']==0]
    report['pass']=len(checks)==2 and all(c['exit_code']==0 for c in checks) and len(demos)==1 and demos[0].get('event')=='demo_pass' and report['runtime']['binary_sha256']==report['binary_sha256'] and report['cleanup'].get('directory_removed') and report['snapshot_comparison']['unchanged'] and report['dns_runtime'].get('pass') and report['dns_runtime'].get('ephemeral_files_removed') is True and report['dns_runtime'].get('all_processes_stopped') is True and report['dns_runtime'].get('native_container_exit_code')==0 and report['dns_runtime'].get('native_container_removed') is True
write_public(output/'product-smoke.json',report)
print(json.dumps({'run_id':run_id,'pass':report['pass'],'binary_sha256':report['binary_sha256'],'checks':report.get('runtime',{}).get('checks',[]),'dns_runtime':report.get('dns_runtime'),'cleanup':report['cleanup'].get('directory_removed'),'baseline_unchanged':report['snapshot_comparison']['unchanged'],'path':str(output/'product-smoke.json')},ensure_ascii=False))
sys.exit(0 if report['pass'] else 1)
