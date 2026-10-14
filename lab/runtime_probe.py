"""Read-only Go/GCC/Docker inventory for bounded Linux race feasibility."""
import concurrent.futures
import json

from remote import Remote, SANITIZER, WORKSPACE, load_hosts, new_run_id, write_public

PROBE=r'''
import os,subprocess,json,shutil
def call(argv):
    try:
        p=subprocess.run(argv,capture_output=True,text=True,timeout=8)
        return {'exit_code':p.returncode,'stdout':p.stdout[:65536]}
    except (OSError,subprocess.TimeoutExpired) as error:return {'exit_code':-1,'error_type':type(error).__name__}
sudo=call(['sudo','-n','true']) if os.geteuid()!=0 else {'exit_code':0}
prefix=['sudo','-n'] if os.geteuid()!=0 and sudo['exit_code']==0 else []
images=call(prefix+['docker','images','--format','{{json .}}'])
image_rows=[]
if images['exit_code']==0:
    for line in images['stdout'].splitlines():
        try:
            row=json.loads(line);image_rows.append({k:row.get(k) for k in ('ID','Repository','Tag','Size')})
        except ValueError:pass
runtime={}
for tool,args in [('go',['go','version']),('gcc',['gcc','--version']),('clang',['clang','--version']),('docker',prefix+['docker','version','--format','{{json .}}'])]:
    result=call(args)
    runtime[tool]={'path':shutil.which(tool),'exit_code':result['exit_code'],'version':result.get('stdout','').splitlines()[:2]}
if runtime['go']['exit_code']==0:
    runtime['go']['environment']=call(['go','env','GOOS','GOARCH','CGO_ENABLED','GOVERSION','GOMODCACHE','GOCACHE'])
fs=shutil.disk_usage('/tmp')
print(json.dumps({'runtime':runtime,'docker_images':image_rows,'docker_images_exit':images['exit_code'],'sudo_noninteractive':sudo['exit_code']==0,'tmp_free_bytes':fs.free}))
'''

def main():
    hosts=load_hosts()
    run_id=new_run_id()
    result={'run_id':run_id,'read_only':True,'hosts':{}}
    def probe(host):
        try:
            with Remote(host) as remote:return remote.python(PROBE,timeout=50)
        except Exception as error:return {'error_type':type(error).__name__,'error':SANITIZER.text(str(error))[:1024]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures={role:pool.submit(probe,host) for role,host in hosts.items()}
        result['hosts']={role:future.result() for role,future in futures.items()}
    output=WORKSPACE/'lab'/'runs'/run_id/'runtime-probe.json'
    write_public(output,result)
    print(json.dumps({'path':str(output),**result},ensure_ascii=False))

if __name__=='__main__':main()
