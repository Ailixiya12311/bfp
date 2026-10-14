"""Freeze Go source and dependencies, run offline Linux race in cached image.

No global tools or packages are installed. Local vendor generation happens only
inside this run's source copy. The remote container uses existing image content,
no network/pull, explicit resource limits, and run-owned writable caches.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tarfile
import time

from remote import Remote, RemoteRun, LabError, SANITIZER, WORKSPACE, load_hosts, new_run_id, write_public, compare_snapshots

SOURCE_EXCLUDED_DIRS=frozenset(('bin','dist','docs','lab','verification','third_party','vendor'))


def collect_module_source(workspace):
    """Collect every root-module Go package, including all platforms and tests."""
    workspace=pathlib.Path(workspace)
    files=[]
    for name in ('go.mod','go.sum'):
        path=workspace/name
        if path.is_file():
            if path.is_symlink():raise LabError('linked module metadata is not supported')
            files.append(path)
    for base,directories,names in __import__('os').walk(workspace,followlinks=False):
        base=pathlib.Path(base)
        directories[:]=sorted(name for name in directories
            if not name.startswith(('.', '_'))
            and name not in SOURCE_EXCLUDED_DIRS
            and not (base/name).is_symlink()
            and not (base/name/'go.mod').is_file())
        for name in names:
            if name.endswith('.go'):
                path=base/name
                if path.is_symlink():raise LabError('linked Go source is not supported')
                files.append(path)
    return sorted(files,key=lambda file:file.relative_to(workspace).as_posix())


def owned_usage_bytes(root):
    total = 0
    for base, _, names in __import__('os').walk(root):
        for name in names:
            try:
                total += (pathlib.Path(base) / name).stat().st_size
            except FileNotFoundError:
                # Go may remove a short-lived build artifact between walk and
                # stat. It is not evidence of an over-budget owned tree.
                continue
    return total


def freeze_source(output):
    source=output/'source'
    source.mkdir()
    files=collect_module_source(WORKSPACE)
    manifest=[]
    for file in sorted(files):
        relative=file.relative_to(WORKSPACE)
        data=file.read_bytes()
        destination=source/relative
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(data)
        manifest.append({'path':relative.as_posix(),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    environment=dict(__import__('os').environ,GOPROXY='off',GOSUMDB='off',GOTOOLCHAIN='local')
    result=subprocess.run(['go','mod','vendor'],cwd=source,capture_output=True,text=True,timeout=45,env=environment)
    if result.returncode:
        raise LabError('offline run-copy vendor generation failed: '+SANITIZER.text(result.stderr)[:2048])
    vendor=source/'vendor'
    vendor_hash=hashlib.sha256()
    for file in sorted(vendor.rglob('*')):
        if file.is_file():
            relative=file.relative_to(source).as_posix()
            data=file.read_bytes()
            vendor_hash.update(relative.encode()+b'\0'+hashlib.sha256(data).digest())
    archive=output/'race-source.tar.gz'
    with tarfile.open(archive,'w:gz') as tar:
        for file in sorted(source.rglob('*')):
            if file.is_file():tar.add(file,arcname='source/'+file.relative_to(source).as_posix(),recursive=False)
    if archive.stat().st_size > 64*1024*1024:
        raise LabError('bounded race archive exceeds 64 MiB')
    write_public(output/'source-manifest.json',{'files':manifest,'vendor_tree_sha256':vendor_hash.hexdigest(),'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'archive_bytes':archive.stat().st_size})
    return archive,manifest,vendor_hash.hexdigest()


def execute(binary_hash=None,timeout=360,packages=None):
    if binary_hash is not None and not re.fullmatch(r'[a-fA-F0-9]{64}',binary_hash):
        raise LabError('related binary SHA256 must be exactly 64 hexadecimal characters')
    packages=packages or ['./...']
    for package in packages:
        if package!='./...' and not re.fullmatch(r'\./(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+',package):
            raise LabError('race packages must be module-relative paths without shell syntax')
        if package!='./...' and not (WORKSPACE/package[2:]).is_dir():
            raise LabError('race package does not exist')
    command='go test -race -p 1 '+' '.join(packages)+' -count=1 -timeout=180s'
    run_id=new_run_id()
    output=WORKSPACE/'lab'/'runs'/run_id
    output.mkdir(parents=True,exist_ok=False)
    archive,manifest,vendor_hash=freeze_source(output)
    report={'run_id':run_id,'source_manifest':manifest,'vendor_tree_sha256':vendor_hash,'related_binary_sha256':binary_hash,'image':'ded31c68586d','resource_limits':{'memory':'384m','memory_swap':'768m','cpu':'.75','pids':256},'command':command,'packages':packages,'offline':True,'pass':False}
    started=time.monotonic()
    with Remote(load_hosts()['receiver']) as remote:
        before=remote.snapshot()
        if before['snapshot']['tmp_free_bytes'] < 1024*1024*1024:
            raise LabError('insufficient spare /tmp disk for bounded race build')
        run=RemoteRun(remote,run_id)
        report['created']=run.create()
        try:
            report['archive_upload']=run.write('race-source.tar.gz',archive.read_bytes())
            script=r'''
import tarfile,subprocess,hashlib,time,shutil
def owned_usage_bytes(root):
    total=0
    for base,_,names in os.walk(root):
        for name in names:
            try: total += (pathlib.Path(base)/name).stat().st_size
            except FileNotFoundError: pass
    return total
archive=p/'race-source.tar.gz'
with tarfile.open(archive) as tar:
    for item in tar.getmembers():
        if not item.isfile() or item.issym() or item.islnk() or not item.name.startswith('source/') or '..' in pathlib.PurePosixPath(item.name).parts:raise RuntimeError('unsafe source archive member')
        target=p/item.name
        target.parent.mkdir(parents=True,exist_ok=True)
        with tar.extractfile(item) as source,open(target,'xb') as destination:shutil.copyfileobj(source,destination)
(p/'cache').mkdir();(p/'tmp').mkdir()
name='bfp-race-'+rid
fd=os.open(p/'race.container.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as marker:json.dump({'run_id':rid,'name':name},marker)
args=['docker','run','--pull=never','--name',name,'--label','bfp.run='+rid,'--rm','--network','none','--read-only','--memory','384m','--memory-swap','768m','--cpus','.75','--pids-limit','256','--cap-drop','ALL','--security-opt','no-new-privileges','--mount','type=bind,src='+str(p/'source')+',dst=/src,readonly','--mount','type=bind,src='+str(p/'cache')+',dst=/cache','--mount','type=bind,src='+str(p/'tmp')+',dst=/tmp','-w','/src','-e','GOTOOLCHAIN=local','-e','GOPROXY=off','-e','GOSUMDB=off','-e','GOFLAGS=-mod=vendor','-e','GOCACHE=/cache','-e','TMPDIR=/tmp','-e','GOMAXPROCS=1','ded31c68586d','sh','-c','go version; gcc --version | head -n 1; go test -race -p 1 ./... -count=1 -timeout=180s']
report={'image':'ded31c68586d'}
result=None
fd=os.open(p/'race.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
try:
    with os.fdopen(fd,'wb') as log:
        result=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT)
        deadline=time.monotonic()+%r
        while result.poll() is None:
            used=owned_usage_bytes(p)
            if used>768*1024*1024 or shutil.disk_usage(p).free<512*1024*1024:
                report['storage_limit']=True;break
            if time.monotonic()>deadline:
                report['timeout']=True;break
            time.sleep(1)
        if result.poll() is not None:report['exit_code']=result.returncode
finally:
    inspect=subprocess.run(['docker','inspect','--format','{{json .Config.Labels}}',name],capture_output=True,text=True,timeout=5)
    if inspect.returncode==0:
        labels=json.loads(inspect.stdout)
        if labels.get('bfp.run')!=rid:raise RuntimeError('container owner mismatch')
        stop=subprocess.run(['docker','rm','-f',name],capture_output=True,text=True,timeout=10)
        report['owned_container_removed']=stop.returncode==0
    else:report['owned_container_removed']=True
    if result is not None and result.poll() is None:
        try:result.wait(timeout=5)
        except subprocess.TimeoutExpired:result.terminate();result.wait(timeout=5)
report['log_bytes']=(p/'race.log').stat().st_size
report['disk_usage_bytes']=owned_usage_bytes(p)
print(json.dumps(report))
''' % timeout
            script=script.replace('go test -race -p 1 ./... -count=1 -timeout=180s',command)
            report['execution']=remote.python(run._check()+script,timeout=timeout+30)
            log=run.read('race.log',limit=2097152)
            write_public(output/'race-log.json',{'text':log})
            print(json.dumps({'stage':'race_execution_complete','run_id':run_id,'execution':report['execution'],'log':log[-12000:]}),flush=True)
        except Exception as error:
            report['error_type']=type(error).__name__
            report['error']=SANITIZER.text(str(error))[:2048]
        finally:
            try:report['cleanup']=run.cleanup()
            except Exception as error:report['cleanup']={'directory_removed':False,'error_type':type(error).__name__,'error':SANITIZER.text(str(error))[:2048]}
            # A long race can outlive the SSH channel while the receiver
            # itself remains healthy. Reconnect before the required after
            # snapshot so a transient control-channel loss is recorded as a
            # bounded evidence failure instead of an unstructured traceback.
            try:
                after=remote.snapshot()
            except Exception as error:
                try:
                    remote.close()
                    remote.connect()
                    after=remote.snapshot()
                except Exception as retry_error:
                    report['snapshot_error']={'first':SANITIZER.text(str(error))[:2048], 'retry':SANITIZER.text(str(retry_error))[:2048]}
                    after=None
            if after is not None:
                report['snapshot_comparison']=compare_snapshots(before,after)
                report['snapshots']={'receiver':{'before':before,'after':after,'comparison':report['snapshot_comparison']}}
            else:
                report['snapshot_comparison']={'unchanged':False,'changes':{},'error':'after snapshot unavailable'}
            report['pass']=report.get('execution',{}).get('exit_code')==0 and report['execution'].get('owned_container_removed') and report['cleanup'].get('directory_removed') and report['snapshot_comparison']['unchanged']
    report['elapsed_seconds']=round(time.monotonic()-started,3)
    write_public(output/'race-result.json',report)
    return report,output/'race-result.json'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary-sha256')
    parser.add_argument('--timeout',type=int,default=360)
    parser.add_argument('--package',action='append',dest='packages',help='module-relative package to check; repeat for more packages; default ./...')
    args=parser.parse_args()
    try:
        result,path=execute(args.binary_sha256,args.timeout,args.packages)
        print(json.dumps({'stage':'complete','pass':result['pass'],'run_id':result['run_id'],'path':str(path),'error':result.get('error')},ensure_ascii=False),flush=True)
        return 0 if result['pass'] else 1
    except Exception as error:
        print(json.dumps({'pass':False,'error_type':type(error).__name__,'error':SANITIZER.text(str(error))[:2048]},ensure_ascii=False),flush=True)
        return 1


if __name__=='__main__':raise SystemExit(main())
