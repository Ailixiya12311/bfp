"""One offline, source-bound next25 Linux race with separate build/test budgets.

Importing this file does not read credentials, freeze source, or connect to a
host. --check-only validates the completed local gate without remote work.
Normal execution reserves one attempt, compiles race-enabled tests without
running them, then runs the full suite once in the same owned container/cache.
Historical lab/race.py and previous attempts remain unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".staging/r9-next25"
GATE = STAGE / "verification/r9-next25/local-gate-attempt01"
REVISION = "v0.1-r9-next25"
RECEIVER = "192.0.2.10"
IMAGE = "ded31c68586d"
INVENTORY = Path(r"C:\Users\developer\Desktop\cold\servers-unredacted.md")
SOURCE_DIRS = (
    "adapter", "classification", "clientconfig", "cmd", "gateway", "internal",
    "obfuscation", "protocol", "scheduler", "security", "session", "tests",
)
PREP_COMMAND = ["go", "test", "-race", "-p", "1", "-run", "^$", "./..."]
RACE_COMMAND = [
    "go", "test", "-race", "-json", "-p", "1", "./...", "-count=1", "-timeout=240s",
]
PREP_SECONDS = 360
RACE_SECONDS = 420
OBSERVATION_GRACE_SECONDS = 90
LOG_LIMIT = 16 * 1024 * 1024

sys.path.insert(0, str(ROOT / "lab"))
import remote  # noqa: E402


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(rows) -> str:
    return sha256((json.dumps(rows, sort_keys=True, indent=2) + "\n").encode())


def source_paths():
    paths = [STAGE / "go.mod", STAGE / "go.sum"]
    for directory in SOURCE_DIRS:
        paths.extend((STAGE / directory).rglob("*.go"))
    for path in paths:
        if path.is_symlink() or not path.resolve().is_relative_to(STAGE.resolve()):
            raise remote.LabError("source is outside the candidate boundary")
    return sorted(paths)


def current_manifest():
    return [{"path": path.relative_to(STAGE).as_posix(), "sha256": sha256(path.read_bytes())}
            for path in source_paths()]


def load_binding():
    manifest_path = GATE / "source-manifest.json"
    summary_path = GATE / "local-summary.json"
    manifest_bytes = manifest_path.read_bytes()
    summary_bytes = summary_path.read_bytes()
    frozen = json.loads(manifest_bytes)
    summary = json.loads(summary_bytes)
    rows = frozen.get("source_manifest", [])
    if frozen.get("revision") != REVISION or summary.get("revision") != REVISION:
        raise remote.LabError("local gate is not the next25 revision")
    if not rows or rows != current_manifest():
        raise remote.LabError("next25 source differs from its frozen local gate")
    if not any(row["path"].startswith("clientconfig/") for row in rows):
        raise remote.LabError("the local gate must include clientconfig")
    digest = canonical_digest(rows)
    if (frozen.get("file_count") != len(rows)
            or summary.get("source_file_count") != len(rows)
            or frozen.get("manifest_sha256") != digest
            or summary.get("source_manifest_sha256") != digest):
        raise remote.LabError("local source-manifest count/digest mismatch")
    if (summary.get("local_checks_pass") is not True
            or summary.get("source_unchanged") is not True
            or summary.get("module_network_disabled") is not True):
        raise remote.LabError("next25 requires a passing, unchanged offline local gate")
    for name in ("go_test", "go_vet", "build_windows", "build_linux"):
        check = summary.get("checks", {}).get(name, {})
        if check.get("pass") is not True or check.get("exit_code") != 0 or check.get("outer_timeout"):
            raise remote.LabError("next25 local check is incomplete: " + name)
    local_tests = summary["checks"]["go_test"]
    if any(local_tests.get(name) for name in (
        "failed_tests", "failed_packages", "tests_without_terminal_event", "panic_events",
    )):
        raise remote.LabError("local tests have failed or unfinished events")
    binaries = [row for row in summary.get("binaries", []) if row.get("platform") == "linux"]
    if len(binaries) != 1 or not re.fullmatch(r"[a-f0-9]{64}", binaries[0].get("sha256", "")):
        raise remote.LabError("local gate must bind one Linux binary SHA256")
    binary = (ROOT / binaries[0]["path"]).resolve()
    if not binary.is_relative_to(GATE.resolve()):
        raise remote.LabError("related Linux binary is outside the local gate")
    binary_data = binary.read_bytes()
    if binary_data[:4] != b"\x7fELF" or sha256(binary_data) != binaries[0]["sha256"]:
        raise remote.LabError("related Linux binary is not the frozen ELF artifact")
    return {
        "revision": REVISION,
        "rows": rows,
        "source_file_count": len(rows),
        "source_manifest_sha256": digest,
        "local_manifest_file_sha256": sha256(manifest_bytes),
        "local_summary_file_sha256": sha256(summary_bytes),
        "related_binary": binaries[0],
        "clientconfig_included": True,
    }


def freeze_source(output: Path, binding):
    source = output / "source"
    source.mkdir()
    rows = []
    for row in binding["rows"]:
        relative = PurePosixPath(row["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise remote.LabError("unsafe path in the frozen source manifest")
        data = (STAGE / row["path"]).read_bytes()
        if sha256(data) != row["sha256"]:
            raise remote.LabError("candidate changed while freezing the race copy")
        destination = source / row["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        rows.append({**row, "bytes": len(data)})
    environment = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOWORK="off")
    result = subprocess.run(["go", "mod", "vendor"], cwd=source, env=environment,
                            capture_output=True, text=True, timeout=45)
    remote.write_public(output / "vendor-preparation.json", {
        "command": ["go", "mod", "vendor"], "exit_code": result.returncode,
        "stdout": result.stdout, "stderr": result.stderr, "offline": True,
    })
    if result.returncode:
        raise remote.LabError("offline vendor preparation failed; see vendor-preparation.json")
    for row in rows:
        if sha256((source / row["path"]).read_bytes()) != row["sha256"]:
            raise remote.LabError("vendor preparation changed frozen module/source files")
    vendor_hash = hashlib.sha256()
    vendor_files = sorted((path.relative_to(source).as_posix(), path)
                          for path in (source / "vendor").rglob("*") if path.is_file())
    for relative, path in vendor_files:
        vendor_hash.update(relative.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    archive = output / "race-source.tar.gz"
    with tarfile.open(archive, "x:gz") as tar:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                if path.is_symlink():
                    raise remote.LabError("symlinks are not allowed in the frozen archive")
                tar.add(path, arcname="source/" + path.relative_to(source).as_posix(), recursive=False)
    if archive.stat().st_size > 64 * 1024 * 1024:
        raise remote.LabError("source archive exceeds the 64 MiB upload limit")
    manifest = {
        "files": rows, "vendor_tree_sha256": vendor_hash.hexdigest(),
        "archive_sha256": sha256(archive.read_bytes()), "archive_bytes": archive.stat().st_size,
    }
    remote.write_public(output / "source-manifest.json", manifest)
    remote.write_public(output / "source-bound.json", {
        **binding, **manifest, "source_unchanged_before_upload": load_binding() == binding,
    })
    if load_binding() != binding:
        raise remote.LabError("local source/binary/gate binding changed before upload")
    return archive, manifest


IDENTITY = r'''
import hashlib,json,os,pathlib
records=[]
def digest_file(path,limit):
    try:
        with path.open('rb') as stream:data=stream.read(limit+1)
        if len(data)>limit:return {'status':'size_limit'}
        return {'status':'ok','sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
    except (OSError,ValueError):return {'status':'unavailable'}
for name in os.listdir('/proc'):
    if not name.isdigit():continue
    process=pathlib.Path('/proc')/name
    identified=False
    try:
        if (process/'comm').read_text().strip()!='xray':continue
        identified=True
        raw=(process/'cmdline').read_bytes()
        records.append({'pid':int(name),'cmdline_sha256':hashlib.sha256(raw).hexdigest(),
                        'executable':digest_file(process/'exe',64*1024*1024)})
    except (OSError,ValueError):
        if identified:records.append({'pid':int(name),'status':'unavailable'})
print(json.dumps({'processes':sorted(records,key=lambda row:row['pid']),
                  'scope':'xray endpoint fingerprints only; no contents; no continuous identity proof'}))
'''


class AuditedRemote(remote.Remote):
    def snapshot(self):
        value = super().snapshot()
        value["xray_identity_observation"] = self.python(IDENTITY, timeout=20)
        return value


# This helper is passed to Remote.python only after local freeze and ownership
# setup. It persists phase boundaries before doing work, and is never rerun.
EXECUTION = r'''
import hashlib,subprocess,tarfile,time,shutil
spec=json.loads((p/'race-spec.json').read_text())
name='bfp-race-'+rid
report={'image':spec['image'],'compile_preparation':{'status':'not_run'},
        'run_id':rid,'full_race':{'status':'not_run','attempts':0},'complete':False}
helper=pathlib.Path('/proc')/str(os.getpid())
report['helper_handle']={'pid':os.getpid(),
                         'starttime':(helper/'stat').read_text().rsplit(')',1)[1].split()[19],
                         'command_sha256':hashlib.sha256((helper/'cmdline').read_bytes()).hexdigest(),
                         'exe':str((helper/'exe').resolve())}
def persist():
    temporary=p/'execution.json.tmp'
    temporary.write_text(json.dumps(report,sort_keys=True)+'\n')
    os.chmod(temporary,0o600)
    os.replace(temporary,p/'execution.json')
def usage():
    total=0
    for base,_,names in os.walk(p):
        for entry in names:
            try:total+=(pathlib.Path(base)/entry).stat().st_size
            except FileNotFoundError:pass
    return total
def ownership():
    if p.is_symlink() or str(p.resolve())!=str(p):raise RuntimeError('unsafe owned directory')
    owner=json.loads((p/'owner.json').read_text())
    if owner.get('run_id')!=rid or owner.get('host')!=spec['receiver']:
        raise RuntimeError('run owner changed')
def inspection():
    result=subprocess.run(['docker','container','inspect',name],capture_output=True,text=True,timeout=5)
    if result.returncode:
        if 'No such container' in result.stderr or 'No such object' in result.stderr:return None
        raise RuntimeError('cannot establish container identity/absence')
    entries=json.loads(result.stdout)
    if len(entries)!=1:raise RuntimeError('container inspection mismatch')
    item=entries[0]
    if item.get('Config',{}).get('Labels',{}).get('bfp.run')!=rid:
        raise RuntimeError('container ownership label mismatch')
    expected={'/src':str(p/'source'),'/cache':str(p/'cache'),'/tmp':str(p/'tmp')}
    binds={mount['Destination']:mount for mount in item.get('Mounts',[]) if mount.get('Type')=='bind'}
    if set(binds)!=set(expected):raise RuntimeError('container mount set mismatch')
    for destination,path in expected.items():
        mount=binds[destination]
        if mount.get('Source')!=path or not pathlib.Path(path).is_relative_to(p):
            raise RuntimeError('container mount ownership mismatch')
        if destination=='/src' and mount.get('RW'):raise RuntimeError('source mount is writable')
    return item
def remove_container():
    ownership()
    if inspection() is None:return True
    stopped=subprocess.run(['docker','rm','-f',name],capture_output=True,text=True,timeout=10)
    if stopped.returncode:raise RuntimeError('owned container removal failed')
    return inspection() is None
def phase(key,command,budget,log_name):
    ownership()
    item=inspection()
    if item is None or not item.get('State',{}).get('Running'):
        raise RuntimeError('owned container is not running')
    state={'status':'running','command':command,'outer_budget_seconds':budget,
           'attempts':1,'exit_code':None,'timeout':False,'storage_limit':False,'pass':False}
    report[key]=state
    persist()
    started=time.monotonic()
    proc=None
    fd=os.open(p/log_name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,'wb') as log:
            proc=subprocess.Popen(['docker','exec',name]+command,stdin=subprocess.DEVNULL,
                                  stdout=log,stderr=subprocess.STDOUT)
            deadline=started+budget
            while proc.poll() is None:
                if usage()>768*1024*1024 or shutil.disk_usage(p).free<512*1024*1024:
                    state['storage_limit']=True
                    break
                if time.monotonic()>=deadline:
                    state['timeout']=True
                    break
                time.sleep(1)
            if proc.poll() is not None:state['exit_code']=proc.returncode
            if state['timeout'] or state['storage_limit']:
                report['owned_container_removed']=remove_container()
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait(timeout=5)
                state['observed_exit_after_stop']=proc.returncode
        state['status']='finished'
        state['elapsed_seconds']=round(time.monotonic()-started,3)
        state['log_bytes']=(p/log_name).stat().st_size
        state['pass']=state['exit_code']==0 and not state['timeout'] and not state['storage_limit']
    except Exception as error:
        state['status']='error'
        state['error_type']=type(error).__name__
        # No shell output/exception text can include unrelated host data.
        if proc is not None and proc.poll() is None:
            report['owned_container_removed']=remove_container()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
        raise
    finally:persist()
    return state['pass']
persist()
try:
    ownership()
    archive=p/'race-source.tar.gz'
    if sha256_expected:=spec.get('archive_sha256'):
        if hashlib.sha256(archive.read_bytes()).hexdigest()!=sha256_expected:
            raise RuntimeError('uploaded source archive digest mismatch')
    else:raise RuntimeError('source archive binding missing')
    expanded=0
    members=set()
    with tarfile.open(archive) as tar:
        for member in tar:
            relative=pathlib.PurePosixPath(member.name)
            if (not member.isfile() or member.issym() or member.islnk() or relative.is_absolute()
                    or '..' in relative.parts or not relative.parts or relative.parts[0]!='source'
                    or member.name in members):raise RuntimeError('unsafe source archive member')
            members.add(member.name)
            expanded+=member.size
            if member.size>64*1024*1024 or expanded>256*1024*1024 or len(members)>50000:
                raise RuntimeError('source extraction exceeds bounded budget')
            target=p/member.name
            target.parent.mkdir(parents=True,exist_ok=True)
            with tar.extractfile(member) as incoming,open(target,'xb') as destination:
                shutil.copyfileobj(incoming,destination)
    source=p/'source'
    expected={row['path'] for row in spec['files']}
    actual={path.relative_to(source).as_posix() for path in source.rglob('*')
            if path.is_file() and not path.relative_to(source).as_posix().startswith('vendor/')}
    if actual!=expected:raise RuntimeError('uploaded source file set mismatch')
    for row in spec['files']:
        data=(source/row['path']).read_bytes()
        if len(data)!=row['bytes'] or hashlib.sha256(data).hexdigest()!=row['sha256']:
            raise RuntimeError('uploaded source differs from local gate')
    vendor_hash=hashlib.sha256()
    vendor_files=sorted((path.relative_to(source).as_posix(),path)
                        for path in (source/'vendor').rglob('*') if path.is_file())
    for relative,path in vendor_files:
        vendor_hash.update(relative.encode()+b'\0'+hashlib.sha256(path.read_bytes()).digest())
    if vendor_hash.hexdigest()!=spec['vendor_tree_sha256']:
        raise RuntimeError('uploaded vendor tree digest mismatch')
    report['upload_binding_verified']=True
    report['archive_sha256']=spec['archive_sha256']
    report['vendor_tree_sha256']=spec['vendor_tree_sha256']
    (p/'cache').mkdir()
    (p/'tmp').mkdir()
    fd=os.open(p/'race.container.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as marker:json.dump({'run_id':rid,'name':name},marker)
    args=['docker','run','-d','--pull=never','--name',name,'--label','bfp.run='+rid,
          '--network','none','--read-only','--memory','384m','--memory-swap','768m',
          '--cpus','.75','--pids-limit','256','--cap-drop','ALL',
          '--security-opt','no-new-privileges',
          '--mount','type=bind,src='+str(source)+',dst=/src,readonly',
          '--mount','type=bind,src='+str(p/'cache')+',dst=/cache',
          '--mount','type=bind,src='+str(p/'tmp')+',dst=/tmp','-w','/src']
    for variable in ('GOTOOLCHAIN=local','GOPROXY=off','GOSUMDB=off','GOFLAGS=-mod=vendor',
                     'GOCACHE=/cache','TMPDIR=/tmp','GOMAXPROCS=1','CGO_ENABLED=1','GOWORK=off'):
        args+=['-e',variable]
    args += [spec['image'],'sh','-c','exec sleep 900']
    created=subprocess.run(args,capture_output=True,text=True,timeout=20)
    if created.returncode:raise RuntimeError('owned container startup failed')
    item=inspection()
    config=item['HostConfig']
    if (config.get('NetworkMode')!='none' or not config.get('ReadonlyRootfs')
            or config.get('Memory')!=384*1024*1024 or config.get('MemorySwap')!=768*1024*1024
            or config.get('NanoCpus')!=750000000 or config.get('PidsLimit')!=256
            or 'ALL' not in config.get('CapDrop',[])
            or not any(option in ('no-new-privileges','no-new-privileges=true','no-new-privileges:true')
                       for option in config.get('SecurityOpt',[]))):
        raise RuntimeError('container resource/isolation constraints differ from request')
    report['container_id']=item['Id']
    report['resolved_image']=item['Image']
    report['toolchain']={}
    for key,command in (('go',['go','version']),('gcc',['gcc','--version'])):
        version=subprocess.run(['docker','exec',name]+command,
                               capture_output=True,text=True,timeout=10)
        report['toolchain'][key]={'exit_code':version.returncode,'text':version.stdout[:8192]}
        if version.returncode:raise RuntimeError('race toolchain is not available offline')
    if phase('compile_preparation',spec['prep_command'],spec['prep_seconds'],'compile.log'):
        phase('full_race',spec['race_command'],spec['race_seconds'],'race.log')
    else:report['full_race']['reason']='compile preparation did not pass'
except Exception as error:
    report['error_type']=type(error).__name__
    report['error']=str(error)[:1024]
finally:
    try:report['owned_container_removed']=remove_container()
    except Exception as error:
        report['owned_container_removed']=False
        report['container_cleanup_error_type']=type(error).__name__
    report['disk_usage_bytes']=usage()
    report['complete']=True
    persist()
print(json.dumps(report))
'''


OBSERVATION = r'''
import hashlib
state=p/'execution.json'
if not state.exists():
    print(json.dumps({'state':'waiting_for_handle','terminal':False}))
else:
    with state.open('rb') as stream:data=stream.read(131073)
    if len(data)>131072:raise RuntimeError('execution observation exceeds bounded limit')
    execution=json.loads(data)
    if execution.get('run_id')!=rid:raise RuntimeError('execution result run ownership mismatch')
    handle=execution.get('helper_handle',{})
    result={'execution':execution,'terminal':False}
    if execution.get('complete') is True:
        result.update({'state':'completed','terminal':True})
    elif not isinstance(handle.get('pid'),int) or handle['pid']<1 or not handle.get('starttime'):
        result['state']='handle_unavailable'
    else:
        process=pathlib.Path('/proc')/str(handle['pid'])
        try:
            fields=(process/'stat').read_text().rsplit(')',1)[1].split()
            same=(fields[19]==handle['starttime']
                  and hashlib.sha256((process/'cmdline').read_bytes()).hexdigest()==handle['command_sha256']
                  and str((process/'exe').resolve())==handle['exe'])
            if not same or fields[0] in ('Z','X','x'):
                result.update({'state':'exact_handle_missing','terminal':True})
            else:result['state']='exact_handle_live'
        except (FileNotFoundError,ProcessLookupError):
            result.update({'state':'exact_handle_missing','terminal':True})
        except OSError:
            result['state']='handle_observation_unavailable'
    print(json.dumps(result))
'''


def observe_same_execution(observer, run, output, deadline):
    """Observe the original helper; a channel timeout never restarts the work."""
    last = {"state": "observation_unavailable", "terminal": False}
    previous = None
    expected_handle = None
    while time.monotonic() < deadline:
        try:
            if observer.client is None:
                observer.connect()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            observed = observer.python(run._check() + OBSERVATION, timeout=min(20, remaining))
            handle = observed.get("execution", {}).get("helper_handle")
            if expected_handle is not None and handle != expected_handle:
                raise remote.LabError("the original execution helper identity changed during observation")
            if handle is not None:
                expected_handle = handle
            last = observed
            remote.write_public(output / "execution-observation.json", last)
            execution = last.get("execution", {})
            progress = (last["state"], execution.get("compile_preparation", {}).get("status"),
                        execution.get("full_race", {}).get("status"))
            if progress != previous:
                print(json.dumps({"stage": "same_handle_observation", "run_id": run.run_id,
                                  "state": progress[0], "compile_preparation": progress[1],
                                  "full_race": progress[2]}), flush=True)
                previous = progress
            if last.get("terminal") is True:
                return last
        except Exception as error:
            # Only the observation is retried. Preserve the original helper's
            # state/handle and refuse to label a failed observation as terminal.
            last["terminal"] = False
            last["observation_error"] = {"type": type(error).__name__,
                                          "text": remote.SANITIZER.text(str(error))[:2048]}
            remote.write_public(output / "execution-observation.json", last)
            observer.close()
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(2, remaining))
    last["terminal"] = False
    last["observation_budget_exhausted"] = True
    remote.write_public(output / "execution-observation.json", last)
    return last


def terminal_coverage(compile_log: str, race_log: str):
    expected = sorted(set(re.findall(r"^(?:ok|\?)\s+(\S+)", compile_log, flags=re.MULTILINE)))
    events = []
    for line in race_log.splitlines():
        try:
            event = json.loads(line)
            if isinstance(event, dict):
                events.append(event)
        except ValueError:
            pass
    packages = {}
    started_tests = set()
    finished_tests = set()
    failed_tests = []
    for event in events:
        action, package, test = event.get("Action"), event.get("Package"), event.get("Test")
        if action == "run" and test:
            started_tests.add((package, test))
        if action in ("pass", "fail", "skip"):
            if test:
                finished_tests.add((package, test))
                if action == "fail":
                    failed_tests.append({"package": package, "test": test})
            elif package:
                packages.setdefault(package, []).append(action)
    missing = sorted(set(expected) - set(packages))
    unexpected = sorted(set(packages) - set(expected))
    bad = {package: actions for package, actions in packages.items()
           if len(actions) != 1 or actions[0] not in ("pass", "skip")}
    unfinished = [{"package": package, "test": test}
                  for package, test in sorted(started_tests - finished_tests)]
    result = {
        "expected_packages": expected, "package_terminal_events": packages,
        "missing_packages": missing, "unexpected_packages": unexpected,
        "failed_or_duplicate_packages": bad, "failed_tests": failed_tests,
        "tests_without_terminal_event": unfinished,
        "packages_passed": sum(actions == ["pass"] for actions in packages.values()),
        "packages_without_tests": sum(actions == ["skip"] for actions in packages.values()),
        "top_level_tests_passed": sum(event.get("Action") == "pass" and bool(event.get("Test"))
                                      and "/" not in event["Test"] for event in events),
        "data_race_reported": "WARNING: DATA RACE" in race_log,
    }
    result["pass"] = bool(expected) and not any((missing, unexpected, bad, failed_tests, unfinished,
                                                result["data_race_reported"]))
    return result


def snapshot_comparison(before, after):
    result = remote.compare_snapshots(before, after)
    baseline_complete = all(value.get("host_key_verified") is True
                            and value.get("snapshot", {}).get("listener_exit") == 0
                            and value.get("snapshot", {}).get("docker_exit") == 0
                            for value in (before, after))
    left, right = before.get("xray_identity_observation"), after.get("xray_identity_observation")
    complete = all(observation is not None and all(
        row.get("executable", {}).get("status") == "ok" for row in observation.get("processes", [])
    ) for observation in (left, right))
    identity_equal = complete and left == right
    result["baseline_complete"] = baseline_complete
    result["xray_identity_unchanged"] = identity_equal
    result["unchanged"] = result["unchanged"] and identity_equal and baseline_complete
    return result


def execute(binding):
    run_id = remote.new_run_id()
    output = STAGE / "lab/runs" / run_id
    claim = GATE.parent / "linux-race-attempt01.json"
    reservation = {"run_id": run_id, "source_manifest_sha256": binding["source_manifest_sha256"],
                   "result": str(output / "race-result.json"), "same_source_retry_allowed": False}
    # Exclusive reservation prevents rerunning the full suite until it passes.
    with claim.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(reservation, indent=2) + "\n")
    output.mkdir(parents=True, exist_ok=False)
    report = {
        **binding, "run_id": run_id, "pass": False, "acceptance_complete": False,
        "production_ready": False, "released": False, "receiver": RECEIVER,
        "image": IMAGE, "network": "none", "offline": True,
        "runner_sha256": sha256(Path(__file__).read_bytes()),
        "execution_helper_sha256": sha256(EXECUTION.encode()),
        "observation_helper_sha256": sha256(OBSERVATION.encode()),
        "resource_limits": {"memory": "384m", "memory_swap": "768m", "cpu": ".75", "pids": 256},
        "compile_preparation_command": PREP_COMMAND, "compile_preparation_outer_seconds": PREP_SECONDS,
        "full_race_command": RACE_COMMAND, "full_race_outer_seconds": RACE_SECONDS,
        "same_source_retry_allowed": False, "singapore_transfer_or_business": "none",
    }
    started = time.monotonic()
    observer = None
    run = None
    before = None
    created = False
    execution_attempted = False
    terminal_observed = True
    try:
        archive, manifest = freeze_source(output, binding)
        report.update({"source_manifest": manifest["files"],
                       "vendor_tree_sha256": manifest["vendor_tree_sha256"],
                       "archive_sha256": manifest["archive_sha256"]})
        hosts = remote.load_hosts(inventory=INVENTORY)
        host = hosts["receiver"]
        if host.hostname != RECEIVER:
            raise remote.LabError("only the authorized Los Angeles receiver may run race")
        observer = AuditedRemote(host)
        observer.connect()
        before = observer.snapshot()
        remote.write_public(output / "before.json", before)
        if before["snapshot"]["tmp_free_bytes"] < 1024 * 1024 * 1024:
            raise remote.LabError("receiver has less than 1 GiB spare /tmp disk")
        run = remote.RemoteRun(observer, run_id)
        report["created"] = run.create()
        created = True
        report["archive_upload"] = run.write("race-source.tar.gz", archive.read_bytes())
        spec = {**manifest, "receiver": RECEIVER, "image": IMAGE,
                "prep_command": PREP_COMMAND, "prep_seconds": PREP_SECONDS,
                "race_command": RACE_COMMAND, "race_seconds": RACE_SECONDS}
        run.write("race-spec.json", json.dumps(spec, separators=(",", ":")).encode())
        remote.write_public(output / "race-result.json", report)
        print(json.dumps({"stage": "source_bound_before_remote_execution", "run_id": run_id,
                          "source_file_count": binding["source_file_count"], "clientconfig_included": True,
                          "source_manifest_sha256": binding["source_manifest_sha256"],
                          "linux_binary_sha256": binding["related_binary"]["sha256"],
                          "receiver": RECEIVER, "network": "none",
                          "prep_outer_seconds": PREP_SECONDS, "race_outer_seconds": RACE_SECONDS}), flush=True)
        try:
            invocation_started = time.monotonic()
            execution_attempted = True
            terminal_observed = False
            report["execution"] = observer.python(run._check() + EXECUTION,
                                                  timeout=PREP_SECONDS + RACE_SECONDS + 120)
            terminal_observed = report["execution"].get("complete") is True
        except Exception as error:
            report["observation_error"] = {"type": type(error).__name__,
                                            "text": remote.SANITIZER.text(str(error))[:2048]}
            # Reconnect/collect only; never rerun the remote helper or test.
            observer.close()
            observed = observe_same_execution(
                observer, run, output,
                invocation_started + PREP_SECONDS + RACE_SECONDS + 120 + OBSERVATION_GRACE_SECONDS,
            )
            report["execution_observation"] = observed
            report["execution"] = observed.get("execution", {})
            terminal_observed = observed.get("terminal") is True
            report["execution_recovered_without_test_retry"] = True
            if not terminal_observed:
                raise remote.LabError("execution is non-terminal; preserved the exact helper and owned artifacts")
            if observed.get("state") == "exact_handle_missing":
                report["helper_missing_before_terminal_result"] = True
        if not terminal_observed:
            raise remote.LabError("execution helper returned without a terminal result")
        compile_log = ""
        if report["execution"].get("compile_preparation", {}).get("attempts") == 1:
            compile_log = run.read("compile.log", limit=LOG_LIMIT)
            remote.write_public(output / "compile-log.json", {"text": compile_log})
        if report["execution"].get("full_race", {}).get("attempts") == 1:
            race_log = run.read("race.log", limit=LOG_LIMIT)
            remote.write_public(output / "race-log.json", {"text": race_log})
            report["package_terminal_coverage"] = terminal_coverage(compile_log, race_log)
        else:
            report["package_terminal_coverage"] = {"pass": False, "reason": "full race was not run"}
    except Exception as error:
        report["error_type"] = type(error).__name__
        report["error"] = remote.SANITIZER.text(str(error))[:2048]
    finally:
        report["execution_attempted"] = execution_attempted
        report["terminal_observed"] = terminal_observed
        if run is not None and created and terminal_observed:
            try:
                report["cleanup"] = run.cleanup()
            except Exception as error:
                report["first_cleanup_error"] = {"type": type(error).__name__,
                                                   "text": remote.SANITIZER.text(str(error))[:2048]}
                try:
                    observer.close()
                    observer.connect()
                    report["cleanup"] = run.cleanup()
                    report["cleanup_reconnected_without_test_retry"] = True
                except Exception as retry_error:
                    report["cleanup"] = {"directory_removed": False, "error_type": type(retry_error).__name__,
                                           "error": remote.SANITIZER.text(str(retry_error))[:2048]}
        if created and not terminal_observed:
            report["cleanup"] = {"directory_removed": False,
                                   "reason": "exact helper is live or its terminal state is unknown"}
            report["snapshot_comparison"] = {"unchanged": False,
                                               "reason": "after snapshot waits for the original execution to terminate"}
        if observer is not None and before is not None and terminal_observed:
            try:
                after = observer.snapshot()
            except Exception as error:
                report["first_after_snapshot_error"] = remote.SANITIZER.text(str(error))[:2048]
                try:
                    observer.close()
                    observer.connect()
                    after = observer.snapshot()
                except Exception as retry_error:
                    report["after_snapshot_error"] = remote.SANITIZER.text(str(retry_error))[:2048]
                    after = None
            if after is not None:
                remote.write_public(output / "after.json", after)
                report["snapshot_comparison"] = snapshot_comparison(before, after)
        if observer is not None:
            observer.close()
        try:
            report["source_and_binary_binding_unchanged"] = load_binding() == binding
        except Exception as error:
            report["source_and_binary_binding_unchanged"] = False
            report["binding_error"] = remote.SANITIZER.text(str(error))[:2048]
        execution = report.get("execution", {})
        report["pass"] = all((
            "error" not in report, "error" not in execution, execution.get("complete") is True,
            terminal_observed is True, not report.get("helper_missing_before_terminal_result"),
            execution.get("upload_binding_verified") is True,
            execution.get("compile_preparation", {}).get("pass") is True,
            execution.get("full_race", {}).get("pass") is True,
            execution.get("full_race", {}).get("attempts") == 1,
            execution.get("owned_container_removed") is True,
            report.get("package_terminal_coverage", {}).get("pass") is True,
            report.get("cleanup", {}).get("directory_removed") is True,
            report.get("snapshot_comparison", {}).get("unchanged") is True,
            report.get("source_and_binary_binding_unchanged") is True,
        ))
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        remote.write_public(output / "race-result.json", report)
    return report, output / "race-result.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true",
                        help="check a completed local gate; do not read credentials or connect")
    args = parser.parse_args()
    try:
        binding = load_binding()
        if args.check_only:
            print(json.dumps({"stage": "local_binding_check", "binding_pass": True,
                              "source_file_count": binding["source_file_count"],
                              "clientconfig_included": True,
                              "source_manifest_sha256": binding["source_manifest_sha256"],
                              "linux_binary_sha256": binding["related_binary"]["sha256"],
                              "remote_run": False}), flush=True)
            return 0
        report, path = execute(binding)
        print(json.dumps({"stage": "complete", "run_id": report["run_id"], "pass": report["pass"],
                          "path": str(path), "compile_preparation": report.get("execution", {}).get("compile_preparation"),
                          "full_race": report.get("execution", {}).get("full_race"),
                          "error": report.get("error")}, ensure_ascii=False), flush=True)
        return 0 if report["pass"] else 1
    except Exception as error:
        print(json.dumps({"pass": False, "error_type": type(error).__name__,
                          "error": remote.SANITIZER.text(str(error))[:2048]}, ensure_ascii=False), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
