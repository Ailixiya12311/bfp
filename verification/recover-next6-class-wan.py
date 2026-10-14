"""Collect an interrupted owned next6 run and launch only its unstarted scenes.

Normal UDP is never relaunched. Original scene budgets and frozen ELF remain
unchanged. All management operations have a watchdog covering RPC initialization.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shlex
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next6'
sys.path.insert(0, str(ROOT / 'lab'))
import remote

spec = importlib.util.spec_from_file_location('next6_management', ROOT / 'verification/run-next6-wan.py')
management = importlib.util.module_from_spec(spec)
spec.loader.exec_module(management)

EXPECTED_BINARY = '2583677700803cbabbbdf986454844a38fcd1512ba1e9a15e780c14e4de5df86'
COUNT, SIZE, INTERVAL, DURATION = 50, 4096, '100ms', '35s'
SCENES = (('udp_to_tcp', '8s'), ('initial_udp_blocked', '1ns'))
LOG_LIMIT, SERVER_LOG_LIMIT = 1 << 20, 4 << 20
METHOD = 'run-owner-static-size-gzip-base64-rpc-v1'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded(endpoint, call, seconds=32):
    """Daemon worker cannot keep interpreter alive after channel-init hangs."""
    complete = threading.Event()
    box = {}
    def worker():
        try:
            box['value'] = call()
        except BaseException as error:
            box['error'] = error
        finally:
            complete.set()
    threading.Thread(target=worker, daemon=True).start()
    if not complete.wait(seconds):
        endpoint.close()
        raise remote.LabError('management watchdog exceeded fixed operation deadline')
    if 'error' in box:
        raise box['error']
    return box['value']


def rpc(endpoint, source, timeout=30, max_output=8 << 20):
    encoded = base64.b64encode(source.encode()).decode()
    command = 'python3 -c ' + shlex.quote("import base64;exec(compile(base64.b64decode(" + repr(encoded) + "),'<bfp-owned-recovery>','exec'))")
    result = bounded(endpoint, lambda: endpoint.execute(command, timeout=timeout, max_output=max_output), timeout + 2)
    if result['exit_code']:
        raise remote.LabError('owned recovery RPC failed: ' + remote.SANITIZER.text(result['stderr'])[:1024])
    try:
        return json.loads(result['stdout'])
    except ValueError:
        raise remote.LabError('owned recovery RPC returned non-JSON') from None


def connect(endpoint):
    endpoint.close()
    return bounded(endpoint, endpoint.connect, 35)


def ensure_connected(endpoint):
    transport = endpoint.client.get_transport() if endpoint.client else None
    if transport is None or not transport.is_active():
        connect(endpoint)


def collect(run, name, limit):
    """Read the exact lstat-size snapshot; never relax the original byte cap."""
    name = remote.file_name(name)
    source = run._check() + r'''
import stat,gzip,base64,hashlib
f=p/%r
st=f.lstat()
if not stat.S_ISREG(st.st_mode) or str(f.resolve())!=str(f):raise RuntimeError('artifact is not owned regular file')
if st.st_size>%r:raise RuntimeError('owned artifact exceeds original collection budget')
fd=os.open(f,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
with os.fdopen(fd,'rb') as stream:
    opened=os.fstat(stream.fileno())
    if (opened.st_dev,opened.st_ino)!=(st.st_dev,st.st_ino):raise RuntimeError('artifact identity changed')
    data=stream.read(st.st_size)
if len(data)!=st.st_size:raise RuntimeError('artifact shrank during fixed snapshot')
text=data.decode('utf-8','strict')
secrets=set()
def values(value):
    if isinstance(value,dict):
        for item in value.values():values(item)
    elif isinstance(value,list):
        for item in value:values(item)
    elif isinstance(value,str) and value:secrets.add(value)
for config_name in ('server.json','normal_udp.json'):
    config=p/config_name
    if config.exists():
        cs=config.lstat()
        if not stat.S_ISREG(cs.st_mode) or cs.st_size>65536:raise RuntimeError('unsafe owned credential source')
        values(json.loads(config.read_text()).get('credentials',{}))
redacted=False
for value in sorted(secrets,key=len,reverse=True):
    if value in text:text=text.replace(value,'[REDACTED]');redacted=True
safe=text.encode()
packed=gzip.compress(safe,compresslevel=6,mtime=0)
print(json.dumps({'name':%r,'snapshot_bytes':len(data),'collected_bytes':len(safe),'sha256':hashlib.sha256(safe).hexdigest(),'gzip_sha256':hashlib.sha256(packed).hexdigest(),'packed':base64.b64encode(packed).decode(),'redacted':redacted,'method':%r}))
''' % (name, limit, name, METHOD)
    envelope = rpc(run.remote, source)
    packed = base64.b64decode(envelope.pop('packed'), validate=True)
    if digest(packed) != envelope['gzip_sha256']:
        raise remote.LabError('collected gzip digest mismatch')
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
        data = stream.read(limit + 1)
    if len(data) > limit or len(data) != envelope['collected_bytes'] or digest(data) != envelope['sha256']:
        raise remote.LabError('collected artifact size/hash mismatch')
    return data.decode('utf-8', errors='strict'), envelope


def json_lines(text):
    rows = []
    for line in text.splitlines():
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise remote.LabError('owned JSONL row not object')
            rows.append(value)
    return rows


def target_opens(run):
    text, _meta = collect(run, 'fixture.log', LOG_LIMIT)
    return max((row.get('opened', 0) for row in json_lines(text) if row.get('event') == 'target_open'), default=0)


def status(run, scene):
    return rpc(run.remote, run._check() + r'''
import hashlib
name=%r
manifest=p/(name+'.process.json')
result=p/(name+'.result.json')
if not manifest.exists():raise RuntimeError('scene was not started')
m=json.loads(manifest.read_text())
if m.get('run_id')!=rid:raise RuntimeError('process owner mismatch')
proc=pathlib.Path('/proc')/str(m['pid'])
live=False
if proc.exists():
    start=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
    cmd=(proc/'cmdline').read_bytes()
    exe=str((proc/'exe').resolve())
    live=start==m['starttime'] and hashlib.sha256(cmd).hexdigest()==m['command_sha256'] and exe==m['exe']
    if not live:raise RuntimeError('existing PID owner mismatch')
print(json.dumps({'result_ready':result.exists(),'process_live':live,'pid':m['pid']}))
''' % scene, timeout=10)


def wait_result(run, scene):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        state = status(run, scene)
        if state['result_ready']:
            return state
        if not state['process_live']:
            raise remote.LabError('owned probe terminal without result')
        time.sleep(.5)
    raise remote.LabError('original fixed 45-second collection window exceeded')


def record_error(error):
    return {'error_type': type(error).__name__, 'error': remote.SANITIZER.text(str(error))[:1024]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    if not remote.RUN_ID.fullmatch(args.run):
        raise remote.LabError('invalid existing run ID')
    output = STAGE / 'lab/runs' / args.run
    if not output.is_dir() or output.is_symlink():
        raise remote.LabError('existing local run directory required')
    if (output / 'class-wan-result.json').exists():
        raise remote.LabError('existing terminal run result is never overwritten')
    binary_hash = digest((output / 'bfp-linux-amd64').read_bytes())
    if binary_hash != EXPECTED_BINARY:
        raise remote.LabError('frozen binary changed')
    remote.WORKSPACE = STAGE
    hosts = remote.load_hosts(inventory=Path(r'C:\Users\developer\Desktop\cold\servers-unredacted.md'))
    management.ManagementRemote.route = 'receiver-jump'
    management.ManagementRemote.jump_host = hosts['receiver']
    endpoints = {role: management.ManagementRemote(host) for role, host in hosts.items()}
    runs = {role: remote.RemoteRun(endpoint, args.run) for role, endpoint in endpoints.items()}
    report = {'run_id': args.run, 'revision': 'r9-next6', 'wire_version': 3,
        'profile': 'class-announcement-v1', 'capabilities': 1, 'binary_sha256': binary_hash,
        'limits': {'count': COUNT, 'size': SIZE, 'interval': INTERVAL, 'duration': DURATION},
        'collection': {'method': METHOD, 'helper_sha256': digest(Path(__file__).read_bytes()),
                       'rpc_timeout_seconds': 30, 'rpc_watchdog_slack_seconds': 2,
                       'server_log_limit_bytes': SERVER_LOG_LIMIT, 'per_probe_log_limit_bytes': LOG_LIMIT},
        'original_collection_interruption': json.loads((output / 'runner-collection-interruption.json').read_text()),
        'missing_current_baseline': True, 'baseline_boundary': 'The interrupted runner kept current before snapshots only in lost memory. No older run baseline substitutes for this run.',
        'uploads': {}, 'scenarios': {}, 'snapshots': {}, 'cleanup': {}, 'collected_artifacts': {},
        'remaining_scenes_launched': [], 'normal_udp_relaunched': False,
        'selected_checks_pass': False, 'pass': False, 'production_ready': False, 'released': False,
        'unchecked_wan_gates': {'selective_missing_class_ack_injection': False, 'retry_exhaustion': False}}
    for role in hosts:
        report['uploads'][role] = json.loads((output / (role + '-upload.json')).read_text())
        if report['uploads'][role].get('pass') is not True or report['uploads'][role].get('sha256') != binary_hash:
            raise remote.LabError('prior verified upload record required')
    def save():
        remote.write_public(output / 'recovery-progress.json', report)
    def capture_scene(scene, blackhole, before=None):
        evidence = {'pass': False, 'relay_blackhole_after': blackhole,
                    'original_scene_not_repeated': scene == 'normal_udp'}
        try:
            ensure_connected(endpoints['sender'])
            evidence['terminal_status'] = status(runs['sender'], scene)
            text, meta = collect(runs['sender'], scene + '.result.json', LOG_LIMIT)
            result = json.loads(text)
            evidence['result'] = result
            report['collected_artifacts'][scene + '.result.json'] = meta
            initial, final = result.get('initial', {}), result.get('final', {})
            if scene == 'normal_udp':
                carrier = initial.get('carrier') == final.get('carrier') == 'udp' and final.get('switches') == 0
            elif scene == 'udp_to_tcp':
                carrier = initial.get('carrier') == 'udp' and final.get('carrier') == 'tcp' and final.get('generation', 0) > initial.get('generation', 0) and final.get('switches', 0) >= 1
            else:
                carrier = initial.get('carrier') == final.get('carrier') == 'tcp'
            evidence['carrier_expectation_met'] = carrier
            if before is not None:
                after = target_opens(runs['receiver'])
                evidence.update(target_opens_before=before, target_opens_after=after, one_target_connection=after - before == 1)
            else:
                evidence['one_target_connection'] = False
                evidence['original_target_before_counter_missing'] = True
            evidence['probe_result_pass'] = result.get('pass') is True
            # Independent peer audit is separate; no invented peer gate here.
            evidence['pass'] = bool(result.get('pass') and carrier and evidence['one_target_connection'])
        except Exception as error:
            evidence.update(record_error(error))
        try:
            text, meta = collect(runs['sender'], scene + '.log', LOG_LIMIT)
            remote.write_public(output / (scene + '.probe-log.json'), {'lines': text})
            report['collected_artifacts'][scene + '.log'] = meta
        except Exception as error:
            evidence['probe_log_collection_error'] = record_error(error)
        report['scenarios'][scene] = evidence
        remote.write_public(output / (scene + '.evidence.json'), evidence)
        save()
        print(json.dumps({'stage': 'scene_collected', 'scenario': scene, 'probe_pass': evidence.get('probe_result_pass', False), 'tcp_completed': evidence.get('result', {}).get('tcp_completed'), 'failure': evidence.get('result', {}).get('failure')}), flush=True)
    started = time.monotonic()
    try:
        for role, endpoint in endpoints.items():
            connect(endpoint)
            ownership = rpc(endpoint, runs[role]._check() + "print(json.dumps({'owner_verified':True,'process_manifests':sorted(x.name for x in p.glob('*.process.json'))}))")
            report.setdefault('ownership', {})[role] = ownership
            print(json.dumps({'stage': 'owner_verified', 'role': role, 'process_manifests': ownership['process_manifests']}), flush=True)
        retained = status(runs['sender'], 'normal_udp')
        if retained['process_live'] or not retained['result_ready']:
            raise remote.LabError('normal UDP must already be terminal with retained result')
        capture_scene('normal_udp', '0s')
        ports = rpc(endpoints['receiver'], runs['receiver']._check() + "cfg=json.loads((p/'server.json').read_text())\nprint(json.dumps({'listen_port':int(cfg['listen'].rsplit(':',1)[1]),'target_ports':cfg['policy']['AllowedPorts']}))")
        if len(ports['target_ports']) != 1:
            raise remote.LabError('original single fixture port required')
        target_port = ports['target_ports'][0]
        for index, (scene, blackhole) in enumerate(SCENES):
            ensure_connected(endpoints['sender'])
            ensure_connected(endpoints['receiver'])
            # Any existing artifact is evidence of an earlier dispatch: refuse
            # rather than reusing a name and accidentally rerunning a scene.
            prepared = rpc(endpoints['sender'], runs['sender']._check() + r'''
import socket
name=%r
for suffix in ('.json','.process.json','.log','.result.json','-relay.process.json','-relay.log'):
    if (p/(name+suffix)).exists():raise RuntimeError('remaining scene already has dispatch artifact; refusing rerun')
port=None
for candidate in range(%r,%r):
    sockets=[]
    try:
        for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
            sock=socket.socket(socket.AF_INET,kind);sockets.append(sock);sock.bind(('127.0.0.1',candidate))
        port=candidate;break
    except OSError:pass
    finally:
        for sock in sockets:sock.close()
if port is None:raise RuntimeError('no free owned relay port')
cfg=json.loads((p/'normal_udp.json').read_text())
if cfg['tcp_server']!=%r:raise RuntimeError('original TCP receiver mismatch')
cfg['server']='127.0.0.1:%%d'%%port
fd=os.open(p/(name+'.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as stream:json.dump(cfg,stream,separators=(',',':'))
print(json.dumps({'relay_port':port,'config_cloned_without_exporting_credentials':True}))
''' % (scene, 19182 + index, 19212 + index, hosts['receiver'].hostname + ':' + str(ports['listen_port'])))
            before = target_opens(runs['receiver'])
            relay_args = ['relay', '-listen', '127.0.0.1:' + str(prepared['relay_port']), '-target', hosts['receiver'].hostname + ':' + str(ports['listen_port']), '-blackhole-after', blackhole]
            bounded(endpoints['sender'], lambda: runs['sender'].start(relay_args, name=scene + '-relay'))
            probe_args = ['class-probe', '-config', scene + '.json', '-target', '127.0.0.1:' + str(target_port), '-count', str(COUNT), '-size', str(SIZE), '-interval', INTERVAL, '-duration', DURATION, '-result', scene + '.result.json']
            report['remaining_scenes_launched'].append(scene)
            save()  # Record dispatch before RPC; unknown launch is never repeated.
            bounded(endpoints['sender'], lambda: runs['sender'].start(probe_args, name=scene))
            print(json.dumps({'stage': 'scene_started_once', 'scenario': scene, 'duration': DURATION, 'count': COUNT}), flush=True)
            try:
                wait_result(runs['sender'], scene)
            except Exception as error:
                report.setdefault('scene_collection_wait_errors', {})[scene] = record_error(error)
            capture_scene(scene, blackhole, before)
        for role, name, limit, artifact in (('receiver', 'server.log', SERVER_LOG_LIMIT, 'server-log.json'), ('receiver', 'fixture.log', LOG_LIMIT, 'fixture-log.json')):
            try:
                text, meta = collect(runs[role], name, limit)
                remote.write_public(output / artifact, {'lines': text})
                report['collected_artifacts'][name] = meta
            except Exception as error:
                report.setdefault('artifact_collection_errors', {})[name] = record_error(error)
    except Exception as error:
        report.update(record_error(error))
    finally:
        # Both original run directories are already known to be owned. Cleanup
        # remains attempted even after a collection or scene-launch failure.
        for role, run in runs.items():
            try:
                ensure_connected(endpoints[role])
                report['cleanup'][role] = bounded(endpoints[role], run.cleanup, 32)
            except Exception as error:
                report['cleanup'][role] = {'directory_removed': False, **record_error(error)}
            save()
            print(json.dumps({'stage': 'owner_cleanup', 'role': role, 'directory_removed': report['cleanup'][role].get('directory_removed', False)}), flush=True)
        for role, endpoint in endpoints.items():
            try:
                ensure_connected(endpoint)
                after = rpc(endpoint, remote.SNAPSHOT, timeout=30)
                report['snapshots'][role] = {'after': after, 'missing_current_baseline': True, 'comparison': {'unchanged': False, 'reason': 'current_before_snapshot_missing'}}
            except Exception as error:
                report['snapshots'][role] = {'missing_current_baseline': True, 'after_error': record_error(error)}
            finally:
                endpoint.close()
        report['elapsed_recovery_seconds'] = round(time.monotonic() - started, 3)
        report['selected_checks_pass'] = False
        report['pass'] = False
        remote.write_public(output / 'class-wan-result.json', report)
        save()
    print(json.dumps({'stage': 'recovery_complete', 'run_id': args.run, 'pass': False,
        'cleanup_complete': len(report['cleanup']) == 2 and all(x.get('directory_removed') for x in report['cleanup'].values()),
        'missing_current_baseline': True}), flush=True)
    return 0 if len(report['cleanup']) == 2 and all(x.get('directory_removed') for x in report['cleanup'].values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
