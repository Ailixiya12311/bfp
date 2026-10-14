"""One frozen wire3 classification WAN matrix, using authorized pinned hosts."""
from __future__ import annotations

import concurrent.futures
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next6'
sys.path.insert(0, str(ROOT / 'lab'))
import remote
import wan
import bounded_staging

spec = importlib.util.spec_from_file_location('management', ROOT/'verification/run-next6-wan.py')
management = importlib.util.module_from_spec(spec)
spec.loader.exec_module(management)

# All limits are fixed before dispatch. No scene is rerun or extended here.
COUNT, SIZE, INTERVAL, DURATION = 50, 4096, '100ms', '35s'
CLASSIFICATION = {'behavior': {'enabled': True, 'window': '800ms', 'bucket': '100ms',
    'min_total_bytes': 8192, 'bulk_bytes_per_second': 1000, 'bulk_sustain': '600ms',
    'activity_gap': '400ms', 'restore': True, 'restore_bytes_per_second': 100,
    'restore_sustain': '600ms', 'cooldown': '0s'}}

def peer_evidence(rows, result):
    sid, flow = result.get('final', {}).get('session_id'), result.get('flow_id')
    views = [view for row in rows if row.get('classification_snapshot_ok')
             for view in row.get('classifications', {}).get(sid, []) if view.get('ID') == flow]
    gates = {}
    for stage in ('bulk', 'restored'):
        local = result.get(stage+'_class') or {}
        local_exact = bool(local.get('TXVersion')) and local.get('TXPublishedVersion') == local.get('TXAckedVersion') == local.get('TXVersion') and not local.get('TXPending')
        # A server tick is only a sample. It proves a current exact ACK if the
        # sampled local state is acknowledged and both independent views match.
        matching = [v for v in views if local and v.get('LocalTX', {}).get('Class') == local.get('PeerTX', {}).get('Class')
                    and v.get('TXVersion') == local.get('PeerTX', {}).get('Version')
                    and v.get('TXAckedVersion') == v.get('TXVersion') == v.get('TXPublishedVersion')
                    and not v.get('TXPending') and v.get('PeerTX', {}).get('Known')
                    and v.get('PeerTX', {}).get('Version') == local.get('TXVersion')
                    and v.get('PeerTX', {}).get('Class') == local.get('LocalTX', {}).get('Class')]
        gates[stage+'_both_directions_exact_ack'] = bool(matching) and local_exact
    final = result.get('final_class') or {}
    gates['peer_unique_bytes'] = any(v.get('LocalTX', {}).get('TotalBytes') == COUNT*SIZE for v in views)
    gates['local_unique_bytes'] = final.get('LocalTX', {}).get('TotalBytes') == COUNT*SIZE
    return {'gates': gates, 'server_observations': views, 'pass': all(gates.values())}

def main():
    remote.WORKSPACE = wan.WORKSPACE = STAGE
    hosts = remote.load_hosts(inventory=Path(r'C:\Users\developer\Desktop\cold\servers-unredacted.md'))
    management.ManagementRemote.route = 'receiver-jump'
    management.ManagementRemote.jump_host = hosts['receiver']
    run_id = remote.new_run_id()
    output = STAGE/'lab/runs'/run_id
    output.mkdir(parents=True, exist_ok=False)
    binary = STAGE/'bfp-r9-next6-linux-amd64'
    data = binary.read_bytes()
    frozen = output/'bfp-linux-amd64'
    frozen.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    report = {'run_id': run_id, 'revision': 'r9-next6', 'wire_version': 3,
        'profile': 'class-announcement-v1', 'capabilities': 1, 'binary_sha256': digest,
        'path': 'Singapore sender -> Los Angeles receiver', 'management': 'receiver-jump with original pinned keys',
        'business': 'Los Angeles public native UDP/TCP', 'classification': CLASSIFICATION,
        'limits': {'count': COUNT, 'size': SIZE, 'interval': INTERVAL, 'duration': DURATION},
        'scenarios': {}, 'snapshots': {}, 'cleanup': {}, 'uploads': {}, 'pass': False,
        'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'upload_helper_sha256': hashlib.sha256(Path(bounded_staging.__file__).read_bytes()).hexdigest(),
        'supersedes_setup_attempt_only': 'eba92b0b60d6cec0295ad61561a24778',
        'unchecked_wan_gates': {'selective_missing_class_ack_injection': False, 'retry_exhaustion': False},
        'production_ready': False, 'released': False}
    remotes, runs = {}, {}
    started = time.monotonic()
    try:
        for role, host in hosts.items():
            remotes[role] = management.ManagementRemote(host).connect()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            tasks = {pool.submit(r.snapshot): role for role, r in remotes.items()}
            for task in concurrent.futures.as_completed(tasks):
                report['snapshots'][tasks[task]] = {'before': task.result()}
        for role, endpoint in remotes.items():
            run = remote.RemoteRun(endpoint, run_id)
            run.create()
            runs[role] = run
            def save_upload(value, role=role):
                remote.write_public(output/(role+'-upload.json'),value)
            uploaded = bounded_staging.upload_binary(run, frozen, save_upload)
            report['uploads'][role]=uploaded
            if uploaded['sha256'] != digest: raise remote.LabError('staged hash mismatch')
            print(json.dumps({'stage':'binary_staged','role':role,'bytes':uploaded['bytes'],'compressed_bytes':uploaded['compressed_bytes'],'sha256':uploaded['sha256'],'management_attempts':len(uploaded['attempts'])}),flush=True)
        receiver, sender = remotes['receiver'], remotes['sender']
        receive_run, send_run = runs['receiver'], runs['sender']
        port = wan.free_port(receiver, 51880, '0.0.0.0')
        target_port = wan.free_port(receiver, 19180, '127.0.0.1')
        sc, cc = wan.credentials()
        receive_run.config('server.json', {'listen': f'0.0.0.0:{port}', 'credentials': sc,
            'policy': {'AllowPrivate': True, 'AllowedCIDRs': ['127.0.0.0/8'], 'AllowedPorts': [target_port], 'MaxConcurrent': 4, 'Timeout': 10000000000},
            'max_sessions': 4, 'classification': CLASSIFICATION})
        receive_run.start(['fixture', '-listen', f'127.0.0.1:{target_port}'], name='fixture')
        receive_run.start(['server', '-config', 'server.json', '-stats', '100ms', '-class-stats'], name='server')
        for index, (scene, blackhole) in enumerate((('normal_udp', '0s'), ('udp_to_tcp', '8s'), ('initial_udp_blocked', '1ns'))):
            relay_port = wan.free_port(sender, 19181+index, '127.0.0.1')
            send_run.config(scene+'.json', {'server': f'127.0.0.1:{relay_port}', 'tcp_server': f'{hosts["receiver"].hostname}:{port}',
                'credentials': cc, 'socks': '127.0.0.1:0', 'classification': CLASSIFICATION})
            before = wan.target_opens(receive_run)
            send_run.start(['relay', '-listen', f'127.0.0.1:{relay_port}', '-target', f'{hosts["receiver"].hostname}:{port}', '-blackhole-after', blackhole], name=scene+'-relay')
            send_run.start(['class-probe', '-config', scene+'.json', '-target', f'127.0.0.1:{target_port}',
                '-count', str(COUNT), '-size', str(SIZE), '-interval', INTERVAL, '-duration', DURATION, '-result', scene+'.result.json'], name=scene)
            print(json.dumps({'stage': 'class_probe_started', 'run_id': run_id, 'scenario': scene}), flush=True)
            try:
                result = wan.wait_result(send_run, scene, timeout=45)
                # Allow one fixed stats sample while the probe's Session is
                # still retained by the server; no business scene is repeated.
                rows = wan.json_lines(receive_run.read('server.log', limit=4*1024*1024))
                peer = peer_evidence(rows, result)
                initial, final = result.get('initial', {}), result.get('final', {})
                if scene == 'normal_udp': carrier = initial.get('carrier') == final.get('carrier') == 'udp' and final.get('switches') == 0
                elif scene == 'udp_to_tcp': carrier = initial.get('carrier') == 'udp' and final.get('carrier') == 'tcp' and final.get('generation', 0) > initial.get('generation', 0) and final.get('switches', 0) >= 1
                else: carrier = initial.get('carrier') == final.get('carrier') == 'tcp'
                one_target = wan.target_opens(receive_run)-before == 1
                report['scenarios'][scene] = {'pass': bool(result.get('pass') and peer['pass'] and carrier and one_target),
                    'result': result, 'peer_evidence': peer, 'carrier_expectation_met': carrier,
                    'one_target_connection': one_target, 'relay_blackhole_after': blackhole}
            except Exception as error:
                report['scenarios'][scene] = {'pass': False, 'error_type': type(error).__name__, 'error': remote.SANITIZER.text(str(error))[:2048]}
            remote.write_public(output/(scene+'.evidence.json'), report['scenarios'][scene])
            remote.write_public(output/(scene+'.probe-log.json'), {'lines': send_run.read(scene+'.log')})
            print(json.dumps({'stage': 'class_probe_complete', 'scenario': scene, 'pass': report['scenarios'][scene]['pass']}), flush=True)
        before = wan.target_opens(receive_run)
        report['random_probe'] = wan.random_probe(sender, hosts['receiver'].hostname, port)
        report['random_probe']['pass'] = report['random_probe']['no_application_response'] and report['random_probe']['tcp_connected'] == 8 and wan.target_opens(receive_run) == before
        remote.write_public(output/'server-log.json', {'lines': receive_run.read('server.log', limit=4*1024*1024)})
        remote.write_public(output/'fixture-log.json', {'lines': receive_run.read('fixture.log')})
    except Exception as error:
        report.update(error_type=type(error).__name__, error=remote.SANITIZER.text(str(error))[:2048])
    finally:
        for role, run in runs.items():
            try:
                transport=run.remote.client.get_transport() if run.remote.client else None
                if transport is None or not transport.is_active():
                    run.remote.close();run.remote.connect()
                report['cleanup'][role] = run.cleanup()
            except Exception as error: report['cleanup'][role] = {'directory_removed': False, 'error_type': type(error).__name__}
        for role, endpoint in remotes.items():
            try:
                item = report['snapshots'].setdefault(role, {})
                item['after'] = endpoint.snapshot()
                if item.get('before'): item['comparison'] = remote.compare_snapshots(item['before'], item['after'])
            except Exception as error: report['snapshots'].setdefault(role, {})['after_error'] = type(error).__name__
            endpoint.close()
        report['selected_checks_pass'] = len(report['scenarios']) == 3 and all(x.get('pass') for x in report['scenarios'].values()) and report.get('random_probe', {}).get('pass') and len(report['cleanup']) == 2 and all(x.get('directory_removed') for x in report['cleanup'].values()) and all(x.get('comparison', {}).get('unchanged') for x in report['snapshots'].values())
        # Selected WAN samples do not prove selective ACK-loss/exhaustion or
        # completion of Stage B's full gate, let alone overall protocol maturity.
        report['pass'] = False
        report['elapsed_seconds'] = round(time.monotonic()-started, 3)
        remote.write_public(output/'class-wan-result.json', report)
    print(json.dumps({'stage': 'complete', 'run_id': run_id, 'selected_checks_pass': report['selected_checks_pass'], 'pass': False, 'path': str(output/'class-wan-result.json')}), flush=True)
    return 0 if report['selected_checks_pass'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
