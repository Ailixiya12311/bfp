"""Automatic-route launcher faults inside an owned network-none netns."""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import time

from launcher_faults import alive, call, native_child, port_open, until

ROOT = pathlib.Path('/tmp/bfp-auto-route-faults')
EVIDENCE = pathlib.Path('/evidence')


def checked(argv):
    result = call(argv)
    if result.returncode:
        raise RuntimeError('fixture command failed: ' + ' '.join(argv) + ': ' + result.stderr.strip())
    return result.stdout


def snapshot():
    result = {}
    for family in ('-4', '-6'):
        for kind in ('rule', 'route'):
            argv = ['ip', family, '-j', kind, 'show'] + (['table', 'all'] if kind == 'route' else [])
            result[family + kind] = json.loads(checked(argv))
    return result


def main():
    report = {'pass': False, 'automatic_routes': True, 'scope': 'owned Linux automatic routing namespace; no WAN or host network changes', 'cases': {}}
    processes, children, outputs = [], [], []
    try:
        for args in (['link', 'add', 'bfp-uplink', 'type', 'dummy'],
                     ['addr', 'add', '192.0.2.2/24', 'dev', 'bfp-uplink'],
                     ['-6', 'addr', 'add', 'fd7e:bf00::1/64', 'dev', 'bfp-uplink', 'nodad'],
                     ['link', 'set', 'bfp-uplink', 'up'],
                     ['route', 'add', 'default', 'via', '192.0.2.1', 'dev', 'bfp-uplink'],
                     ['-6', 'route', 'add', 'default', 'via', 'fd7e:bf00::2', 'dev', 'bfp-uplink']):
            checked(['ip'] + args)
        # Unrelated routes/rules exist before startup and must survive.
        for family, destination in (('-4', '203.0.113.123/32'), ('-6', 'fd7e:aaaa::123/128')):
            checked(['ip', family, 'route', 'add', 'blackhole', destination, 'table', '28765'])
            checked(['ip', family, 'rule', 'add', 'pref', '9000', 'to', destination, 'lookup', '28765'])
        ROOT.mkdir(mode=0o700)
        for directory in ('bin', 'configs'):
            (ROOT / directory).mkdir(mode=0o700)
        for name, source in (('bfp-linux-amd64', '/bfp/bfp'), ('mihomo-bfp-linux-amd64', '/bfp/mihomo')):
            (ROOT / 'bin' / name).symlink_to(source)
        shutil.copyfile('/bfp/start-native.sh', ROOT / 'start-native.sh')
        report['launcher_sha256'] = hashlib.sha256((ROOT / 'start-native.sh').read_bytes()).hexdigest()
        checked(['/bfp/bfp', 'keygen', '-out', str(ROOT / 'credentials')])
        for mode in ('proxy', 'tun'):
            yaml = pathlib.Path(f'/bfp/configs/native-{mode}.yaml').read_text()
            yaml = yaml.replace('    client-config-file: ./credentials/client.json', '    client-config-file: ./credentials/client.json\n    interface-name: bfp-uplink')
            (ROOT / 'configs' / f'native-{mode}.yaml').write_text(yaml)
        marker = ROOT / 'runtime/bfp-tun-supervisor.env'
        generated = ROOT / 'runtime/native-tun.generated.yaml'
        journal = ROOT / 'runtime/bfp-native-network.json'
        report['namespace_before'] = snapshot()

        def start(name, mode='tun'):
            output = open(ROOT / f'{name}.log', 'wb')
            outputs.append(output)
            proc = subprocess.Popen(['sh', str(ROOT / 'start-native.sh'), mode], stdout=output, stderr=output, start_new_session=True)
            processes.append(proc)
            if not until(lambda: proc.poll() is not None or port_open(), 12) or proc.poll() is not None:
                raise RuntimeError(name + ' did not start')
            if mode == 'tun' and not until(lambda: 'BFP TUN interface ready' in (ROOT / f'{name}.log').read_text(), 12):
                raise RuntimeError(name + ' TUN did not start')
            child = native_child(proc)
            children.append(child)
            return proc, child

        for fault in ('native_sigkill', 'launcher_sigkill', 'process_group_sigkill'):
            before = snapshot()
            proc, child = start(fault)
            active = snapshot()
            lease = json.loads(journal.read_text())
            if lease.get('version') != 2 or not lease.get('captured') or not lease.get('rules') or not all(row.get('payload') for row in lease['rules']):
                raise RuntimeError('full kernel rule journal was not recorded before readiness')
            if lease['rule_start'] == 9000:
                raise RuntimeError('TUN allocation reused the occupied rule priority')
            match = re.search(r'^device=(bfp-tun-[0-9a-f]{7})$', marker.read_text(), re.M)
            if not match:
                raise RuntimeError('invalid owned TUN marker')
            device = match.group(1)
            if fault == 'native_sigkill':
                os.kill(child, signal.SIGKILL)
            elif fault == 'launcher_sigkill':
                proc.kill()
            else:
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=9)
            stopped = until(lambda: not alive(child) and not port_open(), 8)
            after = snapshot()
            case = {'exit_code': proc.returncode, 'native_stopped': stopped, 'before': before, 'active': active, 'after': after,
                    'journal': lease,
                    'routes_and_rules_restored_immediately': before == after,
                    'device_removed': call(['ip', 'link', 'show', 'dev', device]).returncode != 0,
                    'lock_released': call(['flock', '-n', str(ROOT / 'runtime/native.lock'), 'true']).returncode == 0}
            report['cases'][fault] = case
            # If the whole group was killed no cleanup code can run. Restart
            # must replay the owned network journal before creating a new TUN.
            if fault != 'process_group_sigkill' and (not stopped or before != after):
                raise RuntimeError(fault + ' left automatic routes or rules behind')
            restarted, restarted_child = start(fault + '-restart', 'proxy')
            case['restart_recovers_routes'] = snapshot() == before
            case['stale_files_removed'] = not marker.exists() and not generated.exists() and not journal.exists()
            restarted.terminate()
            restarted.wait(timeout=9)
            case['restart_exit_code'] = restarted.returncode
            if not case['restart_recovers_routes'] or not case['stale_files_removed'] or restarted.returncode != 143:
                raise RuntimeError(fault + ' restart did not recover owned network')
        report['namespace_after'] = snapshot()
        report['pass'] = report['namespace_after'] == report['namespace_before']
    except Exception as exc:
        report['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        for proc in reversed(processes):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=9)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
        for child in children:
            if alive(child):
                os.kill(child, signal.SIGKILL)
        for output in outputs:
            output.close()
        report['logs'] = {p.name: p.read_text(errors='replace')[-6000:] for p in ROOT.glob('*.log')}
        report['owned_processes_stopped'] = until(lambda: all(not alive(pid) for pid in children), 3)
        report['pass'] = bool(report['pass'] and report['owned_processes_stopped'])
        (EVIDENCE / 'result.json').write_text(json.dumps(report, indent=2))
        os.chmod(EVIDENCE / 'result.json', 0o600)
    print(json.dumps({'pass': report['pass'], 'error': report.get('error')}), flush=True)


if __name__ == '__main__':
    main()
