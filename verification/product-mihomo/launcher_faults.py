"""Fault injection against the packaged launcher inside an owned netns."""
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

ROOT = pathlib.Path('/tmp/bfp-launcher-faults')
EVIDENCE = pathlib.Path('/evidence')


def call(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=10)


def alive(pid):
    try:
        # An orphan may briefly remain a zombie until the container init reaps
        # it; a zombie owns neither a listening socket nor the instance lock.
        state = pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
        return state != 'Z'
    except FileNotFoundError:
        return False


def port_open():
    try:
        with socket.create_connection(('127.0.0.1', 17890), timeout=.2):
            return True
    except OSError:
        return False


def until(predicate, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(.1)
    return bool(predicate())


def native_child(proc):
    for task in pathlib.Path(f'/proc/{proc.pid}/task').iterdir():
        for text in (task / 'children').read_text().split():
            pid = int(text)
            try:
                if pathlib.Path(f'/proc/{pid}/exe').resolve() == pathlib.Path('/bfp/mihomo'):
                    return pid
            except FileNotFoundError:
                pass
    raise RuntimeError('native child PID was not found')


def main():
    report = {'pass': False, 'scope': 'packaged launcher faults in owned Linux netns; no WAN or host routes', 'cases': {}}
    processes, outputs, children = [], [], []
    try:
        ROOT.mkdir(mode=0o700)
        for directory in ('bin', 'configs'):
            (ROOT / directory).mkdir(mode=0o700)
        for name, source in (('bfp-linux-amd64', '/bfp/bfp'), ('mihomo-bfp-linux-amd64', '/bfp/mihomo')):
            (ROOT / 'bin' / name).symlink_to(source)
        shutil.copyfile('/bfp/start-native.sh', ROOT / 'start-native.sh')
        report['launcher_sha256'] = hashlib.sha256((ROOT / 'start-native.sh').read_bytes()).hexdigest()
        generated_keys = call(['/bfp/bfp', 'keygen', '-out', str(ROOT / 'credentials')])
        if generated_keys.returncode:
            raise RuntimeError('fixture credential generation failed: ' + generated_keys.stderr.strip())
        for mode in ('proxy', 'tun'):
            yaml = pathlib.Path(f'/bfp/configs/native-{mode}.yaml').read_text()
            yaml = yaml.replace('  auto-route: true', '  auto-route: false')
            yaml = yaml.replace('  auto-detect-interface: true', '  auto-detect-interface: false')
            (ROOT / 'configs' / f'native-{mode}.yaml').write_text(yaml)
        marker = ROOT / 'runtime/bfp-tun-supervisor.env'
        generated = ROOT / 'runtime/native-tun.generated.yaml'

        def device():
            match = re.search(r'^device=(bfp-tun-[0-9a-f]{7})$', marker.read_text(), re.M)
            if not match:
                raise RuntimeError('invalid device marker')
            return match.group(1)

        def device_absent(name):
            return call(['ip', 'link', 'show', 'dev', name]).returncode != 0

        def start(name, mode):
            log = open(ROOT / f'{name}.log', 'wb')
            outputs.append(log)
            proc = subprocess.Popen(['sh', str(ROOT / 'start-native.sh'), mode], stdout=log, stderr=log)
            processes.append(proc)
            if not until(lambda: proc.poll() is not None or port_open(), 12) or proc.poll() is not None:
                raise RuntimeError(f'{name} did not start')
            if mode == 'tun' and not until(lambda: 'BFP TUN interface ready' in (ROOT / f'{name}.log').read_text(), 12):
                raise RuntimeError(f'{name} did not create TUN')
            pid = native_child(proc)
            children.append(pid)
            return proc, pid

        for mode in ('proxy', 'tun'):
            proc, pid = start(mode + '-parent-kill', mode)
            old_device = device() if mode == 'tun' else None
            proc.kill()
            proc.wait(timeout=3)
            stopped = until(lambda: not alive(pid) and not port_open(), 7)
            lock_result = call(['flock', '-n', str(ROOT / 'runtime/native.lock'), 'true'])
            case = {'launcher_exit_code': proc.returncode, 'native_stopped': stopped,
                    'mixed_port_closed': not port_open(), 'lock_released': lock_result.returncode == 0,
                    'device_removed_by_native': old_device is None or device_absent(old_device)}
            report['cases'][mode + '_launcher_sigkill'] = case
            if proc.returncode != -signal.SIGKILL or not all(case[k] for k in ('native_stopped', 'mixed_port_closed', 'lock_released', 'device_removed_by_native')):
                raise RuntimeError(mode + ' launcher SIGKILL left native process or lock alive')
            # Reenter through proxy after a TUN crash as well: recovery must
            # not depend on choosing the same mode for the next launch.
            restarted, restarted_pid = start(mode + '-restart', 'proxy')
            case['restart_succeeded'] = port_open() and alive(restarted_pid)
            case['stale_marker_removed'] = not marker.exists() and not generated.exists()
            restarted.terminate()
            restarted.wait(timeout=9)
            case['restart_sigterm_exit_code'] = restarted.returncode
            if not case['restart_succeeded'] or not case['stale_marker_removed'] or restarted.returncode != 143:
                raise RuntimeError(mode + ' restart recovery failed')

        for mode in ('proxy', 'tun'):
            proc, pid = start(mode + '-child-kill', mode)
            owned_device = device() if mode == 'tun' else None
            os.kill(pid, signal.SIGKILL)
            proc.wait(timeout=9)
            case = {'launcher_exit_code': proc.returncode, 'mixed_port_closed': not port_open(),
                    'device_removed': owned_device is None or device_absent(owned_device),
                    'marker_removed': not marker.exists(), 'config_removed': not generated.exists(),
                    'lock_released': call(['flock', '-n', str(ROOT / 'runtime/native.lock'), 'true']).returncode == 0}
            report['cases'][mode + '_native_sigkill'] = case
            if proc.returncode != 137 or not all(case[k] for k in ('mixed_port_closed', 'device_removed', 'marker_removed', 'config_removed', 'lock_released')):
                raise RuntimeError(mode + ' native SIGKILL cleanup failed')
        report['pass'] = True
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
        for pid in children:
            if alive(pid):
                os.kill(pid, signal.SIGKILL)
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
