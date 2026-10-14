"""Source-bound real Mihomo native package tests and CLI build, without WAN."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
CHECKOUT = ROOT / '.staging/native-upstream/mihomo-88dcbf7f1614a67c3b36b848ee3592dfa92ada36'
BFP = ROOT / '.staging/r9-next23'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source(stage):
    return [{'path': p.relative_to(stage).as_posix(), 'sha256': sha(p)}
            for p in sorted(stage.rglob('*')) if p.is_file()
            and (p.suffix == '.go' or p.name in ('go.mod', 'go.sum'))
            and 'verification' not in p.relative_to(stage).parts]


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def run(out, name, command, env, timeout):
    started = time.monotonic()
    expired = False
    log_path = out / (name+'.log')
    with log_path.open('xb') as log:
        process = subprocess.Popen(command, cwd=CHECKOUT, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            expired = True
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True, timeout=15)
            code = process.wait(timeout=15)
    result = {'command': command, 'exit_code': code, 'pass': code == 0 and not expired,
              'outer_timeout': expired, 'elapsed_seconds': round(time.monotonic()-started, 3),
              'raw_log': str(log_path)}
    if name == 'native_tests':
        events = []
        for line in log_path.read_text(encoding='utf-8', errors='replace').splitlines():
            try: events.append(json.loads(line))
            except ValueError: pass
        result.update(
            packages_passed=sum(e.get('Action') == 'pass' and 'Test' not in e for e in events),
            top_level_tests_passed=sum(e.get('Action') == 'pass' and 'Test' in e and '/' not in e['Test'] for e in events),
            failed_tests=[{'package': e.get('Package'), 'test': e['Test']} for e in events if e.get('Action') == 'fail' and 'Test' in e])
    print(json.dumps({'phase': name, **result}), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--attempt', required=True)
    args = parser.parse_args()
    if not args.attempt.isdigit(): raise ValueError('numeric attempt required')
    out = ROOT / 'integrations/mihomo/results' / ('native-attempt'+args.attempt)
    out.mkdir(parents=True, exist_ok=False)
    initial = source(CHECKOUT)
    dependency = source(BFP)
    write(out/'source-before-prepare.json', initial)
    write(out/'bfp-source.json', dependency)
    # Keep original changed files, including a failed native attempt's source.
    baseline = json.loads((ROOT/'integrations/mihomo/upstream-source/source-manifest.json').read_text(encoding='utf-8'))
    rows = baseline.get('files', baseline.get('source_manifest', [])) if isinstance(baseline, dict) else baseline
    upstream = {r['path']: r['sha256'] for r in rows}
    changed = [r for r in initial if upstream.get(r['path']) != r['sha256']]
    for row in changed:
        target = out/'source'/row['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((CHECKOUT/row['path']).read_bytes())
    env = os.environ.copy()
    env.update(GOWORK='off', GOTOOLCHAIN='local', GOMAXPROCS='2', CGO_ENABLED='0')
    checks = {}
    checks['prepare_compile'] = run(out, 'prepare_compile',
        ['go','test','-mod=mod','-p','1','-run','^$','./adapter/outbound','./adapter','./tunnel'], env, 240)
    frozen = source(CHECKOUT)
    write(out/'source-frozen.json', frozen)
    write(out/'patch-paths.json', changed)
    if checks['prepare_compile']['pass']:
        checks['native_tests'] = run(out, 'native_tests',
            ['go','test','-json','-mod=readonly','-p','1','-count=1','-timeout=90s','-run','^TestBFP','./adapter/outbound','./adapter','./tunnel'], env, 180)
        checks['vet'] = run(out, 'vet', ['go','vet','-mod=readonly','./adapter/outbound','./adapter','./tunnel'], env, 120)
        checks['build_windows'] = run(out, 'build_windows', ['go','build','-mod=readonly','-trimpath','-o',str(out/'mihomo-bfp-windows.exe'),'.'], env, 180)
        checks['build_linux_amd64'] = run(out, 'build_linux_amd64', ['go','build','-mod=readonly','-trimpath','-o',str(out/'mihomo-bfp-linux-amd64'),'.'], dict(env,GOOS='linux',GOARCH='amd64'), 180)
    result = {'upstream_commit':'88dcbf7f1614a67c3b36b848ee3592dfa92ada36',
              'bfp':str(BFP),'checks':checks,'source_unchanged':source(CHECKOUT)==frozen,
              'bfp_source_unchanged':source(BFP)==dependency,
              'native_checks_pass':all(r['pass'] for r in checks.values()) and len(checks)==5 and source(CHECKOUT)==frozen and source(BFP)==dependency,
              'race':'not_run','wan':'not_run','tun':'not_run','release':False}
    result['binaries'] = [{'path':str(p),'sha256':sha(p)} for p in sorted(out.iterdir()) if p.name in ('mihomo-bfp-windows.exe','mihomo-bfp-linux-amd64')]
    write(out/'summary.json',result)
    print(json.dumps({'path':str(out/'summary.json'),'native_checks_pass':result['native_checks_pass']}),flush=True)
    return 0 if result['native_checks_pass'] else 1


if __name__ == '__main__': raise SystemExit(main())
