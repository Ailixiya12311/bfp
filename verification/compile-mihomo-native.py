"""Bounded compilation of the actual pinned Mihomo package graph."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
CHECKOUT = ROOT / '.staging/native-upstream/mihomo-88dcbf7f1614a67c3b36b848ee3592dfa92ada36'
OUT = ROOT / 'integrations/mihomo/results/compile-attempt01'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot():
    return [{'path': p.relative_to(CHECKOUT).as_posix(), 'sha256': digest(p)}
            for p in sorted(CHECKOUT.rglob('*')) if p.is_file() and (p.suffix == '.go' or p.name in ('go.mod', 'go.sum'))]


def main():
    OUT.mkdir(parents=True, exist_ok=False)
    before = snapshot()
    (OUT / 'source-before.json').write_text(json.dumps(before, indent=2), encoding='utf-8')
    # Preserve the current BFP additions even if this attempt only exposes a
    # compile or dependency failure. Module changes from -mod=mod are recorded.
    for row in before:
        if 'bfp' in row['path'] or row['path'] in ('adapter/parser.go', 'constant/adapters.go', 'go.mod', 'go.sum'):
            source = OUT / 'source' / row['path']
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes((CHECKOUT / row['path']).read_bytes())
    command = ['go', 'test', '-mod=mod', '-p', '1', '-run', '^$', './adapter/outbound', './adapter']
    started = time.monotonic()
    env = os.environ.copy()
    env.update(GOWORK='off', GOTOOLCHAIN='local', GOMAXPROCS='2')
    expired = False
    with (OUT / 'compile.log').open('wb') as log:
        process = subprocess.Popen(command, cwd=CHECKOUT, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            code = process.wait(timeout=240)
        except subprocess.TimeoutExpired:
            expired = True
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True, timeout=15)
            code = process.wait(timeout=15)
    after = snapshot()
    (OUT / 'source-after.json').write_text(json.dumps(after, indent=2), encoding='utf-8')
    result = {'command': command, 'exit_code': code, 'outer_timeout': expired,
              'compile_pass': code == 0 and not expired, 'runtime_tests': 'not_run',
              'elapsed_seconds': round(time.monotonic()-started, 3),
              'scope': 'real pinned Mihomo adapter/outbound and adapter package graph; local dependency downloads only',
              'remote_hosts': 'not_contacted', 'before': before, 'after': after}
    (OUT / 'summary.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('compile_pass', 'exit_code', 'outer_timeout', 'elapsed_seconds')}))
    return 0 if result['compile_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
