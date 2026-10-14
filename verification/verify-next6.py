"""Run one local diagnostics gate on next6 without altering prior evidence."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next6'
OUT = STAGE / 'verification/r9-next6/local-gate'
SOURCE_DIRS = ('adapter', 'classification', 'cmd', 'gateway', 'internal', 'obfuscation', 'protocol', 'scheduler', 'security', 'session', 'tests')


def manifest():
    paths = [STAGE / 'go.mod', STAGE / 'go.sum']
    for directory in SOURCE_DIRS:
        paths.extend((STAGE / directory).rglob('*.go'))
    return [{'path': p.relative_to(STAGE).as_posix(), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(paths)]


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    OUT.mkdir(parents=True, exist_ok=False)
    rows = manifest()
    digest = hashlib.sha256((json.dumps(rows, sort_keys=True, indent=2) + '\n').encode()).hexdigest()
    save(OUT / 'source-manifest.json', {'revision': 'v0.1-r9-next6', 'file_count': len(rows), 'manifest_sha256': digest, 'source_manifest': rows})
    report = {'revision': 'v0.1-r9-next6', 'source_manifest_sha256': digest, 'source_file_count': len(rows),
              'pass': False, 'production_ready': False, 'released': False, 'checks': {}, 'binaries': [],
              'independent_linux_race': {'status': 'not_run'}, 'wan': {'status': 'not_run'}}
    started = time.monotonic()
    env = dict(os.environ, GOTOOLCHAIN='local', CGO_ENABLED='0')
    commands = [
        ('go_test', ['go', 'test', '-json', '-p', '1', './...', '-count=1', '-timeout=180s'], env),
        ('go_vet', ['go', 'vet', './...'], env),
    ]
    for platform in ('windows', 'linux'):
        name = 'bfp-r9-next6-windows.exe' if platform == 'windows' else 'bfp-r9-next6-linux-amd64'
        commands.append(('build_' + platform, ['go', 'build', '-trimpath', '-o', name, './cmd/bfp'], dict(env, GOOS=platform, GOARCH='amd64')))
    try:
        for key, command, environment in commands:
            result = subprocess.run(command, cwd=STAGE, env=environment, capture_output=True, encoding='utf-8', errors='replace', timeout=240)
            log = OUT / (key + '.log')
            log.write_text(result.stdout + result.stderr, encoding='utf-8')
            entry = {'command': command, 'exit_code': result.returncode, 'pass': result.returncode == 0, 'raw_log': str(log.relative_to(ROOT).as_posix())}
            if key == 'go_test':
                events = []
                for line in result.stdout.splitlines():
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        pass
                entry['failed_tests'] = [e.get('Test') for e in events if e.get('Action') == 'fail' and 'Test' in e]
                entry['packages_passed'] = sum(e.get('Action') == 'pass' and 'Test' not in e for e in events)
                entry['top_level_tests_passed'] = sum(e.get('Action') == 'pass' and 'Test' in e and '/' not in e['Test'] for e in events)
            report['checks'][key] = entry
            if key.startswith('build_') and entry['pass']:
                binary = STAGE / command[4]
                report['binaries'].append({'platform': key[6:], 'path': binary.relative_to(ROOT).as_posix(), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()})
            print(json.dumps({'stage': key, **entry}), flush=True)
        report['source_unchanged'] = rows == manifest()
        report['local_checks_pass'] = report['source_unchanged'] and all(x['pass'] for x in report['checks'].values())
        # Local checks do not establish independent race/WAN acceptance.
        report['pass'] = False
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        save(OUT / 'local-summary.json', report)
    print(json.dumps({'path': str((OUT / 'local-summary.json').resolve()), 'local_checks_pass': report.get('local_checks_pass'), 'acceptance_pass': False}), flush=True)


if __name__ == '__main__':
    main()
