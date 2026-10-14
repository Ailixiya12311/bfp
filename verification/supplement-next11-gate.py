"""Preserve the formal timeout, then run only checks never started there."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next11'
GATE = STAGE / 'verification/r9-next11/local-gate'
OUT = STAGE / 'verification/r9-next11/post-timeout-checks'
OUT.mkdir(parents=True, exist_ok=False)
frozen = json.loads((GATE / 'source-manifest.json').read_text(encoding='utf-8'))
def unchanged():
    rows = frozen['source_manifest']
    expected = {r['path']: r['sha256'] for r in rows}
    actual = [STAGE / 'go.mod', STAGE / 'go.sum']
    for directory in ('adapter','classification','cmd','gateway','internal','obfuscation','protocol','scheduler','security','session','tests'):
        actual.extend((STAGE / directory).rglob('*.go'))
    return {p.relative_to(STAGE).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in actual} == expected
timeout = {
    'formal_gate_preserved': True, 'formal_helper_exit_code': 1,
    'command': ['go','test','-json','-p','1','./...','-count=1','-timeout=180s'],
    'outer_budget_seconds': 240, 'formal_elapsed_seconds': 240.015,
    'failure': 'subprocess.TimeoutExpired', 'source_unchanged_on_audit': unchanged(),
    'evidence_gap': 'Original capture_output helper did not persist TimeoutExpired partial stdout/stderr. Named progress, failed tests, and package completion cannot be inferred from the incomplete formal summary.',
    'checks_not_started_in_formal_run': ['go_vet','build_windows','build_linux'],
    'acceptance_complete': False, 'production_ready': False, 'released': False,
}
with (GATE / 'timeout-audit.json').open('x', encoding='utf-8') as output:
    output.write(json.dumps(timeout, indent=2) + '\n')
env = dict(os.environ, GOTOOLCHAIN='local', CGO_ENABLED='0')
commands = [('go_vet', ['go','vet','./...'], env)]
for platform in ('windows','linux'):
    name = 'bfp-r9-next11-windows.exe' if platform == 'windows' else 'bfp-r9-next11-linux-amd64'
    commands.append(('build_'+platform, ['go','build','-trimpath','-o',name,'./cmd/bfp'], dict(env, GOOS=platform, GOARCH='amd64')))
report = {'source_manifest_sha256': frozen['manifest_sha256'], 'checks': {}, 'binaries': [], 'formal_go_test_complete': False,
          'local_checks_pass': False, 'acceptance_complete': False, 'production_ready': False, 'released': False}
for key, command, environment in commands:
    result = subprocess.run(command, cwd=STAGE, env=environment, capture_output=True, timeout=240)
    (OUT / (key+'.log')).write_bytes(result.stdout+result.stderr)
    report['checks'][key] = {'command': command, 'exit_code': result.returncode, 'pass': result.returncode == 0}
    if key.startswith('build_') and result.returncode == 0:
        binary = STAGE / command[4]
        report['binaries'].append({'platform': key[6:], 'path': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()})
    print(json.dumps({'check':key,**report['checks'][key]}), flush=True)
report['source_unchanged'] = unchanged()
with (OUT / 'summary.json').open('x',encoding='utf-8') as output:
    output.write(json.dumps(report,indent=2)+'\n')
print(json.dumps({'path':str(OUT/'summary.json'),'source_unchanged':report['source_unchanged'],'local_checks_pass':False}),flush=True)
