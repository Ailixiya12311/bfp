"""Verify and build a fresh named experimental revision; never overwrite it."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE_DIRS = ('adapter','classification','cmd','gateway','internal','obfuscation','protocol','scheduler','security','session','tests')

def manifest():
    files = [ROOT/'go.mod', ROOT/'go.sum']
    for directory in SOURCE_DIRS:
        files.extend((ROOT/directory).rglob('*.go'))
    return [{'path':p.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(files)]

def execute(revision):
    if not re.fullmatch(r'v[0-9]+\.[0-9]+-r[0-9]+', revision):
        raise ValueError('invalid revision')
    output = ROOT/'verification'/revision
    output.mkdir(parents=True, exist_ok=False)
    (ROOT/'bin').mkdir(exist_ok=True)
    binaries = [ROOT/'bin'/f'bfp-{revision}.exe', ROOT/'bin'/f'bfp-{revision}-linux-amd64']
    if any(p.exists() for p in binaries): raise ValueError('revision binary exists')
    before = manifest()
    report = {'revision':revision, 'pass':False, 'source_manifest':before, 'checks':{}, 'binaries':[]}
    started = time.monotonic()
    environment = dict(os.environ, GOTOOLCHAIN='local', CGO_ENABLED='0')
    checks = [
        ('unit', ['go','test','-json','./...','-count=1','-timeout=45s'], 90),
        ('ticket_repeat', ['go','test','-json','./session','-run','TicketAdversarial|RuntimeTicket|UDPHandshakeConfirmation','-count=5','-timeout=60s'], 90),
        ('vet', ['go','vet','./...'], 60),
        ('modules', ['go','mod','verify'], 30),
        ('lab', [sys.executable,'-m','unittest','discover','-s','lab','-p','test_*.py','-v'], 30),
    ]
    try:
        for name, command, timeout in checks:
            result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
            (output/(name+'.log')).write_text(result.stdout+result.stderr,encoding='utf-8')
            entry = {'command':command,'exit_code':result.returncode,'pass':result.returncode==0}
            if name in ('unit','ticket_repeat'):
                events=[]
                for line in result.stdout.splitlines():
                    try: events.append(json.loads(line))
                    except json.JSONDecodeError: pass
                entry.update({'packages_passed':len([e for e in events if e.get('Action')=='pass' and 'Test' not in e]), 'top_level_pass_events':len([e for e in events if e.get('Action')=='pass' and e.get('Test') and '/' not in e['Test']]), 'test_pass_events':len([e for e in events if e.get('Action')=='pass' and 'Test' in e]), 'skipped_tests':[e.get('Test') for e in events if e.get('Action')=='skip' and 'Test' in e]})
            report['checks'][name]=entry
            print(json.dumps({'stage':name, **entry}),flush=True)
            if result.returncode: return report
        for binary, platform in zip(binaries, ('windows','linux')):
            build_environment=dict(environment,GOOS=platform,GOARCH='amd64')
            command=['go','build','-trimpath','-o',str(binary),'./cmd/bfp']
            result=subprocess.run(command,cwd=ROOT,env=build_environment,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
            report['checks']['build_'+platform]={'command':command,'exit_code':result.returncode,'pass':result.returncode==0}
            (output/('build_'+platform+'.log')).write_text(result.stdout+result.stderr,encoding='utf-8')
            if result.returncode: return report
            data=binary.read_bytes()
            report['binaries'].append({'path':binary.relative_to(ROOT).as_posix(),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'platform':platform})
        after=manifest()
        report['source_unchanged']=before==after
        report['pass']=report['source_unchanged'] and all(x['pass'] for x in report['checks'].values())
    finally:
        report['elapsed_seconds']=round(time.monotonic()-started,3)
        (output/'validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision',required=True)
    args=parser.parse_args()
    report=execute(args.revision)
    print(json.dumps(report,ensure_ascii=False),flush=True)
    raise SystemExit(0 if report['pass'] else 1)
