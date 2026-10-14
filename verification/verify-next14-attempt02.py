from pathlib import Path
import hashlib,json,os,subprocess,time
ROOT=Path(__file__).resolve().parents[1]; STAGE=ROOT/'.staging/r9-next14'; OUT=STAGE/'verification/r9-next14/local-gate-attempt02'; OUT.mkdir(parents=True,exist_ok=False)
source=[]
for n in ('go.mod','go.sum'): source.append(STAGE/n)
for d in ('adapter','classification','cmd','gateway','internal','obfuscation','protocol','scheduler','security','session','tests'): source.extend((STAGE/d).rglob('*.go'))
rows=[{'path':p.relative_to(STAGE).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(source)]
manifest=hashlib.sha256((json.dumps(rows,sort_keys=True,indent=2)+'\n').encode()).hexdigest(); (OUT/'source-manifest.json').write_text(json.dumps({'revision':'v0.1-r9-next14-attempt02','file_count':len(rows),'manifest_sha256':manifest,'source_manifest':rows},indent=2)+'\n')
env=dict(os.environ,GOTOOLCHAIN='local',CGO_ENABLED='0')
checks={}; started=time.monotonic()
cmd=['go','test','-json','-p','1','./...','-count=1','-timeout=180s']; log=OUT/'go_test.log'
with log.open('w',encoding='utf-8') as f:
 try:r=subprocess.run(cmd,cwd=STAGE,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=240); code=r.returncode; timed=False
 except subprocess.TimeoutExpired:code=None;timed=True
text=log.read_text(encoding='utf-8',errors='replace'); events=[]
for line in text.splitlines():
 try:events.append(json.loads(line))
 except ValueError:pass
checks['go_test']={'command':cmd,'exit_code':code,'pass':code==0 and not timed,'outer_timeout':timed,'failed_tests':[e.get('Test') for e in events if e.get('Action')=='fail' and 'Test' in e],'failed_packages':[e.get('Package') for e in events if e.get('Action')=='fail' and 'Test' not in e],'panic_events':[e for e in events if 'panic:' in e.get('Output','')],'tests_without_terminal_event':[],'packages_passed':sum(e.get('Action')=='pass' and 'Test' not in e for e in events),'top_level_tests_passed':sum(e.get('Action')=='pass' and 'Test' in e and '/' not in e['Test'] for e in events)}
for key,cmd,extra in [('go_vet',['go','vet','./...'],{}),('build_windows',['go','build','-trimpath','-o','bfp-r9-next14-attempt02-windows.exe','./cmd/bfp'],{'GOOS':'windows','GOARCH':'amd64'}),('build_linux',['go','build','-trimpath','-o','bfp-r9-next14-attempt02-linux-amd64','./cmd/bfp'],{'GOOS':'linux','GOARCH':'amd64'})]:
 log=OUT/(key+'.log'); e=dict(env,**extra)
 with log.open('w') as f:
  try:r=subprocess.run(cmd,cwd=STAGE,env=e,stdout=f,stderr=subprocess.STDOUT,timeout=240); code=r.returncode; timed=False
  except subprocess.TimeoutExpired:code=None;timed=True
 checks[key]={'command':cmd,'exit_code':code,'pass':code==0 and not timed,'outer_timeout':timed,'raw_log':str(log.relative_to(ROOT).as_posix())}
live=[{'path':p.relative_to(STAGE).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(source)]
report={'revision':'v0.1-r9-next14-attempt02','source_manifest_sha256':manifest,'source_file_count':len(rows),'checks':checks,'source_unchanged':live==rows,'local_checks_pass':live==rows and all(v['pass'] for v in checks.values()),'acceptance_complete':False,'production_ready':False,'released':False,'elapsed_seconds':round(time.monotonic()-started,3)}
(OUT/'local-summary.json').write_text(json.dumps(report,indent=2)+'\n'); print(json.dumps(report),flush=True); raise SystemExit(0 if report['local_checks_pass'] else 1)
