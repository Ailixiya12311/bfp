from pathlib import Path
import hashlib,json,shutil
ROOT=Path(__file__).resolve().parents[1]
PARENT=ROOT/'.staging/r9-next23'
DEST=ROOT/'.staging/r9-next24'
DIRS=('adapter','classification','clientconfig','cmd','gateway','internal','obfuscation','protocol','scheduler','security','session','tests')
if DEST.exists(): raise SystemExit(f'destination exists: {DEST}')
files=[PARENT/'go.mod',PARENT/'go.sum']
for d in DIRS: files.extend((PARENT/d).rglob('*.go'))
rows=[]
for p in sorted(files):
    rel=p.relative_to(PARENT).as_posix()
    rows.append({'path':rel,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
DEST.mkdir(parents=True)
for row in rows:
    src=PARENT/row['path']; dst=DEST/row['path']; dst.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(src,dst)
evidence=DEST/'verification/parent-binding'; evidence.mkdir(parents=True)
record={'candidate':'v0.1-r9-next24','parent_revision':'v0.1-r9-next23','parent':str(PARENT),'parent_file_count':len(rows),'parent_source':rows,'modification':'clientconfig/external_test.go offline module vendor staging only','parent_source_manifest_sha256':hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest(),'remote_race_started':False,'complete_gate':'not_run'}
(evidence/'initial-parent.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'candidate':str(DEST),'parent_files':len(rows),'parent_binding_sha256':record['parent_source_manifest_sha256']}))