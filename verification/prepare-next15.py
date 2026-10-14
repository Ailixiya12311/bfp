from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parents[1]; parent=ROOT/'.staging/r9-next14'; stage=ROOT/'.staging/r9-next15'; frozen=json.loads((parent/'verification/r9-next14/local-gate-attempt02/source-manifest.json').read_text(encoding='utf-8')); rows=frozen['source_manifest']; stage.mkdir(exist_ok=False)
for row in rows:
 data=(parent/row['path']).read_bytes()
 if hashlib.sha256(data).hexdigest()!=row['sha256']: raise ValueError('parent changed: '+row['path'])
 target=stage/row['path']; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(data)
(stage/'verification').mkdir()
proof={'parent_revision':'r9-next14','parent_manifest_sha256':frozen['manifest_sha256'],'parent_source_file_count':len(rows),'copied_source_manifest':rows,'all_copied_hashes_match':all(hashlib.sha256((stage/r['path']).read_bytes()).hexdigest()==r['sha256'] for r in rows)}
(stage/'verification/parent-source-manifest.json').write_text(json.dumps(proof,indent=2)+'\n')
print(json.dumps({'stage':str(stage),'source_count':len(rows),'all_copied_hashes_match':proof['all_copied_hashes_match']}))
