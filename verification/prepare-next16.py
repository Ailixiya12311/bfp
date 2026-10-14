"""Copy the verified next15 source into an independent next16 policy candidate."""
from pathlib import Path
import hashlib
import json
import shutil

ROOT = Path(__file__).resolve().parents[1]
PARENT = ROOT / '.staging/r9-next15'
STAGE = ROOT / '.staging/r9-next16'
assert STAGE.resolve().is_relative_to((ROOT / '.staging').resolve())
frozen = json.loads((PARENT / 'verification/r9-next15/local-gate-attempt03/source-manifest.json').read_text(encoding='utf-8'))
evidence = json.loads((PARENT / 'verification/r9-next15/evidence-index.json').read_text(encoding='utf-8'))
assert evidence['source_bound_local_fuzz_and_race_pass'] and evidence['current_source_matches_frozen']
assert evidence['source_manifest_sha256'] == frozen['manifest_sha256']
rows = frozen['source_manifest']
for row in rows:
    path = Path(row['path'])
    assert not path.is_absolute() and '..' not in path.parts
    assert hashlib.sha256((PARENT / path).read_bytes()).hexdigest() == row['sha256']
STAGE.mkdir(exist_ok=False)
for row in rows:
    path = Path(row['path'])
    destination = STAGE / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PARENT / path, destination)
    assert hashlib.sha256(destination.read_bytes()).hexdigest() == row['sha256']
out = STAGE / 'verification'
out.mkdir()
report = {'parent_revision': 'v0.1-r9-next15', 'revision': 'v0.1-r9-next16',
          'parent_manifest_sha256': frozen['manifest_sha256'], 'file_count': len(rows),
          'copied_source_manifest': rows, 'parent_evidence': str((PARENT / 'verification/r9-next15/evidence-index.json').resolve()),
          'copy_verified': True, 'acceptance_complete': False, 'production_ready': False, 'released': False}
with (out / 'parent-source-manifest.json').open('x', encoding='utf-8') as output:
    json.dump(report, output, indent=2)
    output.write('\n')
print(json.dumps({'stage': str(STAGE), 'files': len(rows), 'parent_manifest_sha256': frozen['manifest_sha256'], 'copy_verified': True}), flush=True)
