"""Create next9 exclusively from the frozen next8 source, without credentials or runs."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
parent = ROOT / '.staging/r9-next8'
stage = ROOT / '.staging/r9-next9'
frozen = json.loads((parent / 'verification/r9-next8/local-gate/source-manifest.json').read_text())
stage.mkdir(exist_ok=False)
rows = frozen['source_manifest']
for row in rows:
    data = (parent / row['path']).read_bytes()
    if hashlib.sha256(data).hexdigest() != row['sha256']:
        raise ValueError('frozen parent source changed: ' + row['path'])
    target = stage / row['path']
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as destination:
        destination.write(data)
proof = {'parent_revision': 'r9-next8', 'parent_manifest_sha256': frozen['manifest_sha256'],
         'parent_source_file_count': len(rows), 'copied_source_manifest': rows,
         'all_copied_hashes_match': all(hashlib.sha256((stage / row['path']).read_bytes()).hexdigest() == row['sha256'] for row in rows)}
(stage / 'verification').mkdir()
(stage / 'verification/parent-source-manifest.json').write_text(json.dumps(proof, indent=2) + '\n')
print(json.dumps({'stage': str(stage), 'source_count': len(rows), 'all_copied_hashes_match': proof['all_copied_hashes_match']}))
