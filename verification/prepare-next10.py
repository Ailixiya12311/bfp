"""Create the next10 source boundary exclusively from frozen next9."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
parent = ROOT / '.staging/r9-next9'
stage = ROOT / '.staging/r9-next10'
frozen = json.loads((parent / 'verification/r9-next9/local-gate/source-manifest.json').read_text(encoding='utf-8'))
rows = frozen['source_manifest']
contents = []
for row in rows:
    data = (parent / row['path']).read_bytes()
    if hashlib.sha256(data).hexdigest() != row['sha256']:
        raise ValueError('frozen parent changed: ' + row['path'])
    contents.append((row, data))
stage.mkdir(exist_ok=False)
for row, data in contents:
    target = stage / row['path']
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as output:
        output.write(data)
proof = {'parent_revision': 'r9-next9', 'parent_manifest_sha256': frozen['manifest_sha256'],
         'parent_source_file_count': len(rows), 'copied_source_manifest': rows,
         'all_copied_hashes_match': all(hashlib.sha256((stage / row['path']).read_bytes()).hexdigest() == row['sha256'] for row in rows)}
(stage / 'verification').mkdir()
(stage / 'verification/parent-source-manifest.json').write_text(json.dumps(proof, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'stage': str(stage), 'source_count': len(rows), 'all_copied_hashes_match': proof['all_copied_hashes_match']}))
