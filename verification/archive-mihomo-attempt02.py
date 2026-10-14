"""Preserve exact post-prepare source bytes from the failed native attempt."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
TREE = ROOT / '.staging/native-upstream/mihomo-88dcbf7f1614a67c3b36b848ee3592dfa92ada36'
OUT = ROOT / 'integrations/mihomo/results/native-attempt02'
frozen = json.loads((OUT / 'source-frozen.json').read_text(encoding='utf-8'))
baseline = json.loads((ROOT / 'integrations/mihomo/upstream-source/source-manifest.json').read_text(encoding='utf-8'))
upstream = {row['path']: row['sha256'] for row in baseline}
assert (OUT / 'summary.json').exists(), 'attempt must be terminal before edits'
assert json.loads((OUT / 'summary.json').read_text())['native_checks_pass'] is False
for row in frozen:
    assert hashlib.sha256((TREE / row['path']).read_bytes()).hexdigest() == row['sha256'], row['path']
archive = OUT / 'source-frozen-bytes'
archive.mkdir(exist_ok=False)
changed = []
for row in frozen:
    if upstream.get(row['path']) == row['sha256']:
        continue
    target = archive / row['path']
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((TREE / row['path']).read_bytes())
    changed.append(row)
(OUT / 'frozen-byte-archive.json').write_text(json.dumps({
    'exact_post_prepare_source': True,
    'full_source_manifest': 'source-frozen.json',
    'changed_files': changed,
    'unchanged_files_baseline': '../../upstream-source/source-manifest.json',
    'original_failure_preserved': True,
}, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'changed_files_preserved': len(changed), 'path': str(archive)}))
