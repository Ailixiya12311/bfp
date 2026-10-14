"""Prepare the native-adapter prerequisite candidate from exact reviewed sources."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / '.staging/r9-next21'
DEST = ROOT / '.staging/r9-next22'
CONFIG = ROOT / '.staging/r9-next22-config'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    frozen_path = BASE / 'verification/r9-next21/local-gate-attempt02/source-manifest.json'
    frozen = json.loads(frozen_path.read_text(encoding='utf-8'))
    for row in frozen['source_manifest']:
        if sha(BASE / row['path']) != row['sha256']:
            raise RuntimeError('next21 differs from attempt02 freeze: ' + row['path'])
    parent = json.loads((CONFIG / 'verification/config-facade/parent-source-manifest.json').read_text(encoding='utf-8'))
    if isinstance(parent, dict):
        parent = parent.get('source_manifest', parent.get('files'))
    for row in parent:
        if sha(ROOT / '.staging/r9-next20' / row['path']) != row['sha256'] or sha(CONFIG / row['path']) != row['sha256']:
            raise RuntimeError('config parent or copied core changed')
    DEST.mkdir(exist_ok=False)
    for row in frozen['source_manifest']:
        target = DEST / row['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write((BASE / row['path']).read_bytes())
    added = []
    for source in sorted((CONFIG / 'clientconfig').iterdir()):
        if not source.is_file():
            continue
        target = DEST / 'clientconfig' / source.name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(source.read_bytes())
        added.append({'path': target.relative_to(DEST).as_posix(), 'sha256': sha(target)})
    evidence = DEST / 'verification/merge'
    evidence.mkdir(parents=True)
    with (evidence / 'initial-parent-and-config.json').open('x', encoding='utf-8') as stream:
        json.dump({'parent': str(BASE), 'parent_manifest': str(frozen_path),
                   'parent_manifest_sha256': frozen['manifest_sha256'],
                   'parent_source_files': frozen['file_count'], 'parent_source': frozen['source_manifest'],
                   'config_branch': str(CONFIG), 'config_parent': str(ROOT / '.staging/r9-next20'),
                   'config_added': added, 'prior_results_copied': False,
                   'complete_gate': 'not_run', 'acceptance_complete': False}, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'candidate': str(DEST), 'parent_files': frozen['file_count'], 'config_added': len(added)}))


if __name__ == '__main__':
    main()
