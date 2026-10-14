"""Create a separate exact next22 child for restored numeric-target metadata."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
PARENT = ROOT / '.staging/r9-next22'
DEST = ROOT / '.staging/r9-next23'
DIRS = ('adapter', 'classification', 'clientconfig', 'cmd', 'gateway', 'internal',
        'obfuscation', 'protocol', 'scheduler', 'security', 'session', 'tests')


def main():
    files = [PARENT / 'go.mod', PARENT / 'go.sum']
    for directory in DIRS:
        files.extend((PARENT / directory).rglob('*.go'))
    rows = [{'path': p.relative_to(PARENT).as_posix(),
             'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(files)]
    DEST.mkdir(exist_ok=False)
    for row in rows:
        target = DEST / row['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write((PARENT / row['path']).read_bytes())
    evidence = DEST / 'verification/merge'
    evidence.mkdir(parents=True)
    record = {'parent': str(PARENT), 'parent_file_count': len(rows), 'parent_source': rows,
              'prior_results_copied': False, 'complete_gate': 'not_run'}
    (evidence / 'initial-parent.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
    print(json.dumps({'candidate': str(DEST), 'parent_files': len(rows)}))


if __name__ == '__main__':
    main()
