"""Preserve the failed next21 gate source before the socket-pair correction."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next21'
OUT = STAGE / 'verification/r9-next21/local-gate-attempt01'


def main():
    manifest = json.loads((OUT / 'source-manifest.json').read_text(encoding='utf-8'))
    summary = json.loads((OUT / 'local-summary.json').read_text(encoding='utf-8'))
    if summary['local_checks_pass'] or not summary['source_unchanged']:
        raise RuntimeError('expected the unchanged failed attempt01 source')
    source = OUT / 'source'
    source.mkdir(exist_ok=False)
    for row in manifest['source_manifest']:
        data = (STAGE / row['path']).read_bytes()
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('source changed before archival: ' + row['path'])
        destination = source / row['path']
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(data)
    report = {
        'revision': 'v0.1-r9-next21', 'attempt': 'local-gate-attempt01',
        'manifest_sha256': manifest['manifest_sha256'], 'files': manifest['file_count'],
        'original_summary_sha256': hashlib.sha256((OUT / 'local-summary.json').read_bytes()).hexdigest(),
        'reason': 'DNS UDP ephemeral port selected first; TCP bind was denied before revocation scenario began',
        'failure_preserved': True, 'source_copy_matches': True,
    }
    with (OUT / 'source-archive.json').open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
