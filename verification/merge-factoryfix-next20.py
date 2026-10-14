"""Apply a reviewed factory fix while retaining the complete attempt01 source."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next20'
FIX = ROOT / '.staging/r9-next20-factoryfix'
DIRS = ('adapter', 'classification', 'cmd', 'gateway', 'internal',
        'obfuscation', 'protocol', 'scheduler', 'security', 'session', 'tests')


def sources(stage):
    files = [stage / 'go.mod', stage / 'go.sum']
    for directory in DIRS:
        files.extend((stage / directory).rglob('*.go'))
    return {p.relative_to(stage).as_posix(): p.read_bytes() for p in sorted(files)}


def rows(files):
    return [{'path': p, 'sha256': hashlib.sha256(b).hexdigest()}
            for p, b in sorted(files.items())]


def main():
    frozen_path = STAGE / 'verification/r9-next20/local-gate-attempt01/source-manifest.json'
    frozen = json.loads(frozen_path.read_text(encoding='utf-8'))
    original, incoming = sources(STAGE), sources(FIX)
    parent = json.loads((FIX / 'verification/factory-fix/parent-manifest.json').read_text(encoding='utf-8'))
    map_rows = lambda value: {item['path']: item['sha256'] for item in value}
    if map_rows(rows(original)) != map_rows(frozen['source_manifest']) or map_rows(rows(original)) != map_rows(parent['files']):
        raise RuntimeError('candidate or factory-fix parent differs from original next20 gate')
    if set(original) - set(incoming):
        raise RuntimeError('factory fix unexpectedly deletes source files')
    archive = frozen_path.parent / 'source'
    archive.mkdir(exist_ok=False)
    for path, data in original.items():
        target = archive / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as output:
            output.write(data)
    changes = []
    for path, data in incoming.items():
        if data == original.get(path):
            continue
        target = STAGE / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        changes.append({'path': path,
                        'previous_sha256': hashlib.sha256(original[path]).hexdigest() if path in original else None,
                        'sha256': hashlib.sha256(data).hexdigest()})
    report = {
        'candidate': 'r9-next20', 'original_gate_manifest': frozen['manifest_sha256'],
        'original_gate_full_source_preserved': rows(sources(archive)) == frozen['source_manifest'],
        'factory_fix_source_unchanged': incoming == sources(FIX),
        'candidate_matches_reviewed_factory_fix': incoming == sources(STAGE),
        'changed_files': changes, 'incoming_manifest': rows(incoming),
        'acceptance_complete': False, 'production_ready': False, 'released': False,
    }
    out = STAGE / 'verification/merge/factory-fix-integration.json'
    with out.open('x', encoding='utf-8') as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write('\n')
    print(json.dumps({k: report[k] for k in (
        'original_gate_full_source_preserved', 'factory_fix_source_unchanged',
        'candidate_matches_reviewed_factory_fix')}, ensure_ascii=False))
    print(json.dumps({'changed_files': [r['path'] for r in changes]}))


if __name__ == '__main__':
    main()
