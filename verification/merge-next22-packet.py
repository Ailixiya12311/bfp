"""Merge only the frozen public packet/lifecycle additions into next22."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
BRANCH = ROOT / '.staging/r9-next22-packet'
DEST = ROOT / '.staging/r9-next22'
ADDED = ('adapter/packet/config.go', 'adapter/packet/packet.go',
         'adapter/packet/target.go', 'adapter/packet/packet_test.go',
         'session/public_lifecycle.go', 'session/public_lifecycle_test.go',
         'docs/公共UDP多目标PacketConn-r9-next22.md')
DIRS = ('adapter', 'classification', 'clientconfig', 'cmd', 'gateway',
        'internal', 'obfuscation', 'protocol', 'scheduler', 'security', 'session', 'tests')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(stage):
    files = [stage / 'go.mod', stage / 'go.sum']
    for folder in DIRS:
        files.extend((stage / folder).rglob('*.go'))
    return [{'path': p.relative_to(stage).as_posix(), 'sha256': sha(p)} for p in sorted(files)]


def main():
    handoff = json.loads((BRANCH / 'verification/frozen-handoff.json').read_text(encoding='utf-8'))
    manifest_path = BRANCH / handoff['manifest']
    if sha(manifest_path) != handoff['manifestSha256']:
        raise RuntimeError('packet frozen manifest changed')
    frozen = json.loads(manifest_path.read_text(encoding='utf-8'))
    rows = {r['path']: r['sha256'] for r in frozen['sourceFiles']}
    for path, expected in rows.items():
        if sha(BRANCH / path) != expected:
            raise RuntimeError('packet frozen source changed: ' + path)
    log = BRANCH / handoff['log']
    if sha(log) != handoff['logSha256']:
        raise RuntimeError('packet final directed test log changed')
    before = manifest(DEST)
    for row in before:
        if row['path'] in ADDED:
            raise RuntimeError('refusing to overwrite existing addition')
    provenance = []
    for path in ADDED:
        source, target = BRANCH / path, DEST / path
        if target.exists():
            raise RuntimeError('destination addition already exists: ' + path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as out:
            out.write(source.read_bytes())
        provenance.append({'path': path, 'sha256': sha(target)})
    after = manifest(DEST)
    after_map = {r['path']: r['sha256'] for r in after}
    if any(after_map[r['path']] != r['sha256'] for r in before):
        raise RuntimeError('a prior next22 file was changed')
    # Differences from the independently developed branch are recorded, not
    # overwritten: next22 owns the repaired next21 DNS/deadline/Client source.
    retained_differences = [
        {'path': path, 'packet_branch_sha256': expected, 'next22_sha256': after_map[path]}
        for path, expected in rows.items() if path in after_map and expected != after_map[path]
    ]
    result = {'branch': str(BRANCH), 'frozen_manifest': str(manifest_path),
              'frozen_manifest_sha256': sha(manifest_path), 'branch_file_count': len(rows),
              'directed_log': str(log), 'directed_log_sha256': sha(log),
              'added': provenance, 'before': before, 'after': after,
              'prior_next22_files_unchanged': True,
              'branch_differences_retained': retained_differences,
              'merge_policy': 'add six public Go files and documentation; retain all existing next22 source',
              'complete_gate': 'not_run', 'native_gate': 'not_run', 'wan': 'not_run'}
    record = DEST / 'verification/merge/packet-public-additions.json'
    with record.open('x', encoding='utf-8') as out:
        json.dump(result, out, ensure_ascii=False, indent=2)
        out.write('\n')
    print(json.dumps({'path': str(record), 'source_files': len(after),
                      'retained_differences': len(retained_differences), 'pass': True}))


if __name__ == '__main__':
    main()
