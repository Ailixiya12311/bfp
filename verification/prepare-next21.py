"""Apply branch deltas using recorded parents, preserving next20 corrections."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / '.staging/r9-next20'
DEST = ROOT / '.staging/r9-next21'
ARCHIVE = BASE / 'verification/r9-next20/local-gate-attempt01/source'
DIRS = ('adapter', 'classification', 'cmd', 'gateway', 'internal',
        'obfuscation', 'protocol', 'scheduler', 'security', 'session', 'tests')


def sources(stage):
    paths = [stage / 'go.mod', stage / 'go.sum']
    for directory in DIRS:
        paths.extend((stage / directory).rglob('*.go'))
    return {p.relative_to(stage).as_posix(): p.read_bytes() for p in sorted(paths)}


def rows(files):
    return [{'path': p, 'sha256': hashlib.sha256(b).hexdigest()}
            for p, b in sorted(files.items())]


def main():
    DEST.mkdir(exist_ok=False)
    before = sources(BASE)
    for path, data in before.items():
        target = DEST / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    out = DEST / 'verification/merge'
    out.mkdir(parents=True)
    report = {'source_before': {'next20': rows(before)}, 'changes': [], 'conflicts': [],
              'prior_results_copied': False, 'acceptance_complete': False}
    branches = (
        ('datagram', ROOT / '.staging/r9-next21-datagram', 'verification/parent-source-manifest.json'),
        ('dns', ROOT / '.staging/r9-next21-dns', 'provenance/parent-source-manifest.json'),
    )
    for name, branch, parent_path in branches:
        incoming = sources(branch)
        parent = json.loads((branch / parent_path).read_text(encoding='utf-8'))
        parent = parent if isinstance(parent, list) else parent['source_manifest']
        parent_hash = {r['path'].removeprefix('./'): r['sha256'] for r in parent}
        report['source_before'][name] = rows(incoming)
        for path, data in incoming.items():
            incoming_hash = hashlib.sha256(data).hexdigest()
            old_hash = parent_hash.get(path)
            if incoming_hash == old_hash:
                continue  # Never overlay branch's unchanged old parent files.
            target = DEST / path
            current = target.read_bytes() if target.exists() else None
            method = 'direct'
            if current == data:
                method = 'identical'
            elif current is not None and hashlib.sha256(current).hexdigest() != old_hash:
                original = ARCHIVE / path
                if not original.exists() or hashlib.sha256(original.read_bytes()).hexdigest() != old_hash:
                    raise RuntimeError('missing exact recorded parent for overlapping delta: ' + path)
                merged = subprocess.run(['git', 'merge-file', '-p', '--', str(target), str(original), str(branch / path)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if merged.returncode not in (0, 1):
                    raise RuntimeError('merge command failed: ' + path)
                data = merged.stdout
                method = 'three_way' if merged.returncode == 0 else 'conflict'
                if merged.returncode:
                    report['conflicts'].append({'branch': name, 'path': path})
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            report['changes'].append({'branch': name, 'path': path, 'method': method})
        for source in (branch / 'docs').glob('*.md'):
            destination = DEST / 'docs' / source.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        report[name + '_unchanged'] = incoming == sources(branch)
    report['next20_unchanged'] = before == sources(BASE)
    with (out / 'three-way-merge.json').open('x', encoding='utf-8') as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write('\n')
    print(json.dumps({'candidate': str(DEST), 'changes': len(report['changes']), 'conflicts': report['conflicts']}))
    return 1 if report['conflicts'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
