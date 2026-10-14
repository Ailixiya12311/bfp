"""Merge a reviewed next20 correction into next21 using its exact source parent."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next21'
BASE = ROOT / '.staging/r9-next20'
DIRS = ('adapter', 'classification', 'cmd', 'gateway', 'internal',
        'obfuscation', 'protocol', 'scheduler', 'security', 'session', 'tests')


def sources(stage):
    paths = [stage / 'go.mod', stage / 'go.sum']
    for directory in DIRS:
        paths.extend((stage / directory).rglob('*.go'))
    return {p.relative_to(stage).as_posix(): p.read_bytes() for p in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--branch', required=True)
    parser.add_argument('--parent-manifest', required=True)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    branch = (ROOT / args.branch).resolve()
    incoming, base, current = sources(branch), sources(BASE), sources(STAGE)
    parent = json.loads((ROOT / args.parent_manifest).read_text(encoding='utf-8'))
    if isinstance(parent, dict):
        parent = parent.get('source_manifest', parent.get('files'))
    old = {r['path'].removeprefix('./'): r['sha256'] for r in parent}
    live = {p: hashlib.sha256(b).hexdigest() for p, b in base.items()}
    if old != live:
        raise RuntimeError('next20 differs from recorded correction parent')
    changes, conflicts = [], []
    for path, data in incoming.items():
        if hashlib.sha256(data).hexdigest() == old.get(path):
            continue
        destination = STAGE / path
        method = 'direct'
        if path in current and current[path] != base.get(path) and current[path] != data:
            merged = subprocess.run(['git', 'merge-file', '-p', '--', str(destination),
                                     str(BASE / path), str(branch / path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if merged.returncode not in (0, 1):
                raise RuntimeError('merge command failed: ' + path)
            data = merged.stdout
            method = 'three_way' if merged.returncode == 0 else 'conflict'
            if merged.returncode:
                conflicts.append(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        changes.append({'path': path, 'method': method, 'sha256': hashlib.sha256(data).hexdigest()})
    report = {'branch': str(branch), 'parent_manifest': args.parent_manifest,
              'changes': changes, 'conflicts': conflicts,
              'incoming_source': [{'path': p, 'sha256': hashlib.sha256(b).hexdigest()} for p, b in sorted(incoming.items())],
              'branch_unchanged': incoming == sources(branch), 'next20_unchanged': base == sources(BASE),
              'prior_gate_results_reused': False, 'acceptance_complete': False}
    output = STAGE / 'verification/merge' / (args.label + '.json')
    with output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'label': args.label, 'changes': len(changes), 'conflicts': conflicts}))
    return 1 if conflicts else 0


if __name__ == '__main__':
    raise SystemExit(main())
