"""Merge the two next20 slices against their frozen next19 source parent."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / '.staging/r9-next19'
CLIENT = ROOT / '.staging/r9-next20-client'
CARRIER = ROOT / '.staging/r9-next20-carrier'
DEST = ROOT / '.staging/r9-next20'
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
    base, client, carrier = sources(BASE), sources(CLIENT), sources(CARRIER)
    frozen = json.loads((BASE / 'verification/r9-next19/local-gate-attempt01/source-manifest.json').read_text(encoding='utf-8'))
    if rows(base) != frozen['source_manifest']:
        raise RuntimeError('next19 source no longer matches frozen parent')
    DEST.mkdir(exist_ok=False)
    evidence = DEST / 'verification/merge'
    evidence.mkdir(parents=True)
    changes, conflicts = [], []
    for path in sorted(set(base) | set(client) | set(carrier)):
        b, c, h = base.get(path), client.get(path), carrier.get(path)
        if c == h:
            result = c
            method = 'identical'
        elif c == b:
            result = h
            method = 'carrier'
        elif h == b:
            result = c
            method = 'client'
        elif b is not None and c is not None and h is not None:
            command = ['git', 'merge-file', '-p', '--', str(CLIENT / path),
                       str(BASE / path), str(CARRIER / path)]
            merged = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if merged.returncode not in (0, 1):
                raise RuntimeError('merge-file failed for ' + path)
            result = merged.stdout
            method = 'three_way' if merged.returncode == 0 else 'conflict'
            if merged.returncode:
                conflicts.append(path)
        else:
            conflicts.append(path)
            result = c if c is not None else h
            method = 'conflict'
        if result is not None:
            target = DEST / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(result)
        if result != b:
            changes.append({'path': path, 'method': method})
    for stage, name in (
        (CLIENT, '客户端Session地址作用域-r9-next20.md'),
        (CARRIER, '物理Carrier拨号注入-r9-next20.md'),
    ):
        target = DEST / 'docs' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(stage / 'docs' / name, target)
    report = {
        'candidate': 'r9-next20',
        'parent_manifest_sha256': frozen['manifest_sha256'],
        'source_before': {'next19': rows(base), 'client': rows(client), 'carrier': rows(carrier)},
        'parent_and_slices_unchanged': (base == sources(BASE) and client == sources(CLIENT) and carrier == sources(CARRIER)),
        'changes': changes, 'conflicts': conflicts,
        'copied_prior_verification_or_binaries': False,
        'acceptance_complete': False, 'production_ready': False, 'released': False,
    }
    (evidence / 'three-way-merge.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'candidate': str(DEST), 'changed_source_files': len(changes),
                      'conflicts': conflicts, 'parents_unchanged': report['parent_and_slices_unchanged']}))
    return 1 if conflicts else 0


if __name__ == '__main__':
    raise SystemExit(main())
