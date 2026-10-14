"""Preserve attempt01 and prepare separate gates for the DNS listener repair."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next21'
DIRS = ('adapter', 'classification', 'cmd', 'gateway', 'internal',
        'obfuscation', 'protocol', 'scheduler', 'security', 'session', 'tests')


def main():
    old_path = STAGE / 'verification/r9-next21/local-gate-attempt01/source-manifest.json'
    old_manifest = json.loads(old_path.read_text(encoding='utf-8'))
    old = {row['path']: row['sha256'] for row in old_manifest['source_manifest']}
    paths = [STAGE / 'go.mod', STAGE / 'go.sum']
    for directory in DIRS:
        paths.extend((STAGE / directory).rglob('*.go'))
    current = {p.relative_to(STAGE).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted(paths)}
    expected = {'adapter/dns/server.go', 'adapter/dns/listen.go', 'adapter/dns/listen_test.go',
                'session/datagram_deadline_next21_test.go'}
    changed = [{'path': p, 'before_sha256': old.get(p), 'after_sha256': current.get(p)}
               for p in sorted(set(old) | set(current)) if old.get(p) != current.get(p)]
    if {row['path'] for row in changed} != expected:
        raise RuntimeError('unexpected source delta relative to archived attempt01')
    archived = STAGE / 'verification/r9-next21/local-gate-attempt01/source'
    if any(hashlib.sha256((archived / p).read_bytes()).hexdigest() != h for p, h in old.items()):
        raise RuntimeError('original failed source archive changed')
    helpers = []
    for name in ('run-next21-gate.py', 'fuzz-next21.py', 'run-next21-race.py', 'finalize-next21.py'):
        original = ROOT / 'verification' / name
        destination = original.with_name(name.replace('next21', 'next21-attempt02'))
        text = original.read_text(encoding='utf-8').replace('local-gate-attempt01', 'local-gate-attempt02')
        if name == 'finalize-next21.py':
            marker = "    next20_failure = read(ROOT / '.staging/r9-next20/verification/r9-next20/local-gate-attempt02/local-summary.json')"
            extra = '''    repair = read(STAGE / 'verification/merge/listener-pair-correction.json')
    failed_out = STAGE / 'verification/r9-next21/local-gate-attempt01'
    failed_manifest = read(failed_out / 'source-manifest.json')
    gates['listener_repair_source_matches_frozen'] = row_map(repair['source_manifest']) == row_map(frozen['source_manifest'])
    gates['next21_attempt01_summary_preserved'] = hashlib.sha256((failed_out / 'local-summary.json').read_bytes()).hexdigest() == repair['failed_summary_sha256']
    gates['next21_attempt01_source_preserved'] = all(hashlib.sha256((failed_out / 'source' / r['path']).read_bytes()).hexdigest() == r['sha256'] for r in failed_manifest['source_manifest'])
'''
            if marker not in text:
                raise RuntimeError('finalizer correction insertion marker changed')
            text = text.replace(marker, extra + marker)
            text = text.replace("        'prior_wan':", "        'next21_attempt01': {'status': 'strict_fail_preserved', 'reason': 'UDP-selected DNS port could not be bound for TCP', 'summary': str(failed_out / 'local-summary.json')},\n        'prior_wan':")
        with destination.open('x', encoding='utf-8') as stream:
            stream.write(text)
        helpers.append({'source': original.relative_to(ROOT).as_posix(),
                        'source_sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
                        'helper': destination.relative_to(ROOT).as_posix(),
                        'helper_sha256': hashlib.sha256(destination.read_bytes()).hexdigest()})
    failure = STAGE / 'verification/r9-next21/local-gate-attempt01/local-summary.json'
    record = {
        'revision': 'v0.1-r9-next21', 'changes': changed, 'helpers': helpers,
        'source_manifest': [{'path': p, 'sha256': h} for p, h in sorted(current.items())],
        'failed_gate_manifest_sha256': old_manifest['manifest_sha256'],
        'failed_summary_sha256': hashlib.sha256(failure.read_bytes()).hexdigest(),
        'original_failed_source_unchanged': True,
        'behavior': 'TCP selects ephemeral DNS port first; UDP pairing retries at most eight owned candidates; explicit port is fixed',
        'test_refinement': 'same registration snapshot, no premature timeout, gate-to-recovery still before cutoff',
        'prior_results_reused': False, 'acceptance_complete': False,
    }
    path = STAGE / 'verification/merge/listener-pair-correction.json'
    with path.open('x', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'path': str(path), 'changed_files': len(changed), 'helper_count': len(helpers)}))


if __name__ == '__main__':
    main()
