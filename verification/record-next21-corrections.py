"""Record reviewed direct corrections relative to the first merged source."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next21'
OUT = STAGE / 'verification/merge/direct-corrections.json'
DIRS = ('adapter', 'classification', 'cmd', 'gateway', 'internal',
        'obfuscation', 'protocol', 'scheduler', 'security', 'session', 'tests')


def main():
    baseline_path = STAGE / 'verification/combined-directed-attempt01/source-manifest.json'
    baseline = json.loads(baseline_path.read_text(encoding='utf-8'))
    rows = baseline if isinstance(baseline, list) else baseline['source_manifest']
    old = {row['path']: row['sha256'] for row in rows}
    paths = [STAGE / 'go.mod', STAGE / 'go.sum']
    for directory in DIRS:
        paths.extend((STAGE / directory).rglob('*.go'))
    current = {p.relative_to(STAGE).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted(paths)}
    expected = {
        'adapter/dns/server.go', 'adapter/dns/server_test.go',
        'gateway/client_dns_queued_cancel_test.go', 'session/client.go',
        'session/context_mutex.go', 'session/client_connect_cancel_test.go',
        'session/close_runtime_test.go', 'session/flow.go', 'session/datagram_tx.go',
        'session/datagram_deadline.go', 'session/datagram_deadline_next21_test.go',
    }
    delta = [{
        'path': path, 'before_sha256': old.get(path), 'after_sha256': current.get(path),
    } for path in sorted(set(old) | set(current)) if old.get(path) != current.get(path)]
    unexpected = [row['path'] for row in delta if row['path'] not in expected]
    if unexpected:
        raise RuntimeError('unexpected edits outside reviewed correction scope: ' + repr(unexpected))
    report = {
        'revision': 'v0.1-r9-next21', 'baseline': str(baseline_path),
        'baseline_file_sha256': hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
        'changes': delta,
        'source_manifest': [{'path': p, 'sha256': h} for p, h in sorted(current.items())],
        'reviewed_behaviors': [
            'queued Client.Connect cancellation without cancelling the lock owner',
            'DNS AD AA RA false; CD RD echoed; real queued DNS deadline and Close',
            'simultaneous-close fixture supplies actual first request ciphertext in both directions',
            'UDP entry cutoff covers write gate, recovery and actor admission; setters only tighten',
            'UDP actor deadline check and whole-message admission serialize with setters',
        ],
        'deadline_close_order': 'simultaneous readiness may produce timeout or ErrClosed',
        'local_caller_concurrency': 'one node and timer per local Write caller, bounded in time, no separate cardinality cap',
        'review': 'independent read-only agent review; no correctness blocker found',
        'complete_gate_results_reused': False, 'acceptance_complete': False,
    }
    with OUT.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'path': str(OUT), 'changed_files': len(delta), 'unexpected': unexpected}))


if __name__ == '__main__':
    main()
