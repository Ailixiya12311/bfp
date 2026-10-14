"""Prepare next21 independent source-bound gates without inheriting results."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
records = []
for source_name, output_name in (
    ('run-next20-gate.py', 'run-next21-gate.py'),
    ('run-next20-race.py', 'run-next21-race.py'),
    ('fuzz-next20.py', 'fuzz-next21.py'),
):
    original = ROOT / 'verification' / source_name
    output = original.with_name(output_name)
    text = original.read_text(encoding='utf-8').replace('next20', 'next21').replace('next18 local gate', 'next21 local gate')
    with output.open('x', encoding='utf-8') as stream:
        stream.write(text)
    records.append({'source': original.relative_to(ROOT).as_posix(),
                    'source_sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
                    'helper': output.relative_to(ROOT).as_posix(),
                    'helper_sha256': hashlib.sha256(output.read_bytes()).hexdigest()})
out = ROOT / '.staging/r9-next21/verification/helper-provenance.json'
with out.open('x', encoding='utf-8') as stream:
    json.dump({'helpers': records, 'prior_results_copied': False}, stream, indent=2)
    stream.write('\n')
print(json.dumps({'helpers_created': len(records), 'prior_results_copied': False}))
