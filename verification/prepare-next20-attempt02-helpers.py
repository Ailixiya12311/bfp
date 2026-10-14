"""Keep the first next20 gate immutable while preparing the corrected gate."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
records = []
for source_name, output_name in (
    ('run-next20-gate.py', 'run-next20-gate-attempt02.py'),
    ('run-next20-race.py', 'run-next20-race-attempt02.py'),
    ('fuzz-next20.py', 'fuzz-next20-attempt02.py'),
):
    original = ROOT / 'verification' / source_name
    output = original.with_name(output_name)
    source = original.read_text(encoding='utf-8')
    source = source.replace('local-gate-attempt01', 'local-gate-attempt02')
    source = source.replace('race-snapshots-attempt01', 'race-snapshots-attempt02')
    source = source.replace('fuzz-attempt01', 'fuzz-attempt02')
    source = source.replace('next18 local gate', 'next20 attempt02 local gate')
    with output.open('x', encoding='utf-8') as stream:
        stream.write(source)
    records.append({'source': original.relative_to(ROOT).as_posix(),
                    'source_sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
                    'helper': output.relative_to(ROOT).as_posix(),
                    'helper_sha256': hashlib.sha256(output.read_bytes()).hexdigest()})
out = ROOT / '.staging/r9-next20/verification/helper-provenance-attempt02.json'
with out.open('x', encoding='utf-8') as stream:
    json.dump({'helpers': records, 'prior_results_copied': False}, stream, indent=2)
    stream.write('\n')
print(json.dumps({'helpers_created': len(records), 'prior_results_copied': False}))
