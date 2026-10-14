"""Create independent next20 gate helpers; do not copy previous results."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
records = []
for name in ('run-next19-gate.py', 'run-next19-race.py', 'fuzz-next19.py'):
    original = ROOT / 'verification' / name
    output = original.with_name(name.replace('next19', 'next20'))
    source = original.read_text(encoding='utf-8')
    with output.open('x', encoding='utf-8') as stream:
        stream.write(source.replace('next19', 'next20'))
    records.append({'source': original.relative_to(ROOT).as_posix(),
                    'source_sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
                    'helper': output.relative_to(ROOT).as_posix(),
                    'helper_sha256': hashlib.sha256(output.read_bytes()).hexdigest()})
out = ROOT / '.staging/r9-next20/verification/helper-provenance.json'
with out.open('x', encoding='utf-8') as stream:
    json.dump({'helpers': records, 'prior_results_copied': False}, stream, indent=2)
    stream.write('\n')
print(json.dumps({'helpers_created': len(records), 'prior_results_copied': False}))
