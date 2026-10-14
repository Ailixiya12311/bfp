"""Create next15 gates from the prior bounded runner without starting a run."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for source, target in [('verify-next14.py', 'verify-next15.py'),
                       ('run-next14-race.py', 'run-next15-race.py')]:
    content = (ROOT / 'verification' / source).read_text(encoding='utf-8')
    content = content.replace('next14', 'next15')
    if target.startswith('run-'):
        content = content.replace('local-gate-attempt02', 'local-gate')
    else:
        content = content.replace('local bounded Session close and lifecycle gate',
                                  'local bounded authenticated Datagram repair gate')
    with (ROOT / 'verification' / target).open('x', encoding='utf-8') as output:
        output.write(content)
print('next15 helpers created; no local or remote run started')
