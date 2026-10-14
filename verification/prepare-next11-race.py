"""Create the successor race helper; it refuses a failed frozen local gate."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'verification/run-next10-race.py').read_text(encoding='utf-8')
with (ROOT / 'verification/run-next11-race.py').open('x', encoding='utf-8') as output:
    output.write(source.replace('next10', 'next11'))
print('next11 race helper created; no remote run started')
