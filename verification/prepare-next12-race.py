"""Prepare next12's source-bound race helper without starting remote work."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'verification/run-next11-race.py').read_text(encoding='utf-8')
with (ROOT/'verification/run-next12-race.py').open('x',encoding='utf-8') as output:
    output.write(source.replace('next11','next12'))
print('next12 race helper ready; it requires a passed frozen local gate')
