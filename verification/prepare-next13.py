"""Create the retirement boundary from next12's frozen source."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'verification/prepare-next11.py').read_text(encoding='utf-8')
source=source.replace('next11','__CHILD__').replace('next10','next12').replace('__CHILD__','next13')
exec(compile(source,str(ROOT/'verification/prepare-next13.py'),'exec'))
for stem in ('targeted','verify'):
    source=(ROOT/'verification'/(stem+'-next12.py')).read_text(encoding='utf-8')
    with (ROOT/'verification'/(stem+'-next13.py')).open('x',encoding='utf-8') as output:
        output.write(source.replace('next12','next13'))
print('next13 source and verification helpers created')
