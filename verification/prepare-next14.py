"""Create next14 solely from the passed, frozen next13 source manifest."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
source = (ROOT/'verification/prepare-next11.py').read_text(encoding='utf-8')
source = source.replace('next11', '__CHILD__').replace('next10', 'next13').replace('__CHILD__', 'next14')
exec(compile(source, str(ROOT/'verification/prepare-next14.py'), 'exec'))
source = (ROOT/'verification/verify-next13.py').read_text(encoding='utf-8')
with (ROOT/'verification/verify-next14.py').open('x', encoding='utf-8') as output:
    output.write(source.replace('next13', 'next14'))
