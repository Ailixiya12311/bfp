"""Copy next11's frozen source and create streamed next12 verification."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT/'verification/prepare-next11.py').read_text(encoding='utf-8')
source = source.replace('next11','__SUCCESSOR__').replace('next10','next11').replace('__SUCCESSOR__','next12')
exec(compile(source,str(ROOT/'verification/prepare-next12.py'),'exec'))
source = (ROOT/'verification/targeted-next11.py').read_text(encoding='utf-8').replace('next11','next12')
with (ROOT/'verification/targeted-next12.py').open('x',encoding='utf-8') as output: output.write(source)
source = (ROOT/'verification/verify-next11.py').read_text(encoding='utf-8').replace('next11','next12')
old = """            result = subprocess.run(command, cwd=STAGE, env=environment, capture_output=True, encoding='utf-8', errors='replace', timeout=240)
            log = OUT / (key + '.log')
            log.write_text(result.stdout + result.stderr, encoding='utf-8')
            entry = {'command': command, 'exit_code': result.returncode, 'pass': result.returncode == 0, 'raw_log': str(log.relative_to(ROOT).as_posix())}
"""
new = """            log = OUT / (key + '.log')
            timed_out = False
            with log.open('xb') as output:
                try:
                    result = subprocess.run(command, cwd=STAGE, env=environment, stdout=output, stderr=subprocess.STDOUT, timeout=240)
                    exit_code = result.returncode
                except subprocess.TimeoutExpired:
                    exit_code = None
                    timed_out = True
            captured = log.read_text(encoding='utf-8', errors='replace')
            entry = {'command': command, 'exit_code': exit_code, 'pass': exit_code == 0 and not timed_out, 'raw_log': str(log.relative_to(ROOT).as_posix()), 'outer_timeout': timed_out}
"""
if old not in source: raise ValueError('expected old verifier block missing')
source = source.replace(old,new).replace('for line in result.stdout.splitlines():','for line in captured.splitlines():')
with (ROOT/'verification/verify-next12.py').open('x',encoding='utf-8') as output: output.write(source)
print('next12 source and streamed local verifier created; no tests started')
