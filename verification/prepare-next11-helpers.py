"""Adapt bounded verification helpers without rewriting next10 evidence."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for stem in ('targeted', 'verify'):
    source = (ROOT / 'verification' / (stem + '-next10.py')).read_text(encoding='utf-8')
    text = source.replace('next10', 'next11')
    if stem == 'verify':
        text = text.replace("import subprocess\n", "import subprocess\nimport sys\n")
        text = text.replace("'pass': False, 'production_ready': False", "'pass': False, 'acceptance_complete': False, 'production_ready': False")
        needle = "                entry['packages_passed'] = sum"
        extra = """                entry['failed_packages'] = [e['Package'] for e in events if e.get('Action') == 'fail' and 'Test' not in e]
                entry['panic_events'] = [{'package': e.get('Package'), 'active_test': e.get('Test'), 'output': e['Output'].strip()} for e in events if 'panic:' in e.get('Output', '')]
                terminal = {(e.get('Package'), e.get('Test')) for e in events if e.get('Action') in ('pass', 'fail', 'skip') and 'Test' in e}
                entry['tests_without_terminal_event'] = [{'package': e['Package'], 'test': e['Test']} for e in events if e.get('Action') == 'run' and 'Test' in e and (e['Package'], e['Test']) not in terminal]
"""
        if needle not in text:
            raise ValueError('parser marker missing')
        text = text.replace(needle, extra + needle)
        text = text.replace("    main()\n", "    main()\n    report = json.loads((OUT / 'local-summary.json').read_text(encoding='utf-8'))\n    sys.exit(0 if report.get('local_checks_pass') else 1)\n")
    with (ROOT / 'verification' / (stem + '-next11.py')).open('x', encoding='utf-8') as output:
        output.write(text)
print('next11 selected and formal helper files created')
