import ipaddress
import json
from pathlib import Path

import yaml

evidence = Path(__file__).parent
config = yaml.safe_load((evidence / 'generated-fixture.yaml').read_text(encoding='utf-8-sig'))
prefixes = json.loads((evidence / 'expected-prefixes.json').read_text(encoding='utf-8-sig'))
expected = []
for base, excluded in [('0.0.0.0/0', '192.0.2.10/32'), ('::/0', '2001:db8::9/128')]:
    expected.extend(ipaddress.ip_network(base).address_exclude(ipaddress.ip_network(excluded)))
actual = [ipaddress.ip_network(prefix) for prefix in prefixes]
assert set(actual) == set(expected), 'PowerShell complement differs from Python ipaddress'
assert len(actual) == 160
assert config['tun']['route-exclude-address'] == ['192.0.2.10/32', '192.0.2.11/32']
assert config['interface-name'] == "Fixture uplink's name"
assert config['tun']['device'].startswith('bfp-tun-')
summary = {'prefix_complement_python_verified': True, 'prefix_count': len(actual), 'generated_yaml_verified': True, 'host_tun_started': False}
(evidence / 'generated-validation-result.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
print(json.dumps(summary))
