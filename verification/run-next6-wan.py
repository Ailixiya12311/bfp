"""Run the authorized WAN matrix using pinned SSH on a verified management route.

Only Singapore's SSH management socket uses the tailnet or Los Angeles SSH jump.
BFP UDP and TCP business traffic still goes to the Los Angeles public address.
Existing routes, firewall, exit-node settings and services are not modified.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import sys

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.staging/r9-next6'
sys.path.insert(0, str(ROOT / 'lab'))
import remote
import wan


class ManagementRemote(remote.Remote):
    route = 'tailnet'
    jump_host = None

    def connect(self):
        if self.host.role != 'sender':
            return super().connect()
        remote.expected_keys(self.host)
        client = remote.paramiko.SSHClient()
        client.load_host_keys(str(self.host.pin_file))
        client.set_missing_host_key_policy(remote.paramiko.RejectPolicy())
        self.management_jump = None
        if self.route == 'receiver-jump':
            self.management_jump = remote.Remote(self.jump_host).connect()
            try:
                connection = self.management_jump.client.get_transport().open_channel(
                    'direct-tcpip', (self.host.hostname, self.host.port), ('127.0.0.1', 0), timeout=12)
            except Exception:
                self.management_jump.close()
                self.management_jump = None
                raise
        else:
            connection = socket.create_connection(('100.87.106.47', self.host.port), timeout=12)
        try:
            # The original public hostname selects the original pinned key;
            # the supplied socket changes only the management route.
            client.connect(self.host.hostname, port=self.host.port,
                           username=self.host.username, password=self.host.password,
                           look_for_keys=False, allow_agent=False, timeout=12,
                           auth_timeout=12, banner_timeout=12, sock=connection)
        except Exception:
            client.close()
            connection.close()
            if self.management_jump:
                self.management_jump.close()
                self.management_jump = None
            raise
        self.client = client
        self.client.get_transport().set_keepalive(15)
        return self

    def close(self):
        super().close()
        jump = getattr(self, 'management_jump', None)
        if jump:
            jump.close()
            self.management_jump = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ticket-lifecycle', action='store_true')
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--management', choices=('receiver-jump', 'tailnet'), default='receiver-jump')
    args = parser.parse_args()
    remote.WORKSPACE = wan.WORKSPACE = STAGE
    inventory = Path(r'C:\Users\developer\Desktop\cold\servers-unredacted.md')
    wan.load_hosts = lambda: remote.load_hosts(inventory=inventory)
    ManagementRemote.route = args.management
    ManagementRemote.jump_host = wan.load_hosts()['receiver']
    wan.Remote = ManagementRemote
    if args.preflight_only:
        with ManagementRemote(wan.load_hosts()['sender']) as endpoint:
            snap = endpoint.snapshot()
            print(json.dumps({'role': 'sender', 'host_key_verified': snap['host_key_verified'],
                              'management_transport': args.management,
                              'os': snap['snapshot']['os'], 'arch': snap['snapshot']['arch']}))
        return 0
    if args.ticket_lifecycle:
        options = (20, 4096, '200ms', '35s', True)
    else:
        options = (50, 16384, '100ms', '60s', False)
    report, path = wan.run_wan(str(STAGE / 'bfp-r9-next6-linux-amd64'), *options)
    report['management_transport'] = {'receiver': 'public_pinned_ssh', 'sender': args.management + '_pinned_to_original_public_host_key'}
    report['business_transport'] = 'Singapore -> Los Angeles public IP; native BFP UDP/TCP'
    remote.write_public(path, report)
    print(json.dumps({'stage': 'complete', 'pass': report['pass'], 'run_id': report['run_id'],
                      'path': str(path), 'scenarios': {name: value.get('pass') for name, value in report['scenarios'].items()}}, ensure_ascii=False), flush=True)
    return 0 if report['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
