#!/usr/bin/env python3
"""Ordinary unprivileged TCP/UDP sockets; no SOCKS or BFP API."""
import ipaddress, json, os, socket, struct, sys, time


def _skip_name(packet, offset):
    """Advance over a DNS name, accepting ordinary labels and compression."""
    while True:
        if offset >= len(packet):
            raise RuntimeError('DNS name truncated')
        length = packet[offset]
        if length == 0:
            return offset + 1
        if length & 0xc0 == 0xc0:
            if offset + 1 >= len(packet):
                raise RuntimeError('DNS compression pointer truncated')
            return offset + 2
        if length > 63 or offset + 1 + length > len(packet):
            raise RuntimeError('DNS label malformed')
        offset += 1 + length


def dns_a():
    name = b''.join(bytes([len(x)]) + x.encode() for x in 'echo.test'.split('.')) + b'\0'
    query = struct.pack('!HHHHHH', 0x2642, 0x0100, 1, 0, 0, 0) + name + struct.pack('!HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3); s.sendto(query, ('127.0.0.1', 53)); data, _ = s.recvfrom(2048)
    if len(data) < 12 or data[0:2] != query[0:2]: raise RuntimeError('DNS response header missing')
    flags, questions, answers = struct.unpack('!HHH', data[2:8])
    if not flags & 0x8000 or flags & 0x000f or questions != 1 or answers == 0:
        raise RuntimeError('DNS fake A missing')
    at = 12
    at = _skip_name(data, at) + 4  # question type and class
    if at > len(data): raise RuntimeError('DNS question truncated')
    for _ in range(answers):
        at = _skip_name(data, at)
        if at + 10 > len(data): raise RuntimeError('DNS answer malformed')
        rtype, rclass, _, rdlen = struct.unpack('!HHIH', data[at:at+10]); at += 10
        if at + rdlen > len(data): raise RuntimeError('DNS record truncated')
        if rtype == 1 and rclass == 1 and rdlen == 4:
            return socket.inet_ntoa(data[at:at+4])
        at += rdlen
    raise RuntimeError('DNS answer is not A')

def main():
    if os.geteuid() != 20001: raise RuntimeError('probe must run as uid 20001')
    fake = dns_a()
    if ipaddress.ip_address(fake) not in ipaddress.ip_network('198.18.0.0/15'):
        raise RuntimeError('DNS response was not a Mihomo fake-IP')
    payload = b'bfp-tun-next26'
    tcp = socket.create_connection((fake, 18080), 5); tcp.settimeout(5); tcp.sendall(payload); got = tcp.recv(len(payload)); tcp.close()
    if got != payload: raise RuntimeError('TCP echo mismatch')
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.settimeout(5); udp.sendto(payload, (fake, 18080)); got, peer = udp.recvfrom(2048); udp.close()
    if got != payload: raise RuntimeError('UDP echo mismatch')
    time.sleep(1.25)
    print(json.dumps({'uid': os.geteuid(), 'fake_ip': fake, 'tcp': True, 'udp': True, 'udp_peer': peer[0] + ':' + str(peer[1])}))

if __name__ == '__main__':
    try: main()
    except Exception as e:
        print(json.dumps({'uid': os.geteuid(), 'pass': False, 'error': type(e).__name__ + ': ' + str(e)}))
        sys.exit(1)
