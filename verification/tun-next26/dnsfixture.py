#!/usr/bin/env python3
"""Small owned DNS fixture: echo.test -> 127.0.0.1 / ::1."""
import socket, struct, threading

def answer(query):
    if len(query) < 12:
        return b''
    qid, flags, qd, _, _ = struct.unpack('!HHHHH', query[:10])
    if qd != 1:
        return query[:2] + b'\x81\x81' + query[4:6] + b'\x00\x00\x00\x00\x00\x00'
    at = 12
    while at < len(query) and query[at] != 0:
        n = query[at]
        if n & 0xc0 or n > 63 or at + n + 1 >= len(query): return b''
        at += n + 1
    if at + 5 > len(query): return b''
    end = at + 5
    qtype, qclass = struct.unpack('!HH', query[at+1:end])
    if qclass != 1: return query[:2] + b'\x81\x83' + query[4:6] + b'\x00\x00\x00\x00\x00\x00'
    body = query[12:end]
    records = []
    if qtype == 1: records.append(struct.pack('!HHHLH4s', 0xc00c, 1, 1, 30, 4, socket.inet_aton('127.0.0.1')))
    elif qtype == 28: records.append(struct.pack('!HHHLH16s', 0xc00c, 28, 1, 30, 16, socket.inet_pton(socket.AF_INET6, '::1')))
    hdr = struct.pack('!HHHHHH', qid, 0x8180, 1, len(records), 0, 0)
    return hdr + body + b''.join(records)

def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', 1053))
    while True:
        try: data, peer = s.recvfrom(4096); s.sendto(answer(data), peer)
        except OSError: return

def tcp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('127.0.0.1', 1053)); s.listen(8)
    while True:
        try: c, _ = s.accept()
        except OSError: return
        with c:
            try:
                prefix = c.recv(2)
                if len(prefix) != 2: continue
                size = struct.unpack('!H', prefix)[0]; data = b''
                while len(data) < size:
                    part = c.recv(size-len(data))
                    if not part: break
                    data += part
                out = answer(data); c.sendall(struct.pack('!H', len(out)) + out)
            except OSError: pass

threading.Thread(target=udp, daemon=True).start(); tcp()
