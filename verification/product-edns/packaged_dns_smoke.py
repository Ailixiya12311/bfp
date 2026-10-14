"""Exercise an actual packaged CLI using only loopback, with private temp keys."""
from __future__ import annotations

import argparse
import ipaddress
import json
import pathlib
import shutil
import socket
import struct
import subprocess
import tempfile
import time


def recv_exact(conn, count):
    result = bytearray()
    while len(result) < count:
        chunk = conn.recv(count - len(result))
        if not chunk:
            raise RuntimeError("unexpected socket EOF")
        result.extend(chunk)
    return bytes(result)


def endpoint():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()


def ready(process, address):
    until = time.monotonic() + 5
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError("CLI exited before binding its listener")
        try:
            with socket.create_connection(address, timeout=.1):
                return
        except OSError:
            time.sleep(.01)
    raise RuntimeError("CLI listener startup timeout")


def skip_name(data, offset):
    while True:
        size = data[offset]
        if size & 0xc0 == 0xc0:
            return offset + 2
        offset += 1
        if size == 0:
            return offset
        if size > 63:
            raise RuntimeError("invalid DNS name label")
        offset += size


def dns_address(address, network, family, edns):
    name = b"\x09localhost\x00"
    question = name + struct.pack("!HH", family, 1)
    wire = struct.pack("!6H", 0xbf04, 0x100, 1, 0, 0, int(edns)) + question
    if edns:
        options = struct.pack("!HH", 12, 24) + bytes(24)
        wire += b"\x00" + struct.pack("!HHIH", 41, 4096, 0x8000, len(options)) + options
    if network == "tcp":
        with socket.create_connection(address, timeout=3) as conn:
            conn.sendall(struct.pack("!H", len(wire)) + wire)
            count = struct.unpack("!H", recv_exact(conn, 2))[0]
            if count > 1232:
                raise RuntimeError("oversize DNS TCP response")
            reply = recv_exact(conn, count)
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
            conn.settimeout(3)
            conn.connect(address)
            conn.send(wire)
            reply = conn.recv(2048)
    ident, flags, qd, an, ns, ar = struct.unpack_from("!6H", reply)
    if ident != 0xbf04 or flags != 0x8100 or (qd, an, ns, ar) != (1, 1, 0, int(edns)):
        raise RuntimeError("invalid DNS response flags/counts")
    if reply[12:12 + len(question)] != question:
        raise RuntimeError("DNS response changed its question")
    offset = skip_name(reply, 12) + 4
    offset = skip_name(reply, offset)
    typ, cls, ttl, size = struct.unpack_from("!HHIH", reply, offset)
    offset += 10
    if typ != family or cls != 1 or ttl == 0 or size != (4 if family == 1 else 16):
        raise RuntimeError("DNS returned no bounded address lease")
    ip = ipaddress.ip_address(reply[offset:offset + size])
    offset += size
    pool = ipaddress.ip_network("198.18.0.0/15" if family == 1 else "fd42:6266:7000::/96")
    if ip not in pool:
        raise RuntimeError("DNS response escaped the temporary pool")
    if edns:
        if reply[offset:] != b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000, 0):
            raise RuntimeError("DNS response did not negotiate EDNS or reflected an option")
    elif offset != len(reply):
        raise RuntimeError("unexpected legacy DNS response data")
    if len(reply) > (1232 if edns or network == "tcp" else 512):
        raise RuntimeError("DNS reply exceeded its advertised size")
    return ip, ttl


def socks_address(conn):
    kind = recv_exact(conn, 1)[0]
    if kind in (1, 4):
        host = str(ipaddress.ip_address(recv_exact(conn, 4 if kind == 1 else 16)))
    elif kind == 3:
        host = recv_exact(conn, recv_exact(conn, 1)[0]).decode("ascii")
    else:
        raise RuntimeError("invalid SOCKS address type")
    return host, struct.unpack("!H", recv_exact(conn, 2))[0]


def socks_request(address, command, ip, port):
    conn = socket.create_connection(address, timeout=3)
    try:
        conn.sendall(b"\x05\x01\x00")
        if recv_exact(conn, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS greeting failed")
        conn.sendall(bytes((5, command, 0, 1 if ip.version == 4 else 4)) + ip.packed + struct.pack("!H", port))
        if recv_exact(conn, 3) != b"\x05\x00\x00":
            raise RuntimeError("SOCKS request failed")
        return conn, socks_address(conn)
    except BaseException:
        conn.close()
        raise


def tcp_echo(address, ip, port, payload):
    conn, _ = socks_request(address, 1, ip, port)
    with conn:
        conn.sendall(payload)
        if recv_exact(conn, len(payload)) != payload:
            raise RuntimeError("DNS-derived SOCKS TCP echo failed")


def udp_echo(address, ip, port, payload):
    control, relay = socks_request(address, 3, ipaddress.ip_address("0.0.0.0"), 0)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.settimeout(3)
        conn.bind(("127.0.0.1", 0))
        conn.connect(relay)
        conn.send(bytes((0, 0, 0, 1 if ip.version == 4 else 4)) + ip.packed + struct.pack("!H", port) + payload)
        reply = conn.recv(2048)
        if reply[:3] != bytes(3):
            raise RuntimeError("SOCKS UDP reply was fragmented or invalid")
        offset = {1: 8, 4: 20}.get(reply[3])
        if offset is None or struct.unpack_from("!H", reply, offset)[0] != port or reply[offset + 2:] != payload:
            raise RuntimeError("DNS-derived SOCKS UDP echo failed")


def execute(binary, work_dir):
    binary = pathlib.Path(binary).resolve(strict=True)
    work_dir = pathlib.Path(work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    owned = pathlib.Path(tempfile.mkdtemp(prefix=".native-dns-", dir=work_dir)).resolve()
    processes, logs, checks = [], [], []
    report = {"scope": "packaged client/server, loopback DNS to SOCKS TCP/UDP; no WAN", "pass": False, "checks": checks}
    try:
        credentials = owned / "credentials"
        addresses = []
        while len(addresses) < 4:
            candidate = endpoint()
            if candidate not in addresses:
                addresses.append(candidate)
        server_address, socks, dns, target = addresses
        text = lambda address: address[0] + ":" + str(address[1])
        generated = subprocess.run([str(binary), "keygen", "-out", str(credentials), "-server-listen", text(server_address), "-server", text(server_address), "-tcp-server", text(server_address), "-socks", text(socks)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        if generated.returncode:
            raise RuntimeError("packaged keygen failed")
        for kind in ("server", "client"):
            path = credentials / (kind + ".json")
            config = json.loads(path.read_text(encoding="utf-8"))
            if kind == "server":
                config["policy"].update(AllowPrivate=True, AllowedCIDRs=["127.0.0.0/8", "::1/128"], AllowedPorts=[target[1]])
            else:
                config["dns"] = {"listen": text(dns), "mapping_ttl": "30s", "mapping_capacity": 64}
            path.write_text(json.dumps(config), encoding="utf-8")
        def start(command, args, address):
            output = open(owned / (command + "-" + str(len(processes)) + ".log"), "wb")
            logs.append(output)
            kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if hasattr(subprocess, "CREATE_NO_WINDOW") else {}
            process = subprocess.Popen([str(binary), command] + args, stdout=output, stderr=output, **kwargs)
            processes.append(process)
            ready(process, address)
        start("fixture", ["-listen", text(target)], target)
        start("fixture", ["-listen", "[::1]:" + str(target[1])], ("::1", target[1]))
        start("server", ["-config", str(credentials / "server.json")], server_address)
        start("client", ["-config", str(credentials / "client.json")], socks)
        ready(processes[-1], dns)
        mapping = None
        original_ttl = None
        for edns in (False, True):
            for network in ("udp", "tcp"):
                for typ in (1, 28):
                    ip, ttl = dns_address(dns, network, typ, edns)
                    key = ip.packed[-4:]
                    if mapping is not None and (mapping != key or ttl > original_ttl):
                        raise RuntimeError("DNS replaced or renewed the shared mapping")
                    mapping, original_ttl = key, ttl
                    payload = b"packaged DNS to BFP echo"
                    tcp_echo(socks, ip, target[1], payload)
                    udp_echo(socks, ip, target[1], payload)
                    checks.append({"edns": edns, "dns_transport": network, "record": "A" if typ == 1 else "AAAA", "tcp_echo": True, "udp_echo": True})
        report["pass"] = len(checks) == 8
    except Exception as error:
        report["error_type"] = type(error).__name__
        report["error"] = str(error)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for log in logs:
            log.close()
        if owned.parent != work_dir or not owned.name.startswith(".native-dns-"):
            raise RuntimeError("private cleanup path escaped its owner")
        shutil.rmtree(owned)
        report["ephemeral_files_removed"] = not owned.exists()
        report["all_processes_stopped"] = all(p.poll() is not None for p in processes)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--work-dir", required=True)
    args = parser.parse_args()
    result = execute(args.binary, args.work_dir)
    print(json.dumps(result))
    raise SystemExit(0 if result["pass"] else 1)
