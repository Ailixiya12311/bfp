#!/usr/bin/env python3
"""Small, dependency-free helpers for the next26 Mihomo TUN acceptance run.

The program is intended to run *inside* the owned Linux container.  It never
changes routes, starts a proxy, or uses a SOCKS/BFP API.  Route changes belong
to the container runner, while this file provides the ordinary socket fixture,
DNS answers, route evidence, and packet-capture checks used by that runner.

Every command emits JSON evidence.  A missing optional tool is reported as
``available: false``; it is never silently treated as a passing observation.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import json
import os
import pathlib
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from shutil import which
from typing import Any, Iterable


DEFAULT_RECORDS = {
    "bfp-v4.test": {"A": "192.0.2.10"},
    "bfp-v6.test": {"AAAA": "fd77:25::10"},
    "bfp-carrier-v4.test": {"A": "192.0.2.20"},
    "bfp-carrier-v6.test": {"AAAA": "fd77:25::20"},
    "bfp-detour-v4.test": {"A": "192.0.2.30"},
    "bfp-detour-v6.test": {"AAAA": "fd77:25::30"},
}


def json_line(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def emit(value: Any, path: str | None = None) -> None:
    line = json_line(value)
    print(line, flush=True)
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def safe_addr(value: str) -> str:
    """Canonicalise an address without DNS or network access."""
    return str(ipaddress.ip_address(value.strip("[]").split("%", 1)[0]))


def parse_host_port(value: str) -> tuple[str, int]:
    if value.startswith("["):
        host, port = value.rsplit("]:", 1)
        return host[1:], int(port)
    host, port = value.rsplit(":", 1)
    return host, int(port)


def wait_signal() -> threading.Event:
    stop = threading.Event()
    def handler(_signum: int, _frame: Any) -> None:
        stop.set()
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)
    return stop


def write_event(path: str | None, lock: threading.Lock, value: dict[str, Any]) -> None:
    if not path:
        return
    with lock:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json_line(value) + "\n")
            handle.flush()


class EchoFixture:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.stop = wait_signal()
        self.lock = threading.Lock()
        self.counts: Counter[str] = Counter()
        self.log = args.log
        self.threads: list[threading.Thread] = []
        self.sockets: list[socket.socket] = []

    def record(self, event: str, **extra: Any) -> None:
        self.counts[event] += 1
        write_event(self.log, self.lock, {"event": event, "ts": time.time(), **extra})

    def bind(self, family: int, host: str, port: int, kind: str) -> socket.socket:
        sock_type = socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM
        sock = socket.socket(family, sock_type)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port))
        if kind == "tcp":
            sock.listen(64)
        sock.settimeout(0.25)
        self.sockets.append(sock)
        return sock

    def tcp_client(self, conn: socket.socket, peer: Any, bind_addr: Any) -> None:
        with conn:
            self.record("tcp_open", peer=repr(peer), local=repr(bind_addr))
            conn.settimeout(2.0)
            while not self.stop.is_set():
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    continue
                except OSError as exc:
                    self.record("tcp_error", error=str(exc))
                    return
                if not data:
                    return
                conn.sendall(data)
                self.record("tcp_echo", bytes=len(data), peer=repr(peer))

    def tcp_loop(self, sock: socket.socket) -> None:
        while not self.stop.is_set():
            try:
                conn, peer = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self.tcp_client, args=(conn, peer, sock.getsockname()), daemon=True)
            thread.start()
            self.threads.append(thread)

    def udp_loop(self, sock: socket.socket) -> None:
        while not self.stop.is_set():
            try:
                data, peer = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                sock.sendto(data, peer)
                self.record("udp_echo", bytes=len(data), peer=repr(peer), local=repr(sock.getsockname()))
            except OSError as exc:
                self.record("udp_error", error=str(exc))

    def run(self) -> int:
        try:
            for family, host in ((socket.AF_INET, self.args.ipv4), (socket.AF_INET6, self.args.ipv6)):
                if not host:
                    continue
                for kind in ("tcp", "udp"):
                    if self.args.mode not in (kind, "both"):
                        continue
                    try:
                        sock = self.bind(family, host, self.args.port, kind)
                    except OSError as exc:
                        self.record("bind_error", family=family, host=host, kind=kind, error=str(exc))
                        return 2
                    target = self.tcp_loop if kind == "tcp" else self.udp_loop
                    thread = threading.Thread(target=target, args=(sock,), daemon=True)
                    thread.start()
                    self.threads.append(thread)
                    self.record("listening", family=family, kind=kind, address=repr(sock.getsockname()))
            if not self.sockets:
                self.record("bind_error", error="no listen addresses")
                return 2
            while not self.stop.wait(0.25):
                pass
            return 0
        finally:
            for sock in self.sockets:
                try:
                    sock.close()
                except OSError:
                    pass
            self.record("stopped", counts=dict(self.counts))


def dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    original = offset
    jumped = False
    seen: set[int] = set()
    while True:
        if offset >= len(data):
            raise ValueError("DNS name outside packet")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("short DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer in seen:
                raise ValueError("DNS pointer loop")
            seen.add(pointer)
            label, _ = dns_name(data, pointer)
            labels.append(label)
            offset += 2
            jumped = True
            break
        if length > 63 or offset + 1 + length > len(data):
            raise ValueError("invalid DNS label")
        labels.append(data[offset + 1 : offset + 1 + length].decode("idna"))
        offset += 1 + length
    return ".".join(labels).lower(), (original + 2 if jumped else offset)


def dns_wire_name(name: str) -> bytes:
    return b"".join(bytes((len(label),)) + label.encode("idna") for label in name.rstrip(".").split(".")) + b"\0"


def dns_response(query: bytes, records: dict[str, dict[str, str]]) -> tuple[bytes, dict[str, Any]]:
    if len(query) < 12:
        raise ValueError("short DNS header")
    ident, flags, qd, _an, _ns, _ar = struct.unpack("!HHHHHH", query[:12])
    if qd != 1:
        raise ValueError("fixture only supports one DNS question")
    name, offset = dns_name(query, 12)
    if offset + 4 > len(query):
        raise ValueError("short DNS question")
    qtype, qclass = struct.unpack("!HH", query[offset : offset + 4])
    question = query[12 : offset + 4]
    typ = {1: "A", 28: "AAAA"}.get(qtype)
    raw = records.get(name, {}).get(typ or "") if typ else None
    answer = b""
    if raw:
        ip = ipaddress.ip_address(raw)
        expected_version = 4 if typ == "A" else 6
        if ip.version != expected_version:
            raise ValueError("record family mismatch")
        answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, qclass, 30, len(ip.packed)) + ip.packed
    response_flags = 0x8000 | 0x0400 | 0x0080 | (flags & 0x0100)
    packet = struct.pack("!HHHHHH", ident, response_flags, 1, 1 if answer else 0, 0, 0) + question + answer
    return packet, {"name": name, "qtype": typ or str(qtype), "answer": raw, "rcode": 0}


class DNSFixture:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.stop = wait_signal()
        self.lock = threading.Lock()
        self.records = DEFAULT_RECORDS.copy()
        if args.records:
            with open(args.records, encoding="utf-8") as handle:
                loaded = json.load(handle)
            self.records.update({str(k).rstrip(".").lower(): dict(v) for k, v in loaded.items()})
        self.log = args.log
        self.sockets: list[socket.socket] = []

    def query(self, payload: bytes, transport: str, peer: Any) -> bytes:
        try:
            reply, detail = dns_response(payload, self.records)
            write_event(self.log, self.lock, {"event": "dns_query", "transport": transport, "peer": repr(peer), **detail})
            return reply
        except Exception as exc:
            write_event(self.log, self.lock, {"event": "dns_error", "transport": transport, "peer": repr(peer), "error": str(exc)})
            return b""

    def udp_loop(self, sock: socket.socket) -> None:
        sock.settimeout(0.25)
        while not self.stop.is_set():
            try:
                payload, peer = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            reply = self.query(payload, "udp", peer)
            if reply:
                try:
                    sock.sendto(reply, peer)
                except OSError:
                    return

    def tcp_client(self, conn: socket.socket, peer: Any) -> None:
        with conn:
            conn.settimeout(2.0)
            try:
                header = conn.recv(2)
                if len(header) != 2:
                    return
                size = struct.unpack("!H", header)[0]
                payload = b""
                while len(payload) < size:
                    chunk = conn.recv(size - len(payload))
                    if not chunk:
                        return
                    payload += chunk
                reply = self.query(payload, "tcp", peer)
                conn.sendall(struct.pack("!H", len(reply)) + reply)
            except (OSError, ValueError):
                return

    def tcp_loop(self, sock: socket.socket) -> None:
        sock.settimeout(0.25)
        while not self.stop.is_set():
            try:
                conn, peer = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.tcp_client, args=(conn, peer), daemon=True).start()

    def run(self) -> int:
        try:
            for kind in ("udp", "tcp"):
                typ = socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM
                sock = socket.socket(socket.AF_INET, typ)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.args.host, self.args.port))
                if kind == "tcp":
                    sock.listen(32)
                self.sockets.append(sock)
                thread = threading.Thread(target=self.udp_loop if kind == "udp" else self.tcp_loop, args=(sock,), daemon=True)
                thread.start()
            emit({"event": "dns_listening", "address": f"{self.args.host}:{self.args.port}", "records": sorted(self.records)})
            while not self.stop.wait(0.25):
                pass
            return 0
        except OSError as exc:
            emit({"event": "dns_bind_error", "error": str(exc)})
            return 2
        finally:
            for sock in self.sockets:
                try:
                    sock.close()
                except OSError:
                    pass


def command_probe(args: argparse.Namespace) -> int:
    try:
        target = safe_addr(args.host)
        family = socket.AF_INET6 if ":" in target else socket.AF_INET
        payload = args.payload.encode("utf-8")
        started = time.monotonic()
        if args.network == "tcp":
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(args.timeout)
                sock.connect((target, args.port))
                peer = sock.getpeername()
                sock.sendall(payload)
                received = b""
                while len(received) < len(payload):
                    chunk = sock.recv(len(payload) - len(received))
                    if not chunk:
                        break
                    received += chunk
                source = peer[0]
        else:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(args.timeout)
                sock.sendto(payload, (target, args.port))
                received, peer = sock.recvfrom(65535)
                source = peer[0]
        expected_source = safe_addr(args.expect_source) if args.expect_source else None
        source_ok = expected_source is None or safe_addr(source) == expected_source
        passed = received == payload and source_ok
        result = {
            "event": "probe",
            "pass": passed,
            "network": args.network,
            "target": target,
            "port": args.port,
            "source": safe_addr(source),
            "expected_source": expected_source,
            "bytes": len(received),
            "payload_sha256": __import__("hashlib").sha256(payload).hexdigest(),
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            "uid": getattr(os, "getuid", lambda: None)(),
        }
        if args.output:
            pathlib.Path(args.output).write_text(json_line(result) + "\n", encoding="utf-8")
        print(json_line(result), flush=True)
        return 0 if passed else 1
    except Exception as exc:
        result = {"event": "probe", "pass": False, "network": args.network, "target": args.host, "port": args.port, "error": str(exc)}
        print(json_line(result), flush=True)
        if args.output:
            pathlib.Path(args.output).write_text(json_line(result) + "\n", encoding="utf-8")
        return 1


def run_capture(command: list[str]) -> dict[str, Any]:
    if not command or not which(command[0]):
        return {"available": False, "command": command, "error": "command not found"}
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=10)
        return {"available": True, "command": command, "exit_code": proc.returncode, "stdout": proc.stdout[-16384:], "stderr": proc.stderr[-4096:]}
    except Exception as exc:
        return {"available": True, "command": command, "error": str(exc)}


def command_route(args: argparse.Namespace) -> int:
    destination = safe_addr(args.destination)
    family_flag = "-6" if ":" in destination else "-4"
    records = {
        "event": "route_snapshot",
        "netns": os.stat("/proc/self/ns/net").st_ino if os.path.exists("/proc/self/ns/net") else None,
        "destination": destination,
        "uid": args.uid,
        "route_get": run_capture(["ip", "-j", family_flag, "route", "get", destination, "uid", str(args.uid)]),
        "rules": run_capture(["ip", "-j", family_flag, "rule", "show"]),
        "links": run_capture(["ip", "-j", "link", "show"]),
    }
    if args.output:
        pathlib.Path(args.output).write_text(json_line(records) + "\n", encoding="utf-8")
    print(json_line(records), flush=True)
    if args.require and not records["route_get"].get("available"):
        return 2
    return 0


def cap_status() -> dict[str, Any]:
    result: dict[str, Any] = {"euid": getattr(os, "geteuid", lambda: None)(), "has_ipv6": socket.has_ipv6}
    tun = pathlib.Path("/dev/net/tun")
    result["tun_device"] = {"exists": tun.exists(), "mode": oct(tun.stat().st_mode) if tun.exists() else None}
    status = pathlib.Path("/proc/self/status")
    if status.exists():
        for line in status.read_text(errors="replace").splitlines():
            if line.startswith("CapEff:"):
                value = int(line.split()[1], 16)
                result["cap_eff_hex"] = line.split()[1]
                result["cap_net_admin"] = bool(value & (1 << 12))
                result["cap_net_raw"] = bool(value & (1 << 13))
    for key in ("all", "default"):
        p = pathlib.Path(f"/proc/sys/net/ipv6/conf/{key}/disable_ipv6")
        if p.exists():
            result[f"ipv6_disable_{key}"] = p.read_text().strip()
    return result


def command_preflight(args: argparse.Namespace) -> int:
    required = {name: which(name) for name in ("ip", "tcpdump", "ss")}
    result = {"event": "preflight", "available": True, "commands": required, "capabilities": cap_status(), "argv": sys.argv}
    if args.output:
        pathlib.Path(args.output).write_text(json_line(result) + "\n", encoding="utf-8")
    print(json_line(result), flush=True)
    missing = [name for name, path in required.items() if not path]
    if args.require and missing:
        return 2
    return 0


def pcap_packets(path: str) -> Iterable[dict[str, Any]]:
    raw = pathlib.Path(path).read_bytes()
    if len(raw) < 24:
        raise ValueError("short pcap")
    magic = raw[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("unsupported pcap magic or pcapng input")
    _major, _minor, _tz, _sigfigs, _snaplen, linktype = struct.unpack(endian + "HHiiii", raw[4:24])
    offset = 24
    while offset + 16 <= len(raw):
        _sec, _usec, incl, _orig = struct.unpack(endian + "IIII", raw[offset : offset + 16])
        offset += 16
        payload = raw[offset : offset + incl]
        offset += incl
        if len(payload) != incl:
            break
        packet = decode_packet(payload, linktype)
        if packet:
            yield packet


def decode_packet(payload: bytes, linktype: int) -> dict[str, Any] | None:
    if linktype == 1:  # Ethernet, including common VLAN tags.
        if len(payload) < 14:
            return None
        offset, ethertype = 14, struct.unpack("!H", payload[12:14])[0]
        while ethertype in (0x8100, 0x88A8, 0x9100) and len(payload) >= offset + 4:
            ethertype = struct.unpack("!H", payload[offset + 2 : offset + 4])[0]
            offset += 4
        payload = payload[offset:]
        version = 4 if ethertype == 0x0800 else 6 if ethertype == 0x86DD else 0
    elif linktype == 113:  # Linux cooked v1
        if len(payload) < 16:
            return None
        version = 4 if struct.unpack("!H", payload[14:16])[0] == 0x0800 else 6 if struct.unpack("!H", payload[14:16])[0] == 0x86DD else 0
        payload = payload[16:]
    elif linktype == 276:  # Linux cooked v2
        if len(payload) < 20:
            return None
        protocol = struct.unpack("!H", payload[0:2])[0]
        version = 4 if protocol == 0x0800 else 6 if protocol == 0x86DD else 0
        payload = payload[20:]
    elif linktype in (101, 228, 12):  # raw IP / DLT_IPV4 / DLT_RAW
        version = (payload[0] >> 4) if payload else 0
    else:
        return None
    if version == 4:
        if len(payload) < 20:
            return None
        ihl = (payload[0] & 0x0F) * 4
        if len(payload) < ihl:
            return None
        proto = payload[9]
        src, dst = str(ipaddress.ip_address(payload[12:16])), str(ipaddress.ip_address(payload[16:20]))
        body = payload[ihl:]
    elif version == 6:
        if len(payload) < 40:
            return None
        proto = payload[6]
        src, dst = str(ipaddress.ip_address(payload[8:24])), str(ipaddress.ip_address(payload[24:40]))
        body = payload[40:]
    else:
        return None
    sport = dport = None
    if proto in (6, 17) and len(body) >= 4:
        sport, dport = struct.unpack("!HH", body[:4])
    return {"ip_version": version, "protocol": "tcp" if proto == 6 else "udp" if proto == 17 else str(proto), "src": src, "dst": dst, "sport": sport, "dport": dport, "bytes": len(payload)}


def command_pcap(args: argparse.Namespace) -> int:
    try:
        packets = list(pcap_packets(args.pcap))
        counts = Counter((p["protocol"], p["src"], p["dst"], p["sport"], p["dport"]) for p in packets)
        result: dict[str, Any] = {"event": "pcap", "available": True, "pcap": args.pcap, "packets": len(packets), "flows": [{"protocol": k[0], "src": k[1], "dst": k[2], "sport": k[3], "dport": k[4], "packets": n} for k, n in counts.items()]}
        if args.require_destination:
            dst = safe_addr(args.require_destination)
            result["required_destination_packets"] = sum(1 for p in packets if p["dst"] == dst)
            result["pass"] = result["required_destination_packets"] >= args.minimum
        if args.forbid_destination:
            dst = safe_addr(args.forbid_destination)
            result["forbidden_destination_packets"] = sum(1 for p in packets if p["dst"] == dst)
            result["pass"] = result.get("pass", True) and result["forbidden_destination_packets"] == 0
    except Exception as exc:
        result = {"event": "pcap", "available": False, "pcap": args.pcap, "pass": False, "error": str(exc)}
    if args.output:
        pathlib.Path(args.output).write_text(json_line(result) + "\n", encoding="utf-8")
    print(json_line(result), flush=True)
    return 0 if result.get("pass", True) else 1


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)
    p = sub.add_parser("echo", help="ordinary TCP/UDP echo fixture")
    p.add_argument("--mode", choices=("tcp", "udp", "both"), default="both")
    p.add_argument("--ipv4", default="192.0.2.10")
    p.add_argument("--ipv6", default="fd77:25::10")
    p.add_argument("--port", type=int, default=18080)
    p.add_argument("--log")
    p.set_defaults(func=lambda a: EchoFixture(a).run())
    p = sub.add_parser("dns", help="A/AAAA DNS fixture, UDP and TCP")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=15353)
    p.add_argument("--records")
    p.add_argument("--log")
    p.set_defaults(func=lambda a: DNSFixture(a).run())
    p = sub.add_parser("probe", help="ordinary numeric TCP/UDP socket probe")
    p.add_argument("--network", choices=("tcp", "udp"), required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--payload", default="tun-next26")
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--expect-source")
    p.add_argument("--output")
    p.set_defaults(func=command_probe)
    p = sub.add_parser("route", help="route/rule/netns evidence")
    p.add_argument("--destination", required=True)
    p.add_argument("--uid", type=int, default=20001)
    p.add_argument("--output")
    p.add_argument("--require", action="store_true")
    p.set_defaults(func=command_route)
    p = sub.add_parser("preflight", help="container capability/tool preflight")
    p.add_argument("--output")
    p.add_argument("--require", action="store_true")
    p.set_defaults(func=command_preflight)
    p = sub.add_parser("pcap", help="parse classic pcap without scapy")
    p.add_argument("--pcap", required=True)
    p.add_argument("--output")
    p.add_argument("--require-destination")
    p.add_argument("--forbid-destination")
    p.add_argument("--minimum", type=int, default=1)
    p.set_defaults(func=command_pcap)
    return root


if __name__ == "__main__":
    parsed = parser().parse_args()
    raise SystemExit(parsed.func(parsed))
