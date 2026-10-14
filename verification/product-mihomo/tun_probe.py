"""Ordinary kernel sockets after the launcher drops to UID 20001."""
import json
import os
import socket
import sys
import time


def exchange(conn, payload):
    conn.sendall(payload)
    data = b""
    while len(data) < len(payload):
        part = conn.recv(len(payload) - len(data))
        if not part:
            raise RuntimeError("TCP EOF")
        data += part
    if data != payload:
        raise RuntimeError("TCP echo mismatch")


def emit(value):
    print(json.dumps({"uid": os.geteuid(), **value}), flush=True)


def main():
    if os.geteuid() != 20001:
        raise RuntimeError("probe requires UID 20001")
    cfg = json.loads(sys.argv[1])
    mode, host, port = cfg["mode"], cfg["host"], cfg["port"]
    payload = b"bfp-product-native-tun"
    if mode in ("tcp", "held-tcp", "blocked-tcp"):
        with socket.create_connection((host, port), timeout=5) as conn:
            conn.settimeout(8)
            exchange(conn, payload)
            emit({"stage": "before" if mode == "held-tcp" else "complete", "network": "tcp", "target": host,
                  "local": list(conn.getsockname()), "peer": list(conn.getpeername()), "pass": True})
            if mode == "held-tcp":
                if sys.stdin.readline().strip() != "continue":
                    raise RuntimeError("missing continuation")
                started = time.monotonic()
                exchange(conn, b"bfp-after-udp-failure")
                emit({"stage": "after", "pass": True, "elapsed_ms": round((time.monotonic() - started) * 1000),
                      "local": list(conn.getsockname()), "peer": list(conn.getpeername())})
    else:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as conn:
            conn.settimeout(5)
            conn.connect((host, port))
            conn.send(payload)
            data = conn.recv(4096)
            if data != payload:
                raise RuntimeError("UDP echo mismatch")
            emit({"stage": "complete", "network": "udp", "target": host, "local": list(conn.getsockname()),
                  "peer": list(conn.getpeername()), "pass": True})


try:
    main()
except Exception as exc:
    emit({"pass": False, "error": type(exc).__name__ + ": " + str(exc)})
    raise SystemExit(1)
