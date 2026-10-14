"""Real kernel application sockets through packaged TUN over the WAN fixture."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

CONTROL = Path("/control")
PRODUCT = Path("/tmp/bfp-native-tun")

IP_WRAPPER = r'''#!/usr/bin/env python3
import json,socket,sys
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
    conn.settimeout(12)
    conn.connect('/control/bridge.sock')
    conn.sendall(b'I'+json.dumps(sys.argv[1:]).encode()+b'\n')
    reply=b''
    while not reply.endswith(b'\n'):
        part=conn.recv(32768)
        if not part: raise RuntimeError('namespace ip helper EOF')
        reply+=part
    result=json.loads(reply)
sys.stdout.write(result['stdout']);sys.stderr.write(result['stderr'])
raise SystemExit(result['exit_code'])
'''


def exact(conn, size):
    out = bytearray()
    while len(out) < size:
        data = conn.recv(size - len(out))
        if not data:
            raise EOFError("unexpected socket EOF")
        out.extend(data)
    return bytes(out)


def application(cfg):
    if os.geteuid() != 20001:
        raise RuntimeError("application probe must use UID 20001")
    count, interval = cfg["count"], cfg["interval"]
    result = {"pass": False, "uid": os.geteuid(), "tcp": [], "udp": [], "tcp_completed": 0,
              "udp_completed": 0, "udp_failed": count}

    def dns(network, qtype):
        tid = os.urandom(2)
        packet = tid + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + b"\x09localhost\x00" + struct.pack("!HH", qtype, 1)
        kind = socket.SOCK_STREAM if network == "tcp" else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, kind) as conn:
            conn.settimeout(10)
            conn.connect(("192.0.2.53", 53))
            conn.sendall((struct.pack("!H", len(packet)) if network == "tcp" else b"") + packet)
            reply = exact(conn, struct.unpack("!H", exact(conn, 2))[0]) if network == "tcp" else conn.recv(2048)
        if reply[:2] != tid or len(reply) < 12 or (struct.unpack("!H", reply[2:4])[0] & 15):
            raise RuntimeError("TUN DNS query failed")
        qd, an = struct.unpack("!HH", reply[4:8])
        offset = 12

        def skip_name(pos):
            while reply[pos]:
                if reply[pos] & 0xc0 == 0xc0:
                    return pos + 2
                pos += 1 + reply[pos]
            return pos + 1

        for _ in range(qd):
            offset = skip_name(offset) + 4
        for _ in range(an):
            offset = skip_name(offset)
            typ, cls, ttl, length = struct.unpack("!HHIH", reply[offset:offset + 10])
            offset += 10
            data = reply[offset:offset + length]
            offset += length
            if typ == qtype and cls == 1:
                return socket.inet_ntop(socket.AF_INET if qtype == 1 else socket.AF_INET6, data)
        raise RuntimeError("TUN DNS answer missing")

    try:
        fake4, fake6 = dns("udp", 1), dns("tcp", 28)
        result["dns_before"] = {"A": fake4, "AAAA": fake6, "resolver": "192.0.2.53:53", "through_tun_hijack": True}
        print(json.dumps({"event": "dns_ready", "uid": os.geteuid(), "fake4": fake4, "fake6": fake6}), flush=True)
        if sys.stdin.readline().strip() != "continue":
            raise RuntimeError("probe continuation missing")
        started = time.monotonic()
        # This numeric target has no listener in the namespace. Its echo can
        # only come from the LA fixture via TUN and the authenticated Session.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as numeric:
            numeric.settimeout(6)
            numeric.connect((cfg["server_host"], cfg["fixture_port"]))
            numeric.send(b"bfp-numeric-tun-wan")
            result["numeric_ipv4_udp"] = numeric.recv(2048) == b"bfp-numeric-tun-wan"
        if not result["numeric_ipv4_udp"]:
            raise RuntimeError("numeric TUN UDP echo mismatch")

        def loop(network, host):
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM if network == "tcp" else socket.SOCK_DGRAM) as conn:
                conn.settimeout(6)
                conn.connect((host, cfg["fixture_port"]))
                local, peer = list(conn.getsockname()), list(conn.getpeername())
                for i in range(count):
                    payload = (("bfp-tun-wan-%s-%04d-" % (network, i)).encode() + bytes([i % 251]) * 1024)[:1024]
                    begin = time.monotonic()
                    conn.sendall(payload)
                    reply = exact(conn, len(payload)) if network == "tcp" else conn.recv(4096)
                    item = {"iteration": i, "ok": reply == payload, "bytes": len(reply),
                            "elapsed_ms": round((time.monotonic() - begin) * 1000, 1),
                            "same_local_and_peer": local == list(conn.getsockname()) and peer == list(conn.getpeername())}
                    result[network].append(item)
                    if not item["ok"] or not item["same_local_and_peer"]:
                        raise RuntimeError("held %s TUN flow changed or corrupted data" % network)
                    if i + 1 < count:
                        time.sleep(interval)
        with ThreadPoolExecutor(max_workers=2) as pool:
            tcp = pool.submit(loop, "tcp", fake4)
            udp = pool.submit(loop, "udp", fake6)
            tcp.result()
            udp.result()
        result["dns_after"] = {"A": dns("udp", 1), "AAAA": dns("tcp", 28)}
        result["fake_ip_lease_kept"] = all(result["dns_after"][k] == result["dns_before"][k] for k in ("A", "AAAA"))
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 1)
    except Exception as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
    result["tcp_completed"] = sum(x["ok"] for x in result["tcp"])
    result["udp_completed"] = sum(x["ok"] for x in result["udp"])
    result["udp_failed"] = count - result["udp_completed"]
    result["pass"] = bool(not result.get("error") and result["tcp_completed"] == count and
                          result["udp_completed"] == count and result.get("fake_ip_lease_kept"))
    print(json.dumps(result), flush=True)


def run():
    cfg = json.loads(Path("/bfp/tun-job.json").read_text())
    deadline = time.monotonic() + 35
    while not (CONTROL / "network-ready").exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("owned namespace not prepared")
        time.sleep(.1)
    for part in ("bin", "credentials", "configs", "tools"):
        (PRODUCT / part).mkdir(parents=True, mode=0o700)
    shutil.copyfile("/bfp/client.json", PRODUCT / "credentials/client.json")
    os.chmod(PRODUCT / "credentials/client.json", 0o600)
    shutil.copyfile("/bfp/start-native.sh", PRODUCT / "start-native.sh")
    (PRODUCT / "bin/mihomo-bfp-linux-amd64").symlink_to("/bfp/mihomo")
    (PRODUCT / "bin/bfp-linux-amd64").symlink_to("/bfp/bfp")
    (PRODUCT / "tools/ip").write_text(IP_WRAPPER)
    os.chmod(PRODUCT / "tools/ip", 0o700)
    os.environ["PATH"] = str(PRODUCT / "tools") + ":" + os.environ["PATH"]
    yaml = Path("/bfp/native-tun.yaml").read_text()
    yaml = yaml.replace("    client-config-file: ./credentials/client.json", "    client-config-file: ./credentials/client.json\n    interface-name: lo")
    yaml = yaml.replace("  nameserver: [1.1.1.1, 8.8.8.8]", "  nameserver: [127.0.0.1:15353]\n  use-hosts: false\n  use-system-hosts: false\n  fake-ip-filter-mode: whitelist\n  fake-ip-filter: [localhost]")
    yaml = yaml.replace("  proxy-server-nameserver: [1.1.1.1, 8.8.8.8]", "  proxy-server-nameserver: [127.0.0.1:15353]")
    (PRODUCT / "configs/native-tun.yaml").write_text(yaml)
    stop = threading.Event()
    connections = []
    native = probe = timer = None
    report = {"pass": False, "automatic_routes": True, "scenario": cfg["scenario"],
              "carrier_fixture": "loopback UDP/TCP to private Unix bridge; host sockets use the LA WAN endpoint"}

    def ns_snapshot():
        value = {}
        for family in ("-4", "-6"):
            for kind in ("rule", "route"):
                args = ["ip", family, "-j", kind, "show"] + (["table", "all"] if kind == "route" else [])
                value[family + kind] = json.loads(subprocess.check_output(args, text=True, timeout=12))
        return value

    def connect_bridge(kind):
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(10)
        conn.connect(str(CONTROL / "bridge.sock"))
        conn.sendall(kind)
        connections.append(conn)
        return conn

    def forward(client):
        upstream = None
        connections.append(client)
        try:
            upstream = connect_bridge(b"T")
            while not stop.is_set():
                ready, _, _ = select.select([client, upstream], [], [], .2)
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is client else client).sendall(data)
        except OSError:
            pass
        finally:
            client.close()
            if upstream is not None:
                upstream.close()

    def serve_tcp(listener):
        listener.settimeout(.2)
        while not stop.is_set():
            try:
                client, _ = listener.accept()
                threading.Thread(target=forward, args=(client,), daemon=True).start()
            except socket.timeout:
                pass
            except OSError:
                return

    def serve_udp(listener):
        upstream = connect_bridge(b"U")
        peer = None
        while not stop.is_set():
            try:
                ready, _, _ = select.select([listener, upstream], [], [], .2)
                for source in ready:
                    if source is listener:
                        data, peer = listener.recvfrom(65535)
                        upstream.sendall(struct.pack("!H", len(data)) + data)
                    else:
                        data = exact(upstream, struct.unpack("!H", exact(upstream, 2))[0])
                        if peer:
                            listener.sendto(data, peer)
            except OSError:
                return

    try:
        report["namespace_before"] = ns_snapshot()
        if cfg["scenario"] == "initial_udp_blocked":
            (CONTROL / "drop-udp").write_text("blocked")
        for kind, target in ((socket.SOCK_STREAM, serve_tcp), (socket.SOCK_DGRAM, serve_udp)):
            listener = socket.socket(socket.AF_INET, kind)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 51880))
            if kind == socket.SOCK_STREAM:
                listener.listen(8)
            connections.append(listener)
            threading.Thread(target=target, args=(listener,), daemon=True).start()
        with (PRODUCT / "native.log").open("wb") as log:
            native = subprocess.Popen(["sh", str(PRODUCT / "start-native.sh"), "tun"], stdout=log, stderr=log)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if native.poll() is not None:
                raise RuntimeError("packaged launcher exited")
            if "BFP TUN interface ready:" in (PRODUCT / "native.log").read_text(errors="replace"):
                break
            time.sleep(.1)
        else:
            raise RuntimeError("packaged TUN did not become ready")
        marker = PRODUCT / "runtime/bfp-tun-supervisor.env"
        device = re.search(r"^device=(bfp-tun-[0-9a-f]{7})$", marker.read_text(), re.M).group(1)
        report["device"] = device
        report["namespace_running"] = ns_snapshot()
        for host in (cfg["server_host"], "192.0.2.53", "198.18.0.2", "fd42:6266:7000::2"):
            family = "-6" if ":" in host else "-4"
            # Linux's auto-route rules match DNS destination port 53. A
            # port-less route query would describe non-DNS LAN traffic.
            dport = "53" if host == "192.0.2.53" else str(cfg["fixture_port"])
            rows = json.loads(subprocess.check_output(["ip", family, "-j", "route", "get", host, "ipproto", "udp", "dport", dport, "uid", "20001"], text=True, timeout=12))
            report.setdefault("application_routes", {})[host] = rows
            if not rows or rows[0].get("dev") != device:
                raise RuntimeError("automatic application route bypasses TUN: " + host)
        launch = "import os,runpy; m=runpy.run_path('/bfp/wan_tun_container.py'); os.setgroups([]);os.setgid(20001);os.setuid(20001);m['application'](" + repr(cfg) + ")"
        probe = subprocess.Popen(["python3", "-u", "-c", launch], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        first = json.loads(probe.stdout.readline())
        report["dns_ready"] = first
        if first.get("event") != "dns_ready" or first.get("uid") != 20001:
            report["probe"] = first
            raise RuntimeError("kernel DNS query through TUN failed")
        if cfg["scenario"] == "udp_to_tcp":
            timer = threading.Timer(8, lambda: (CONTROL / "drop-udp").write_text("blocked"))
            timer.start()
        stdout, stderr = probe.communicate("continue\n", timeout=55)
        report["probe"] = json.loads(stdout.strip().splitlines()[-1])
        report["probe_exit_code"] = probe.returncode
        if probe.returncode or not report["probe"].get("pass"):
            raise RuntimeError("ordinary TUN application probe failed")
        native.terminate()
        native.wait(timeout=9)
        report["launcher_exit_code"] = native.returncode
        report["owned_device_removed"] = device not in {name for _, name in socket.if_nameindex()}
        report["owned_marker_removed"] = not marker.exists() and not (PRODUCT / "runtime/native-tun.generated.yaml").exists()
        report["namespace_after"] = ns_snapshot()
        report["routes_and_rules_restored"] = report["namespace_after"] == report["namespace_before"]
        report["pass"] = bool(native.returncode == 143 and report["owned_device_removed"] and report["owned_marker_removed"] and report["routes_and_rules_restored"])
    except Exception as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        if timer:
            timer.cancel()
            timer.join(timeout=1)
        for proc in (probe, native):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=9)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
        stop.set()
        for conn in connections:
            conn.close()
        log_path = PRODUCT / "native.log"
        report["native_log"] = log_path.read_text(errors="replace")[-10000:] if log_path.is_file() else ""
        (CONTROL / "result.json").write_text(json.dumps(report))
        # This public evidence is collected by the host's ubuntu user. The
        # enclosing control/run directories remain private (0700); configs
        # and credentials are never written into the evidence file.
        os.chmod(CONTROL / "result.json", 0o644)
        # The host collects the result and removes this owned container.
        time.sleep(3)


if __name__ == "__main__":
    try:
        run()
    except Exception as exc:
        (CONTROL / "result.json").write_text(json.dumps({"pass": False, "error": type(exc).__name__ + ": " + str(exc)}))
