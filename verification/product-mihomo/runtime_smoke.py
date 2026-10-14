"""Run the released native Mihomo, BFP server and loopback echo endpoints."""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import ipaddress
import json
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import tempfile
import time


def recv_exact(conn, count):
    data = bytearray()
    while len(data) < count:
        part = conn.recv(count - len(data))
        if not part:
            raise RuntimeError("unexpected EOF")
        data.extend(part)
    return bytes(data)


def endpoint():
    with socket.socket() as conn:
        conn.bind(("127.0.0.1", 0))
        return conn.getsockname()


def ready(process, address):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("program exited before opening its listener")
        try:
            with socket.create_connection(address, timeout=.1):
                return
        except OSError:
            time.sleep(.02)
    raise RuntimeError("listener startup timeout")


def ready_runtime(process, log_file):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("native process exited before runtime ready")
        if "Mihomo runtime ready" in pathlib.Path(log_file).read_text(errors="replace"):
            return
        time.sleep(.01)
    raise RuntimeError("native runtime startup timeout")


def skip_name(data, offset):
    while offset < len(data):
        size = data[offset]
        if size & 0xc0 == 0xc0:
            if offset + 1 >= len(data):
                break
            return offset + 2
        offset += 1
        if size == 0:
            return offset
        if size > 63 or offset + size > len(data):
            break
        offset += size
    raise RuntimeError("invalid DNS name")


def dns_address(address, network, typ, name="localhost"):
    question = b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\0" + struct.pack("!HH", typ, 1)
    wire = struct.pack("!6H", 0xbf06, 0x100, 1, 0, 0, 0) + question
    if network == "tcp":
        with socket.create_connection(address, timeout=3) as conn:
            conn.sendall(struct.pack("!H", len(wire)) + wire)
            data = recv_exact(conn, struct.unpack("!H", recv_exact(conn, 2))[0])
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
            conn.settimeout(3)
            conn.connect(address)
            conn.send(wire)
            data = conn.recv(4096)
    ident, flags, qd, an, _, _ = struct.unpack_from("!6H", data)
    if ident != 0xbf06 or not flags & 0x8000 or flags & 15 or qd != 1:
        raise RuntimeError("DNS query failed")
    offset = skip_name(data, 12) + 4
    for _ in range(an):
        offset = skip_name(data, offset)
        rtype, cls, _, count = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        if rtype == typ and cls == 1 and count == (4 if typ == 1 else 16):
            ip = ipaddress.ip_address(data[offset:offset + count])
            # The BFP Session-scoped AAAA pool is deliberately separate from
            # Mihomo's built-in fake-IP pool. Keep this verifier tied to the
            # product template so a pool migration cannot silently turn an
            # AAAA mapping check into a real-address check.
            pool = ipaddress.ip_network("198.18.0.0/15" if typ == 1 else "fd42:6266:7000::/96")
            if ip not in pool:
                raise RuntimeError("DNS returned a real address instead of fake-IP")
            return ip
        offset += count
    raise RuntimeError("DNS returned no requested address")


def wire_address(host, port):
    try:
        ip = ipaddress.ip_address(host)
        address = bytes((1 if ip.version == 4 else 4,)) + ip.packed
    except ValueError:
        name = host.encode("ascii")
        address = bytes((3, len(name))) + name
    return address + struct.pack("!H", port)


def read_socks_address(conn):
    typ = recv_exact(conn, 1)[0]
    if typ in (1, 4):
        host = str(ipaddress.ip_address(recv_exact(conn, 4 if typ == 1 else 16)))
    elif typ == 3:
        host = recv_exact(conn, recv_exact(conn, 1)[0]).decode("ascii")
    else:
        raise RuntimeError("invalid SOCKS address")
    return host, struct.unpack("!H", recv_exact(conn, 2))[0]


def request(address, command, host, port):
    conn = socket.create_connection(address, timeout=5)
    try:
        conn.sendall(b"\x05\x01\0")
        if recv_exact(conn, 2) != b"\x05\0":
            raise RuntimeError("SOCKS greeting failed")
        conn.sendall(bytes((5, command, 0)) + wire_address(host, port))
        if recv_exact(conn, 3) != b"\x05\0\0":
            raise RuntimeError("SOCKS request failed")
        return conn, read_socks_address(conn)
    except BaseException:
        conn.close()
        raise


def tcp_echo(address, host, port, payload):
    conn, _ = request(address, 1, host, port)
    with conn:
        conn.sendall(payload)
        if recv_exact(conn, len(payload)) != payload:
            raise RuntimeError("native TCP echo mismatch")


def udp_echo(address, host, port, payload):
    control, relay = request(address, 3, "0.0.0.0", 0)
    if relay[0] == "0.0.0.0":
        relay = address[0], relay[1]
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.settimeout(5)
        conn.bind(("127.0.0.1", 0))
        conn.connect(relay)
        conn.send(bytes(3) + wire_address(host, port) + payload)
        data = conn.recv(4096)
        if data[:3] != bytes(3):
            raise RuntimeError("invalid SOCKS UDP reply")
        at = 4
        if data[3] in (1, 4):
            at += 4 if data[3] == 1 else 16
        elif data[3] == 3:
            at += 1 + data[at]
        else:
            raise RuntimeError("invalid UDP reply address")
        if struct.unpack_from("!H", data, at)[0] != port or data[at + 2:] != payload:
            raise RuntimeError("native UDP echo mismatch")


def json_events(path):
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events


def classification_mix(mixed, target, interactive, owned, report):
    """Small real native traffic sample; it does not test saturated fairness."""
    result = {"pass": False, "phase": "opening", "bulk_bytes": 0,
              "interactive_completed": 0, "udp_completed": 0, "interactive_rtt_ms": [],
              "scope": "loopback native JSON policy, three held flows, 16 KiB/s for 10s; no saturation, FEC or WAN"}
    report["classification_mix"] = result
    with contextlib.ExitStack() as sockets:
        bulk, _ = request(mixed, 1, target[0], target[1])
        sockets.enter_context(bulk)
        fast, _ = request(mixed, 1, interactive[0], interactive[1])
        sockets.enter_context(fast)
        control, relay = request(mixed, 3, "0.0.0.0", 0)
        sockets.enter_context(control)
        udp = sockets.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        udp.settimeout(5)
        udp.bind(("127.0.0.1", 0))
        udp.connect((mixed[0], relay[1]) if relay[0] == "0.0.0.0" else relay)
        def exchange():
            payload = ("interactive-%04d" % result["interactive_completed"]).encode()
            began = time.monotonic()
            fast.sendall(payload)
            if recv_exact(fast, len(payload)) != payload:
                raise RuntimeError("mixed Interactive echo mismatch")
            result["interactive_rtt_ms"].append(round((time.monotonic() - began) * 1000, 3))
            result["interactive_completed"] += 1
            payload = ("normal-udp-%04d" % result["udp_completed"]).encode()
            wire = bytes(3) + wire_address(target[0], target[1]) + payload
            udp.send(wire)
            if udp.recv(4096) != wire:
                raise RuntimeError("mixed Normal UDP echo mismatch")
            result["udp_completed"] += 1
        exchange()
        def current():
            events = [v for v in json_events(owned / "server.log") if v.get("event") == "stats"]
            if not events:
                return None
            value = events[-1]
            if not value.get("classification_snapshot_ok") or len(value.get("sessions") or []) != 1:
                return None
            session = value["sessions"][0]
            views = (value.get("classifications") or {}).get(session["session_id"]) or []
            return {"session": session, "flows": views} if len(views) == 3 else None
        def stable(value, bulk_class):
            if value is None:
                return False
            for flow in value["flows"]:
                baseline = flow["LocalTX"]["Baseline"]
                expected = bulk_class if flow["Network"] == "tcp" and baseline["Class"] == 1 else baseline["Class"]
                if (flow["LocalTX"]["Class"] != expected or flow["PeerTX"].get("Class") != expected
                    or not flow["PeerTX"].get("Known") or flow["TXVersion"] == 0 or flow["TXPending"]
                    or flow["TXPublishedVersion"] != flow["TXVersion"] or flow["TXAckedVersion"] != flow["TXVersion"]):
                    return False
            return True
        def wait_class(expected, seconds):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                value = current()
                if stable(value, expected):
                    return value
                time.sleep(.05)
            result["last_snapshot"] = current()
            raise RuntimeError("mixed classification phase did not settle: " + result["phase"])
        result["phase"] = "initial-normal"
        initial = wait_class(1, 3)
        result["initial"] = initial
        if sorted((v["Network"], v["LocalTX"]["Baseline"]["Class"]) for v in initial["flows"]) != [("tcp", 0), ("tcp", 1), ("udp", 1)]:
            raise RuntimeError("mixed baseline classes were not Interactive TCP, Normal TCP and Normal UDP")
        opened = {name: [v for v in json_events(owned / (name + ".log")) if v.get("event") == "target_open"][-1]["opened"] for name in ("echo4", "interactive")}
        result["phase"] = "sustained-transfer"
        began = time.monotonic()
        payload = b"bfp-native-classification".ljust(4096, b"x")
        for index in range(40):
            bulk.sendall(payload)
            if recv_exact(bulk, len(payload)) != payload:
                raise RuntimeError("mixed Bulk echo mismatch")
            result["bulk_bytes"] += len(payload)
            exchange()
            time.sleep(max(0, began + (index + 1) * .25 - time.monotonic()))
        result["phase"] = "bulk-published"
        bulk_view = wait_class(2, 2)
        result["bulk"] = bulk_view
        bulk_id = next(v["ID"] for v in initial["flows"] if v["Network"] == "tcp" and v["LocalTX"]["Baseline"]["Class"] == 1)
        result["phase"] = "idle-restore"
        idle_started = time.monotonic()
        restored = wait_class(1, 13)
        result["restored"] = restored
        result["idle_restore_ms"] = round((time.monotonic() - idle_started) * 1000, 3)
        histories = [v for v in json_events(owned / "server.log") if v.get("event") == "stats" and (v.get("classifications") or {}).get(initial["session"]["session_id"])]
        ids = {v["ID"] for v in initial["flows"]}
        expected_bytes = {v["ID"]: v["LocalTX"]["TotalBytes"] for v in bulk_view["flows"]}
        result["same_session_and_flows"] = all(len(v["sessions"]) == 1 and v["sessions"][0]["session_id"] == initial["session"]["session_id"] for v in histories) and {v["ID"] for v in restored["flows"]} == ids
        result["idle_application_bytes_unchanged"] = all(v["LocalTX"]["TotalBytes"] == expected_bytes[v["ID"]] for v in restored["flows"])
        result["bulk_application_bytes_exact"] = expected_bytes[bulk_id] == result["bulk_bytes"]
        result["interactive_locked"] = all(flow["LocalTX"]["Class"] == 0 and flow["LocalTX"]["Baseline"]["Locked"] for value in histories for flow in value["classifications"][initial["session"]["session_id"]] if flow["LocalTX"]["Baseline"]["Class"] == 0)
        after = {name: [v for v in json_events(owned / (name + ".log")) if v.get("event") == "target_open"][-1]["opened"] for name in opened}
        result["target_connections_not_reopened"] = after == opened
        result["target_open_counts"] = {"initial": opened, "final": after}
        if not all(result[name] for name in ("same_session_and_flows", "idle_application_bytes_unchanged", "bulk_application_bytes_exact", "interactive_locked", "target_connections_not_reopened")):
            raise RuntimeError("mixed classification state or byte accounting check failed")
        exchange()
        result["pass"], result["phase"] = True, "complete"


def execute(bfp, mihomo, templates, work_dir, classification_profile="standard", mixed_classification=False):
    bfp, mihomo, templates = [pathlib.Path(p).resolve(strict=True) for p in (bfp, mihomo, templates)]
    work_dir = pathlib.Path(work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    owned = pathlib.Path(tempfile.mkdtemp(prefix=".native-mihomo-", dir=work_dir)).resolve()
    processes, outputs = [], []
    report = {"pass": False, "scope": "packaged native mixed SOCKS TCP/UDP and fake-IP DNS; loopback, no TUN or WAN",
              "binaries": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (bfp, mihomo)},
              "classification_profile": classification_profile, "checks": []}
    try:
        addresses = []
        while len(addresses) < (5 if mixed_classification else 4):
            candidate = endpoint()
            if candidate not in addresses:
                addresses.append(candidate)
        server, mixed, dns, target = addresses[:4]
        interactive = addresses[4] if mixed_classification else None
        text = lambda p: p[0] + ":" + str(p[1])
        keygen_args = [str(bfp), "keygen", "-out", str(owned / "credentials"), "-server-listen", text(server),
                       "-server", text(server), "-tcp-server", text(server)]
        if classification_profile != "standard":
            keygen_args += ["-classification-profile", classification_profile]
        keygen = subprocess.run(keygen_args, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=5)
        if keygen.returncode:
            raise RuntimeError("keygen failed")
        config_file = owned / "credentials/server.json"
        server_config = json.loads(config_file.read_text(encoding="utf-8"))
        server_config["policy"].update(AllowPrivate=True, AllowedCIDRs=["127.0.0.0/8", "::1/128"], AllowedPorts=[target[1]])
        if mixed_classification:
            server_config["policy"]["AllowedPorts"].append(interactive[1])
            rule = {"name": "local-interactive", "network": "tcp", "ports": [{"first": interactive[1], "last": interactive[1]}], "class": "interactive", "locked": True, "priority": 100}
            client_file = owned / "credentials/client.json"
            client_config = json.loads(client_file.read_text(encoding="utf-8"))
            for configuration in (server_config, client_config):
                configuration["classification"]["rules"].insert(0, rule)
            client_file.write_text(json.dumps(client_config), encoding="utf-8")
        config_file.write_text(json.dumps(server_config), encoding="utf-8")
        configs = owned / "configs"
        shutil.copytree(templates, configs)
        for name in ("native-proxy.yaml", "native-tun.yaml"):
            check = subprocess.run([str(mihomo), "-t", "-d", str(owned / "runtime"), "-f", str(configs / name)],
                                   cwd=owned, capture_output=True, text=True, timeout=15)
            report["checks"].append({"config": name, "exit_code": check.returncode, "output": check.stdout + check.stderr})
            if check.returncode:
                raise RuntimeError("native sample config check failed: " + name)
        # Invalid user input containing '%' must remain intact in diagnostics.
        bad_text = "proxies:\n  - name: bad\n    type: unsupported%protocol\n"
        bad_path = configs / "invalid.yaml"
        bad_path.write_text(bad_text, encoding="utf-8")
        for label, flags in (("invalid-file", ["-f", str(bad_path)]),
                             ("invalid-inline", ["-config", base64.b64encode(bad_text.encode()).decode()])):
            check = subprocess.run([str(mihomo), "-t", "-d", str(owned / "runtime")] + flags,
                                   cwd=owned, capture_output=True, text=True, timeout=15)
            output = check.stdout + check.stderr
            preserved = check.returncode == 1 and "unsupported%protocol" in output and "%!" not in output
            report["checks"].append({"config": label, "exit_code": check.returncode, "diagnostic_preserved": preserved, "output": output})
            if not preserved:
                raise RuntimeError("invalid config diagnostic was lost or treated as a format string")
        yaml = (configs / "native-proxy.yaml").read_text(encoding="utf-8")
        yaml = yaml.replace("mixed-port: 17890", "mixed-port: " + str(mixed[1]))
        yaml = yaml.replace("listen: 127.0.0.1:1053", "listen: " + text(dns))
        yaml = yaml.replace("  nameserver: [1.1.1.1, 8.8.8.8]", "  nameserver: [127.0.0.1:9]\n  use-hosts: false\n  use-system-hosts: false\n  fake-ip-filter-mode: whitelist\n  fake-ip-filter: [localhost]")
        yaml = yaml.replace("  proxy-server-nameserver: [1.1.1.1, 8.8.8.8]", "  proxy-server-nameserver: [127.0.0.1:9]")
        smoke = configs / "smoke.yaml"
        smoke.write_text(yaml, encoding="utf-8")
        def start(name, argv, address):
            log = open(owned / (name + ".log"), "wb")
            outputs.append(log)
            kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
            proc = subprocess.Popen(argv, cwd=owned, stdout=log, stderr=log, **kwargs)
            processes.append(proc)
            ready(proc, address)
        start("echo4", [str(bfp), "fixture", "-listen", text(target)], target)
        start("echo6", [str(bfp), "fixture", "-listen", "[::1]:" + str(target[1])], ("::1", target[1]))
        if mixed_classification:
            start("interactive", [str(bfp), "fixture", "-listen", text(interactive)], interactive)
        start("server", [str(bfp), "server", "-config", str(config_file), "-stats", "100ms"] + (["-class-stats"] if mixed_classification else []), server)
        start("mihomo", [str(mihomo), "-d", str(owned / "runtime"), "-f", str(smoke)], mixed)
        ready_runtime(processes[-1], owned / "mihomo.log")
        ready(processes[-1], dns)
        if mixed_classification:
            classification_mix(mixed, target, interactive, owned, report)
        targets = [("ipv4", "127.0.0.1"), ("ipv6", "::1"), ("domain", "localhost")]
        for network in ("udp", "tcp"):
            for typ in (1, 28):
                report["phase"] = "dns-" + network + "-" + str(typ)
                ip = dns_address(dns, network, typ)
                label = "dns-" + network + ("-A" if typ == 1 else "-AAAA")
                targets.append((label, str(ip)))
        for label, host in targets:
            payload = ("bfp-native-" + label).encode()
            report["phase"] = "tcp-" + label
            tcp_echo(mixed, host, target[1], payload)
            report["phase"] = "udp-" + label
            udp_echo(mixed, host, target[1], payload)
            report["checks"].append({"target": label, "host": host, "tcp": True, "udp": True})
        time.sleep(.15)
        server_events = []
        for line in (owned / "server.log").read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if value.get("event") == "stats":
                server_events.append(value)
        report["server_stats"] = server_events[-3:]
        report["native_session_observed"] = any(v.get("sessions") for v in server_events)
        if not report["native_session_observed"]:
            raise RuntimeError("no BFP Session observed at server")
        report["pass"] = True
        report["phase"] = "complete"
    except Exception as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        report["process_exit_codes_before_cleanup"] = [p.poll() for p in processes]
        for proc in reversed(processes):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
        for log in outputs:
            log.close()
        report["logs"] = {p.name: p.read_text(encoding="utf-8", errors="replace")[-12000:] for p in owned.glob("*.log")}
        if owned.parent != work_dir or not owned.name.startswith(".native-mihomo-"):
            raise RuntimeError("unsafe cleanup path")
        shutil.rmtree(owned)
        report["cleanup"] = {"processes_stopped": all(p.poll() is not None for p in processes), "directory_removed": not owned.exists()}
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bfp", required=True)
    parser.add_argument("--mihomo", required=True)
    parser.add_argument("--templates", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--classification-profile", choices=("standard", "low-bandwidth"), default="standard")
    parser.add_argument("--mixed-classification", action="store_true")
    args = parser.parse_args()
    if args.mixed_classification and args.classification_profile != "low-bandwidth":
        parser.error("--mixed-classification requires --classification-profile low-bandwidth")
    result = execute(args.bfp, args.mihomo, args.templates, args.work_dir, args.classification_profile, args.mixed_classification)
    pathlib.Path(args.result).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"pass": result["pass"], "checks": len(result["checks"]), "error": result.get("error"), "artifact": args.result}))
    raise SystemExit(0 if result["pass"] else 1)
