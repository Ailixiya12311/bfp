"""WAN socket bridge for a run-owned, network-none TUN container.

Only encrypted carrier records cross this Unix socket. Host routes and
firewall rules are untouched; ip commands run in the verified container netns.
The bridge is a test fixture, not part of the BFP wire protocol or product.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import threading
import time


def execute(run_path, run_id, cfg):
    run_path = Path(run_path)
    control = run_path / "control"
    control.mkdir(mode=0o700)
    name = "bfp-race-" + run_id
    prefix = ["sudo", "-n"] if os.geteuid() else []
    pid = None
    stop = threading.Event()
    live_sockets = []
    sockets_lock = threading.Lock()
    counters = {"udp_sent": 0, "udp_received": 0, "udp_dropped": 0, "tcp_connections": 0}
    errors = []

    def command(argv, timeout=10):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError("fixture command failed: " + result.stderr[-1600:])
        return result.stdout

    def inspect_container():
        data = json.loads(command(["docker", "inspect", name]))[0]
        if data["Config"].get("Labels", {}).get("bfp.run") != run_id or data["HostConfig"]["NetworkMode"] != "none":
            raise RuntimeError("container ownership or network mode changed")
        for mount in data["Mounts"]:
            if mount["Type"] == "bind" and not Path(mount["Source"]).is_relative_to(run_path):
                raise RuntimeError("unexpected bind mount")
        active_pid = data["State"]["Pid"]
        if not data["State"]["Running"] or active_pid < 2 or (pid is not None and pid != active_pid):
            raise RuntimeError("container PID changed or stopped")
        # On SG the SSH user is ubuntu while Docker's process belongs to
        # root. Read the namespace identity with the already verified sudo
        # capability rather than weakening the private run directory.
        identity_source = "import os,sys;print(os.stat('/proc/'+sys.argv[1]+'/ns/net').st_ino)"
        inode = int(command(prefix + ["python3", "-c", identity_source, str(active_pid)]).strip())
        if inode == os.stat("/proc/self/ns/net").st_ino:
            raise RuntimeError("refusing host network namespace")
        return active_pid

    def ip(args):
        if not isinstance(args, list) or not args or len(args) > 32 or any(not isinstance(a, str) or len(a) > 100 for a in args):
            raise RuntimeError("invalid ip fixture arguments")
        if any(a in ("-b", "-batch", "-netns", "netns", "exec") for a in args):
            raise RuntimeError("ip namespace or batch escape refused")
        active_pid = inspect_container()
        r = subprocess.run(prefix + ["nsenter", "-t", str(active_pid), "-n", "ip"] + args,
                           capture_output=True, text=True, timeout=8)
        return {"exit_code": r.returncode, "stdout": r.stdout[:16000], "stderr": r.stderr[:1600]}

    def exact(conn, size):
        out = bytearray()
        while len(out) < size:
            part = conn.recv(size - len(out))
            if not part:
                raise EOFError()
            out.extend(part)
        return bytes(out)

    def register(conn):
        with sockets_lock:
            live_sockets.append(conn)
        return conn

    def handle(conn):
        upstream = None
        register(conn)
        conn.settimeout(10)
        try:
            kind = exact(conn, 1)
            if kind == b"I":
                request = bytearray()
                while len(request) < 4096:
                    b = exact(conn, 1)
                    if b == b"\n":
                        break
                    request.extend(b)
                else:
                    raise RuntimeError("ip request too long")
                reply = ip(json.loads(request))
                conn.sendall(json.dumps(reply).encode() + b"\n")
                return
            if kind not in (b"T", b"U"):
                raise RuntimeError("unknown bridge channel")
            endpoint = (cfg["server_host"], cfg["server_port"])
            if kind == b"T":
                upstream = register(socket.create_connection(endpoint, timeout=8))
                counters["tcp_connections"] += 1
            else:
                upstream = register(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                upstream.connect(endpoint)
            upstream.settimeout(8)
            while not stop.is_set():
                ready, _, _ = select.select([conn, upstream], [], [], .2)
                for source in ready:
                    if kind == b"T":
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is conn else conn).sendall(data)
                    elif source is conn:
                        size = struct.unpack("!H", exact(conn, 2))[0]
                        data = exact(conn, size)
                        if (control / "drop-udp").exists():
                            counters["udp_dropped"] += 1
                        else:
                            upstream.send(data)
                            counters["udp_sent"] += 1
                    else:
                        data = upstream.recv(65535)
                        if (control / "drop-udp").exists():
                            counters["udp_dropped"] += 1
                        else:
                            conn.sendall(struct.pack("!H", len(data)) + data)
                            counters["udp_received"] += 1
        except (EOFError, ConnectionError, socket.timeout):
            pass
        except Exception as exc:
            if not stop.is_set():
                errors.append(type(exc).__name__ + ": " + str(exc))
        finally:
            conn.close()
            if upstream is not None:
                upstream.close()

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(control / "bridge.sock"))
    os.chmod(control / "bridge.sock", 0o600)
    listener.listen(32)
    listener.settimeout(.2)

    def accept():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                pass
            except OSError:
                return

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    report = {"pass": False, "scope": "automatic TUN routes in a network-none container; Unix fixture carries encrypted UDP/TCP over the real WAN"}
    try:
        argv = ["docker", "run", "-d", "--pull=never", "--network", "none", "--name", name,
                "--label", "bfp.run=" + run_id, "--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
                "--cap-add", "NET_RAW", "--cap-add", "SETUID", "--cap-add", "SETGID",
                "--cap-add", "DAC_OVERRIDE",
                "--security-opt", "no-new-privileges", "--read-only", "--pids-limit", "96",
                "--memory", "384m", "--cpus", "0.75", "--tmpfs", "/tmp:rw,exec,nosuid,size=96m",
                "--device", "/dev/net/tun:/dev/net/tun:rwm",
                "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
                "--sysctl", "net.ipv6.conf.default.disable_ipv6=0",
                "-v", str(run_path) + ":/bfp:ro", "-v", str(control) + ":/control:rw",
                cfg["image"], "python3", "/bfp/wan_tun_container.py"]
        report["container_id"] = command(argv).strip()
        pid = inspect_container()
        for args in (["link", "add", "bfp-uplink", "type", "dummy"],
                     ["addr", "add", "192.0.2.2/24", "dev", "bfp-uplink"],
                     ["-6", "addr", "add", "fd7e:bf00::1/64", "dev", "bfp-uplink", "nodad"],
                     ["link", "set", "bfp-uplink", "up"],
                     ["route", "add", "default", "via", "192.0.2.1", "dev", "bfp-uplink"],
                     ["-6", "route", "add", "default", "via", "fd7e:bf00::2", "dev", "bfp-uplink"]):
            result = ip(args)
            if result["exit_code"]:
                raise RuntimeError("owned netns setup failed: " + result["stderr"])
        (control / "network-ready").write_text("ready")
        deadline = time.monotonic() + 85
        while time.monotonic() < deadline:
            result_path = control / "result.json"
            if result_path.is_file():
                report["business"] = json.loads(result_path.read_text())
                report["pass"] = report["business"].get("pass") is True
                break
            data = json.loads(command(["docker", "inspect", name]))[0]
            if not data["State"]["Running"]:
                raise RuntimeError("TUN container stopped without result")
            time.sleep(.25)
        else:
            raise RuntimeError("bounded TUN scenario timeout")
        report["bridge_counters"] = dict(counters)
        report["bridge_errors"] = errors[:10]
        udp_evidence = counters["udp_dropped"] > 0 if cfg["scenario"] == "initial_udp_blocked" else counters["udp_sent"] > 0
        report["pass"] = bool(report["pass"] and not errors and udp_evidence and
                              (cfg["scenario"] == "normal_udp" or counters["tcp_connections"] > 0))
    except Exception as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        stop.set()
        listener.close()
        with sockets_lock:
            for conn in live_sockets:
                try:
                    conn.close()
                except OSError:
                    pass
        thread.join(timeout=1)
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True, timeout=8)
        report["container_log"] = (logs.stdout + logs.stderr)[-6000:]
        inspect = subprocess.run(["docker", "inspect", name], capture_output=True, text=True, timeout=5)
        if inspect.returncode == 0:
            data = json.loads(inspect.stdout)[0]
            if data["Config"].get("Labels", {}).get("bfp.run") != run_id:
                raise RuntimeError("owned container cleanup refused")
            removed = subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, timeout=12)
            report["container_removed"] = removed.returncode == 0
        else:
            report["container_removed"] = True
        report["pass"] = bool(report["pass"] and report["container_removed"])
    return report
