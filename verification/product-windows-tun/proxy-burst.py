"""One bounded proxy OPEN/cancel burst; no TUN or system proxy changes."""
import argparse
import concurrent.futures
import datetime
import json
import pathlib
import socket
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--client", required=True)
parser.add_argument("--result", required=True)
args = parser.parse_args()
client = pathlib.Path(args.client).resolve()
result_path = ROOT / "verification/product-windows-tun" / args.result
if client.parent != (ROOT / "credentials-client-ready").resolve() or result_path.exists():
    raise RuntimeError("unexpected client or existing result")
if result_path.parent != ROOT / "verification/product-windows-tun" or result_path.suffix != ".json":
    raise RuntimeError("unexpected result path")
wrapper = client / "deploy/windows-client.ps1"
ps = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(wrapper)]


def control(action):
    proc = subprocess.run(ps + ["-Action", action, "-Json"], capture_output=True, text=True, timeout=35)
    return proc.returncode, json.loads(proc.stdout)


def read_exact(conn, count):
    data = bytearray()
    while len(data) < count:
        part = conn.recv(count - len(data))
        if not part:
            raise EOFError("SOCKS reply ended")
        data.extend(part)
    return bytes(data)


def open_and_close(index):
    try:
        with socket.create_connection(("127.0.0.1", 17890), timeout=4) as conn:
            conn.settimeout(4)
            conn.sendall(b"\x05\x01\x00")
            if read_exact(conn, 2) != b"\x05\x00":
                return "greeting_rejected"
            host = b"www.cloudflare.com"
            conn.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + b"\x01\xbb")
            if index % 3 == 0:
                return "client_cancelled_open"
            reply = read_exact(conn, 4)
            if reply[:3] != b"\x05\x00\x00":
                return "target_or_admission_refused"
            size = {1: 4, 4: 16}.get(reply[3])
            if reply[3] == 3:
                size = read_exact(conn, 1)[0]
            if size is None:
                return "invalid_socks_reply"
            read_exact(conn, size + 2)
            time.sleep(0.15)
            return "opened_then_closed"
    except (OSError, EOFError):
        return "bounded_open_failed"


result = {"started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "scope": "48 concurrent SOCKS OPENs with early cancel, then HTTPS; one burst only",
          "host_tun_started": False, "system_proxy_changed": False, "new_remote_deployment": False,
          "pass": False}
launcher = None
log_path = client / "burst-launcher.out.log"


def termination_events():
    if not log_path.exists():
        raise RuntimeError("diagnostic stdout was not retained")
    return [line.strip() for line in log_path.read_text(encoding="utf-8-sig").splitlines()
            if "event=bfp_session_business_ended" in line]


try:
    _, before = control("status")
    if before["running"] or before["port_listening"] or before["cleanup_pending"] or before["tun"]["needs_recovery"]:
        raise RuntimeError("client must be stopped and recovered")
    stdout = open(client / "burst-launcher.out.log", "w", encoding="utf-8")
    stderr = open(client / "burst-launcher.err.log", "w", encoding="utf-8")
    launcher = subprocess.Popen(ps + ["-Action", "start", "-Mode", "proxy"], stdout=stdout, stderr=stderr)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        _, status = control("status")
        if status["proxy_owner_verified"] and status["pid"] == launcher.pid:
            break
        if launcher.poll() is not None:
            raise RuntimeError("owned launcher exited")
        time.sleep(0.2)
    else:
        raise RuntimeError("owned proxy did not become ready")
    code, initial = control("check")
    result["https_before"] = initial
    if code or initial.get("exit_ip") != "192.0.2.10" or not initial.get("success"):
        raise RuntimeError("initial HTTPS failed")
    with concurrent.futures.ThreadPoolExecutor(max_workers=48) as executor:
        outcomes = list(executor.map(open_and_close, range(48)))
    result["burst"] = {name: outcomes.count(name) for name in sorted(set(outcomes))}
    code, after = control("check")
    result["https_after"] = after
    result["pass"] = code == 0 and after.get("success") is True and after.get("exit_ip") == "192.0.2.10"
    result["unexpected_termination_events"] = termination_events()
    result["pass"] = result["pass"] and not result["unexpected_termination_events"]
except Exception as error:
    result["error_type"] = type(error).__name__
    if isinstance(error, RuntimeError):
        result["error"] = str(error)
finally:
    if launcher is not None:
        stop_code, stopped = control("stop")
        result["cleanup_complete"] = stop_code == 0 and stopped.get("cleanup_complete") is True
        result["pass"] = result["pass"] and result["cleanup_complete"]
        launcher.wait(timeout=10)
        stdout.close()
        stderr.close()
    _, result["final_status"] = control("status")
    result["termination_events_including_stop"] = termination_events() if log_path.exists() else None
    result["completed_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
print(json.dumps(result, ensure_ascii=False))
raise SystemExit(0 if result["pass"] else 1)
