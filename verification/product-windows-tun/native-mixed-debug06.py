"""One small native proxy/DNS/UDP observation without host network changes."""
import concurrent.futures
import datetime
import ipaddress
import json
import pathlib
import socket
import struct
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
CLIENT = ROOT / "credentials-client-ready/tun-debug06"
RECORD = ROOT / "verification/product-windows-tun/native-mixed-debug06.json"
LOG = CLIENT / "mixed-launcher.out.log"
PS = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
      str(CLIENT / "deploy/windows-client.ps1")]
if RECORD.exists() or LOG.exists():
    raise RuntimeError("preserve previous evidence")


def control(action):
    value = subprocess.run(PS + ["-Action", action, "-Json"], capture_output=True, text=True, timeout=30)
    return value.returncode, json.loads(value.stdout)


def exact(conn, count):
    data = bytearray()
    while len(data) < count:
        block = conn.recv(count - len(data))
        if not block:
            raise EOFError("SOCKS ended")
        data.extend(block)
    return bytes(data)


def greeting():
    conn = socket.create_connection(("127.0.0.1", 17890), timeout=5)
    conn.settimeout(5)
    conn.sendall(b"\x05\x01\x00")
    if exact(conn, 2) != b"\x05\x00":
        conn.close()
        raise RuntimeError("SOCKS greeting rejected")
    return conn


def reply(conn):
    header = exact(conn, 4)
    size = {1: 4, 4: 16}.get(header[3])
    if size is None:
        raise RuntimeError("unexpected SOCKS address")
    ip = ipaddress.ip_address(exact(conn, size))
    port = struct.unpack("!H", exact(conn, 2))[0]
    return header[1], ip, port


def dns_message(query_type):
    question = b"\x03www\x0acloudflare\x03com\x00" + struct.pack("!HH", query_type, 1)
    return struct.pack("!HHHHHH", 0xBF06, 0x0100, 1, 0, 0, 0) + question


def fakeip(query_type):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(dns_message(query_type), ("127.0.0.1", 1053))
        data, _ = sock.recvfrom(4096)
    if data[:2] != b"\xbf\x06" or data[3] & 15 or struct.unpack("!H", data[6:8])[0] != 1:
        raise RuntimeError("fake-IP DNS response invalid")
    size = 4 if query_type == 1 else 16
    # This one-question/one-answer response ends with the address RDATA.
    if struct.unpack("!H", data[-size - 2:-size])[0] != size:
        raise RuntimeError("fake-IP DNS address size invalid")
    address = ipaddress.ip_address(data[-size:])
    network = ipaddress.ip_network("198.18.0.0/15" if query_type == 1 else "fd42:6266:7000::/96")
    if address not in network:
        raise RuntimeError("expected Session fake-IP")
    return address


def small_udp():
    with greeting() as conn:
        conn.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
        status, relay, port = reply(conn)
        if status or not port:
            raise RuntimeError("UDP association rejected")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            address = "127.0.0.1" if relay.is_unspecified else str(relay)
            payload = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + b"\x00\x35" + dns_message(1)
            sock.sendto(payload, (address, port))
            data, _ = sock.recvfrom(4096)
        if (len(data) < 22 or data[:4] != b"\x00\x00\x00\x01"
                or data[4:10] != socket.inet_aton("1.1.1.1") + b"\x00\x35"
                or data[10:12] != b"\xbf\x06" or not data[12] & 0x80
                or data[13] & 15 or struct.unpack("!H", data[16:18])[0] == 0):
            raise RuntimeError("UDP DNS reply invalid")
        return {"requests": 1, "sent_bytes": len(payload), "reply_bytes": len(data), "reply_verified": True}


def churn(index, addresses):
    try:
        with greeting() as conn:
            address = ipaddress.ip_address("127.0.0.1") if index % 3 == 0 else addresses[index % 2]
            conn.sendall(b"\x05\x01\x00" + bytes([1 if address.version == 4 else 4]) + address.packed + b"\x01\xbb")
            if index % 4 == 0:
                return "cancelled_open"
            status, _, _ = reply(conn)
            # Mihomo acknowledges SOCKS before its outbound OPEN completes.
            return "socks_refused" if status else "socks_replied_then_closed"
    except (OSError, EOFError):
        return "bounded_open_failed"


def https(address):
    resolved = str(address) if address.version == 4 else "[" + str(address) + "]"
    proc = subprocess.run(["curl.exe", "--noproxy", "", "--proxy", "socks5://127.0.0.1:17890",
                           "--resolve", "www.cloudflare.com:443:" + resolved, "--fail", "--silent",
                           "--show-error", "--max-time", "12", "https://www.cloudflare.com/cdn-cgi/trace"],
                          capture_output=True, timeout=15)
    exit_ip = next((line[3:] for line in proc.stdout.decode("utf-8", "replace").splitlines() if line.startswith("ip=")), None)
    return {"curl_exit_code": proc.returncode, "exit_ip": exit_ip,
            "response_bytes": len(proc.stdout), "family": address.version,
            "success": proc.returncode == 0 and exit_ip == "192.0.2.10"}


result = {"started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "native_version": "0.1.0-debug-tun06", "host_tun_started": False,
          "system_proxy_changed": False, "singapore_used": False,
          "scope": "Session fake-IP A/AAAA, one UDP DNS query, 24 small SOCKS setup/cancel observations, two HTTPS responses",
          "pass": False}
launcher = None
stdout = stderr = None
try:
    _, before = control("status")
    if before["running"] or before["port_listening"] or before["cleanup_pending"] or before["tun"]["needs_recovery"]:
        raise RuntimeError("diagnostic client must be fully stopped")
    stdout = LOG.open("x", encoding="utf-8")
    stderr = (CLIENT / "mixed-launcher.err.log").open("x", encoding="utf-8")
    launcher = subprocess.Popen(PS + ["-Action", "start", "-Mode", "proxy"], stdout=stdout, stderr=stderr)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        _, state = control("status")
        if state["proxy_owner_verified"] and state["pid"] == launcher.pid:
            break
        if launcher.poll() is not None:
            raise RuntimeError("owned launcher exited")
        time.sleep(0.2)
    else:
        raise RuntimeError("proxy readiness timed out")
    addresses = [fakeip(1), fakeip(28)]
    result["dns_fakeip_families_verified"] = [4, 6]
    result["https_ipv4_before"] = https(addresses[0])
    result["udp"] = small_udp()
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as workers:
        values = list(workers.map(lambda index: churn(index, addresses), range(24)))
    result["churn"] = {name: values.count(name) for name in sorted(set(values))}
    # Refresh a 30-second lease if slow preceding steps used its whole budget.
    result["https_ipv6_after"] = https(fakeip(28))
    actual_log = LOG.read_text(encoding="utf-8-sig")
    result["native_log_ready_verified"] = "Mihomo runtime ready" in actual_log
    result["termination_events_before_stop"] = [line.strip() for line in actual_log.splitlines()
                                               if "event=bfp_session_business_ended" in line]
    result["pass"] = (result["https_ipv4_before"]["success"] and result["https_ipv6_after"]["success"]
                      and result["udp"]["reply_verified"] and result["native_log_ready_verified"]
                      and not result["termination_events_before_stop"])
except Exception as error:
    result["error_type"] = type(error).__name__
    if isinstance(error, RuntimeError):
        result["error"] = str(error)
finally:
    if launcher is not None:
        try:
            code, stopped = control("stop")
            result["cleanup_complete"] = code == 0 and stopped.get("cleanup_complete") is True
            result["pass"] = result["pass"] and result["cleanup_complete"]
            launcher.wait(timeout=10)
            result["launcher_exited"] = True
        except Exception as error:
            result["cleanup_complete"] = False
            result["cleanup_error_type"] = type(error).__name__
            result["pass"] = False
    for stream in (stdout, stderr):
        if stream is not None:
            stream.close()
    try:
        code, result["final_status"] = control("status")
        state = result["final_status"]
        result["final_cleanup_verified"] = (code == 0 and state.get("state") == "stopped"
                                            and state.get("running") is False and state.get("port_listening") is False
                                            and state.get("supervisor_lock_held") is False
                                            and state.get("cleanup_pending") is False
                                            and state.get("tun", {}).get("needs_recovery") is False)
        result["pass"] = result["pass"] and result["final_cleanup_verified"]
    except Exception as error:
        result["final_cleanup_verified"] = False
        result["final_status_error_type"] = type(error).__name__
        result["pass"] = False
    try:
        result["termination_events_including_stop"] = [line.strip() for line in LOG.read_text(encoding="utf-8-sig").splitlines()
                                                       if "event=bfp_" in line] if LOG.exists() else None
    except Exception as error:
        result["log_error_type"] = type(error).__name__
        result["pass"] = False
    result["completed_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    RECORD.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result))
raise SystemExit(0 if result["pass"] else 1)
