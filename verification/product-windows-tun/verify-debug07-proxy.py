"""Check one frozen diagnostic binary's proxy and instance logs; no host takeover."""
import datetime
import hashlib
import json
import pathlib
import re
import socket
import struct
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
CLIENT = ROOT / "credentials-client-ready/tun-debug07"
RECORD = ROOT / "verification/product-windows-tun/proxy-debug07-real.json"
LOG = CLIENT / "proxy-observation.out.log"
PS = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
      str(CLIENT / "deploy/windows-client.ps1")]
if RECORD.exists() or LOG.exists():
    raise RuntimeError("preserve existing observation")


def control(action):
    value = subprocess.run(PS + ["-Action", action, "-Json"], capture_output=True, text=True,
                           timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
    return value.returncode, json.loads(value.stdout)


def events():
    # Keep only the fixed diagnostic message, not target-bearing runtime lines.
    values = []
    for line in LOG.read_text(encoding="utf-8-sig").splitlines():
        match = re.search(r"(event=bfp_[a-z_]+ outbound=\d+ owner=\d+[^\"]*)", line)
        if match:
            values.append(match.group(1))
    return values


result = {"started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "native_version": "0.1.0-debug-tun07", "host_tun_started": False,
          "system_proxy_changed": False, "singapore_used": False,
          "scope": "one local fake-IP DNS query, one HTTPS response, fixed instance logs and normal stop",
          "pass": False}
launcher = None
stdout = stderr = None
try:
    _, state = control("status")
    if state["running"] or state["port_listening"] or state["cleanup_pending"] or state["tun"]["needs_recovery"]:
        raise RuntimeError("diagnostic client must be fully stopped")
    binary = CLIENT / "client/bin/mihomo-bfp-windows-amd64.exe"
    result["native_binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    version = subprocess.run([str(binary), "-v"], capture_output=True, text=True, timeout=10,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    result["native_binary_version_output"] = version.stdout.strip()
    result["native_binary_version_verified"] = version.returncode == 0 and "v1.19.32-bfp-0.1.0-debug-tun07" in version.stdout
    stdout = LOG.open("x", encoding="utf-8")
    stderr = (CLIENT / "proxy-observation.err.log").open("x", encoding="utf-8")
    launcher = subprocess.Popen(PS + ["-Action", "start", "-Mode", "proxy"], stdout=stdout, stderr=stderr,
                                creationflags=subprocess.CREATE_NO_WINDOW)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        _, state = control("status")
        if state["proxy_owner_verified"] and state["pid"] == launcher.pid and state["mode"] == "proxy":
            break
        if launcher.poll() is not None:
            raise RuntimeError("owned launcher exited")
        time.sleep(0.2)
    else:
        raise RuntimeError("proxy readiness timed out")
    # DNS alone must register the Session watcher before a TCP request does.
    question = b"\x03www\x0acloudflare\x03com\x00" + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", 0xBF07, 0x0100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(query, ("127.0.0.1", 1053))
        response, source = sock.recvfrom(4096)
    result["dns_reply_verified"] = (source == ("127.0.0.1", 1053) and len(response) >= 12
                                    and response[:2] == b"\xbf\x07" and response[2] & 0x80 != 0
                                    and response[3] & 15 == 0 and struct.unpack("!H", response[6:8])[0] == 1)
    dns_events = events()
    result["dns_only_owner_registered"] = any("event=bfp_session_started" in value for value in dns_events)
    code, result["https"] = control("check")
    before_stop = events()
    result["instance_events_before_stop"] = before_stop
    result["termination_before_stop"] = any("event=bfp_session_business_ended" in value for value in before_stop)
    result["pass"] = (code == 0 and result["https"].get("success") is True
                      and result["https"].get("exit_ip") == "192.0.2.10"
                      and result["dns_reply_verified"] and result["dns_only_owner_registered"]
                      and result["native_binary_version_verified"] and not result["termination_before_stop"])
except Exception as error:
    result["error_type"] = type(error).__name__
    if isinstance(error, RuntimeError):
        result["error"] = str(error)
finally:
    if launcher is not None:
        try:
            code, stopped = control("stop")
            result["cleanup_complete"] = code == 0 and stopped.get("cleanup_complete") is True
            launcher.wait(timeout=10)
            result["launcher_exited"] = True
        except Exception as error:
            result["cleanup_complete"] = False
            result["cleanup_error_type"] = type(error).__name__
    for stream in (stdout, stderr):
        if stream is not None:
            stream.close()
    try:
        code, state = control("status")
        result["final_status"] = state
        result["final_cleanup_verified"] = (code == 0 and state.get("state") == "stopped"
                                            and state.get("running") is False and state.get("port_listening") is False
                                            and state.get("supervisor_lock_held") is False
                                            and state.get("cleanup_pending") is False
                                            and state.get("tun", {}).get("needs_recovery") is False)
        result["instance_events_including_stop"] = events() if LOG.exists() else []
    except Exception as error:
        result["final_cleanup_verified"] = False
        result["final_status_error_type"] = type(error).__name__
    result["pass"] = result["pass"] and result.get("cleanup_complete") is True and result.get("final_cleanup_verified") is True
    result["completed_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    RECORD.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"pass": result["pass"], "cleanup": result.get("final_cleanup_verified"),
                  "instance_events_verified": result.get("dns_only_owner_registered"), "evidence": str(RECORD)}))
