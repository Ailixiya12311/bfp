"""Native packaged proxy and TUN checks, confined to an owned netns."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/bfp")
import runtime_smoke as mixed
import tun_harness as harness

ROOT = pathlib.Path("/tmp/bfp-product")
EVIDENCE = pathlib.Path("/evidence")
UID = 20001


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise RuntimeError("command failed: " + " ".join(argv) + ": " + result.stderr[-2048:])
    return result.stdout


def json_command(argv):
    return json.loads(command(argv))


def stats():
    values = []
    for line in (ROOT / "server.log").read_text(errors="replace").splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("event") == "stats":
            values.append(obj)
    return values[-1].get("sessions", []) if values else []


def fixture_events():
    path = EVIDENCE / "echo.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def probe_argv(mode, host):
    # Read the root-only bind input into memory before dropping privileges.
    launch = 'import os; code=compile(open("/bfp/tun_probe.py","rb").read(),"/bfp/tun_probe.py","exec"); os.setgroups([]); os.setgid(20001); os.setuid(20001); exec(code,{"__name__":"__main__"})'
    return ["python3", "-c", launch, json.dumps({"mode": mode, "host": host, "port": 18080})]


def probe(mode, host, expected=True):
    result = subprocess.run(probe_argv(mode, host), capture_output=True, text=True, timeout=12)
    try:
        data = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise RuntimeError("probe did not produce JSON: " + result.stderr[-2048:])
    data["exit_code"] = result.returncode
    if expected and (not data.get("pass") or data.get("uid") != UID or result.returncode):
        raise RuntimeError("ordinary TUN probe failed: " + json.dumps(data))
    return data


def run():
    ROOT.mkdir(mode=0o700)
    processes, outputs = [], []
    report = {"pass": False, "scope": "packaged Linux native proxy and owned TUN; no WAN or host routing changes", "tun_rows": []}
    capture_processes = []
    try:
        report["preflight"] = {"capabilities": harness.cap_status(), "commands": {x: shutil.which(x) for x in ("ip", "ss", "tcpdump", "iptables")},
                               "netns": os.stat("/proc/self/ns/net").st_ino}
        report["preflight"]["same_namespace_backend_sysctls"] = {name: pathlib.Path("/proc/sys/net/ipv4/conf/" + name).read_text().strip()
                                                                 for name in ("all/accept_local", "default/accept_local", "all/rp_filter", "default/rp_filter")}
        if not all(report["preflight"]["commands"].values()):
            raise RuntimeError("missing required TUN/capture/fault tool")
        if not all(report["preflight"]["capabilities"].get(x) for x in ("cap_net_admin", "cap_net_raw")):
            raise RuntimeError("missing required container capability")
        # Mihomo's system IPv6 check requires a non-loopback IPv6 unicast
        # address. Configure the real owned backend before parsing its config.
        command(["ip", "addr", "add", "192.0.2.10/32", "dev", "lo"])
        command(["ip", "-6", "addr", "add", "fd77:25::10/128", "dev", "lo", "nodad"])
        report["backend_addresses"] = json_command(["ip", "-j", "addr", "show", "dev", "lo"])
        report["mixed"] = mixed.execute("/bfp/bfp", "/bfp/mihomo", "/bfp/configs", ROOT)
        if not report["mixed"]["pass"]:
            raise RuntimeError("packaged Linux native mixed check failed")
        command(["/bfp/bfp", "keygen", "-out", str(ROOT / "credentials"), "-server-listen", "127.0.0.1:51880",
                 "-server", "127.0.0.1:51880", "-tcp-server", "127.0.0.1:51880"])
        path = ROOT / "credentials/server.json"
        cfg = json.loads(path.read_text())
        cfg["policy"].update(AllowPrivate=True, AllowedCIDRs=["192.0.2.10/32", "fd77:25::10/128"], AllowedPorts=[18080])
        path.write_text(json.dumps(cfg))
        yaml = pathlib.Path("/bfp/configs/native-tun.yaml").read_text()
        yaml = yaml.replace("./credentials/client.json", str(ROOT / "credentials/client.json"))
        yaml = yaml.replace("listen: 127.0.0.1:1053", "listen: 127.0.0.1:1054")
        yaml = yaml.replace("  nameserver: [1.1.1.1, 8.8.8.8]", "  nameserver: [127.0.0.1:15353]\n  use-hosts: false\n  use-system-hosts: false\n  fake-ip-filter-mode: whitelist\n  fake-ip-filter: [bfp-v4.test, bfp-v6.test]")
        yaml = yaml.replace("  proxy-server-nameserver: [1.1.1.1, 8.8.8.8]", "  proxy-server-nameserver: [127.0.0.1:15353]")
        yaml = yaml.replace("  auto-route: true", "  auto-route: false")
        yaml = yaml.replace("  auto-detect-interface: true", "  auto-detect-interface: false")
        (ROOT / "tun.yaml").write_text(yaml)
        # Exercise the exact packaged launcher, including its instance lock
        # and signal supervision, instead of launching Mihomo directly.
        product = ROOT / "native-package"
        for directory in ("bin", "configs", "credentials"):
            (product / directory).mkdir(parents=True, mode=0o700)
        (product / "bin/mihomo-bfp-linux-amd64").symlink_to("/bfp/mihomo")
        (product / "bin/bfp-linux-amd64").symlink_to("/bfp/bfp")
        shutil.copyfile("/bfp/start-native.sh", product / "start-native.sh")
        shutil.copyfile(ROOT / "credentials/client.json", product / "credentials/client.json")
        os.chmod(product / "credentials/client.json", 0o600)
        (product / "configs/native-tun.yaml").write_text(yaml)
        marker = product / "runtime/bfp-tun-supervisor.env"
        generated = product / "runtime/native-tun.generated.yaml"
        launcher = ["sh", str(product / "start-native.sh"), "tun"]
        report["launcher"] = {"packaged_script_sha256": hashlib.sha256(pathlib.Path("/bfp/start-native.sh").read_bytes()).hexdigest()}
        def current_device():
            record = marker.read_text()
            match = re.search(r"^device=(bfp-tun-[0-9a-f]{7,8})$", record, re.M)
            if not match:
                raise RuntimeError("invalid launcher device record")
            return match.group(1)
        def start(name, argv, address=None):
            output = open(ROOT / (name + ".log"), "wb")
            outputs.append(output)
            proc = subprocess.Popen(argv, cwd=ROOT, stdout=output, stderr=output)
            processes.append(proc)
            if address:
                mixed.ready(proc, address)
            return proc
        start("echo", ["python3", "/bfp/tun_harness.py", "echo", "--ipv4", "192.0.2.10", "--ipv6", "fd77:25::10", "--port", "18080", "--log", str(EVIDENCE / "echo.jsonl")], ("192.0.2.10", 18080))
        start("dns", ["python3", "/bfp/tun_harness.py", "dns", "--host", "127.0.0.1", "--port", "15353", "--log", str(EVIDENCE / "dns.jsonl")], ("127.0.0.1", 15353))
        start("server", ["/bfp/bfp", "server", "-config", str(path), "-stats", "100ms"], ("127.0.0.1", 51880))
        native = start("mihomo", launcher, ("127.0.0.1", 17890))
        mixed.ready_runtime(native, ROOT / "mihomo.log")
        mixed.ready(native, ("127.0.0.1", 1054))
        device = current_device()
        report["launcher"]["device_name"] = device
        report["launcher"]["device_name_fits_linux"] = len(device.encode()) <= 15
        if not report["launcher"]["device_name_fits_linux"]:
            raise RuntimeError("launcher device exceeds Linux IFNAMSIZ")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if any(v.get("ifname") == device for v in json_command(["ip", "-j", "link", "show"])):
                break
            time.sleep(.05)
        else:
            raise RuntimeError("TUN interface absent")
        marker_before = marker.read_bytes()
        generated_before = generated.read_bytes()
        duplicate = subprocess.run(launcher, capture_output=True, text=True, timeout=5)
        report["launcher"]["single_instance"] = {
            "exit_code": duplicate.returncode,
            "message": duplicate.stderr.strip(),
            "marker_unchanged": marker.read_bytes() == marker_before,
            "config_unchanged": generated.read_bytes() == generated_before,
            "original_device_alive": any(v.get("ifname") == device for v in json_command(["ip", "-j", "link", "show"])),
        }
        duplicate_gate = report["launcher"]["single_instance"]
        if duplicate_gate["exit_code"] != 3 or not all(duplicate_gate[k] for k in ("marker_unchanged", "config_unchanged", "original_device_alive")):
            raise RuntimeError("duplicate launcher damaged the active instance")
        command(["ip", "-6", "addr", "add", "fd7e:bf00::1/126", "dev", device, "nodad"])
        for family in ("-4", "-6"):
            command(["ip", family, "rule", "del", "pref", "0"])
            command(["ip", family, "rule", "add", "pref", "100", "lookup", "local"])
            command(["ip", family, "route", "add", "table", "2999", "default", "dev", device])
            command(["ip", family, "rule", "add", "pref", "1", "uidrange", "20001-20001", "lookup", "2999"])
            command(["ip", family, "rule", "add", "pref", "2", "uidrange", "20001-20001", "unreachable"])
        for name, interface in (("tun", device), ("lo", "lo")):
            # Evidence is root-only; Debian tcpdump otherwise drops to its
            # service UID before opening the output under this private mount.
            argv = ["tcpdump", "-Z", "root", "-i", interface, "-n", "-U", "-w", str(EVIDENCE / (name + ".pcap"))]
            argv += ["tcp or udp" if name == "tun" else "port 51880 or port 18080"]
            capture_processes.append(start("capture-" + name, argv))
        time.sleep(.25)
        if any(p.poll() is not None for p in capture_processes):
            raise RuntimeError("packet capture failed to start")
        fake4 = str(mixed.dns_address(("127.0.0.1", 1054), "udp", 1, "bfp-v4.test"))
        fake6 = str(mixed.dns_address(("127.0.0.1", 1054), "tcp", 28, "bfp-v6.test"))
        targets = [("numeric4", "192.0.2.10", "192.0.2.10"), ("numeric6", "fd77:25::10", "fd77:25::10"),
                   ("fakeA", fake4, "192.0.2.10"), ("fakeAAAA", fake6, "fd77:25::10")]
        for label, host, backend in targets:
            family = "-6" if ":" in host else "-4"
            route = json_command(["ip", family, "-j", "route", "get", host, "uid", str(UID)])
            if not route or route[0].get("dev") != device:
                raise RuntimeError("probe route bypassed TUN")
            for network in ("tcp", "udp"):
                report["phase"] = label + "-" + network
                result = probe(network, host)
                report["tun_rows"].append({"target": label, "address": host, "backend": backend, "network": network, "route": route, "probe": result})
        time.sleep(.15)
        # A held kernel TCP connection must survive the native UDP->TCP switch.
        held = subprocess.Popen(probe_argv("held-tcp", "192.0.2.10"), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        processes.append(held)
        first = json.loads(held.stdout.readline())
        if first.get("stage") != "before" or not first.get("pass"):
            raise RuntimeError("held connection did not establish")
        time.sleep(.15)
        before = stats()
        opens_before = sum(v.get("event") == "tcp_open" for v in fixture_events())
        for option in ("--dport", "--sport"):
            command(["iptables", "-I", "OUTPUT", "-p", "udp", option, "51880", "-j", "DROP"])
        stdout, stderr = held.communicate("continue\n", timeout=12)
        after_probe = json.loads(stdout.strip().splitlines()[-1])
        time.sleep(.2)
        after = stats()
        opens_after = sum(v.get("event") == "tcp_open" for v in fixture_events())
        same_session = bool(len(before) == 1 and any(v.get("session_id") == before[0].get("session_id") and v.get("carrier") == "tcp" and v.get("generation", 0) > before[0].get("generation", 0) for v in after))
        report["live_fallback"] = {"before": before, "after": after, "probe_before": first, "probe_after": after_probe,
                                   "backend_tcp_opens_before": opens_before, "backend_tcp_opens_after": opens_after,
                                   "pass": held.returncode == 0 and after_probe.get("pass") is True and same_session and opens_before == opens_after}
        if not report["live_fallback"]["pass"]:
            raise RuntimeError("native live fallback did not preserve session and target")
        report["post_fallback_udp"] = probe("udp", fake4)
        # Fresh native process, with UDP still blackholed, exercises initial fallback.
        native.terminate()
        native.wait(timeout=9)
        report["launcher"]["first_sigterm_cleanup"] = {
            "exit_code": native.returncode,
            "device_removed": not any(v.get("ifname") == device for v in json_command(["ip", "-j", "link", "show"])),
            "marker_removed": not marker.exists(),
            "generated_config_removed": not generated.exists(),
        }
        if native.returncode != 143 or not all(report["launcher"]["first_sigterm_cleanup"][k] for k in ("device_removed", "marker_removed", "generated_config_removed")):
            raise RuntimeError("launcher signal cleanup failed")
        for family in ("-4", "-6"):
            # The TUN device disappearing also removed its table routes.
            command(["ip", family, "rule", "del", "pref", "1"])
            command(["ip", family, "rule", "del", "pref", "2"])
        initial_ids = {v["session_id"] for v in stats()}
        # A marker left by an interrupted old run must be recovered only
        # after acquiring the lock. This dummy is created in this netns.
        command(["ip", "link", "add", "bfp-tun-deadbee", "type", "dummy"])
        marker.write_text("version=1\nmode=tun\ndevice=bfp-tun-deadbee\n")
        native = start("mihomo-initial", launcher, ("127.0.0.1", 17890))
        mixed.ready_runtime(native, ROOT / "mihomo-initial.log")
        mixed.ready(native, ("127.0.0.1", 1054))
        device = current_device()
        report["launcher"]["stale_device_recovered"] = not any(v.get("ifname") == "bfp-tun-deadbee" for v in json_command(["ip", "-j", "link", "show"]))
        if not report["launcher"]["stale_device_recovered"]:
            raise RuntimeError("stale owned device was not recovered")
        time.sleep(.1)
        command(["ip", "-6", "addr", "add", "fd7e:bf00::1/126", "dev", device, "nodad"])
        for family in ("-4", "-6"):
            command(["ip", family, "route", "add", "table", "2999", "default", "dev", device])
            command(["ip", family, "rule", "add", "pref", "1", "uidrange", "20001-20001", "lookup", "2999"])
            command(["ip", family, "rule", "add", "pref", "2", "uidrange", "20001-20001", "unreachable"])
        initial_tcp = probe("tcp", "192.0.2.10")
        initial_udp = probe("udp", "fd77:25::10")
        time.sleep(.2)
        report["initial_fallback"] = {"tcp": initial_tcp, "udp": initial_udp, "sessions": stats()}
        report["initial_fallback"]["pass"] = any(v.get("session_id") not in initial_ids and v.get("carrier") == "tcp" for v in report["initial_fallback"]["sessions"])
        if not report["initial_fallback"]["pass"]:
            raise RuntimeError("initial UDP block did not use TCP")
        opens_before = len(fixture_events())
        session_opens_before = sum(v.get("opened", 0) for v in stats())
        unknown = probe("tcp", "198.18.0.250", expected=False)
        time.sleep(.1)
        session_opens_after = sum(v.get("opened", 0) for v in stats())
        report["unknown_fake"] = {"probe": unknown, "session_opens_before": session_opens_before, "session_opens_after": session_opens_after,
                                  "pass": unknown.get("pass") is False and len(fixture_events()) == opens_before and session_opens_before == session_opens_after}
        if not report["unknown_fake"]["pass"]:
            raise RuntimeError("unknown fake-IP reached backend")
        # Remove only the owned UID table route; unreachable fallback forbids bypass.
        command(["ip", "-4", "route", "del", "table", "2999", "default"])
        removed = probe("tcp", "192.0.2.10", expected=False)
        report["route_removed"] = {"probe": removed, "pass": removed.get("pass") is False and len(fixture_events()) == opens_before}
        if not report["route_removed"]["pass"]:
            raise RuntimeError("removed TUN route leaked to backend")
        native.terminate()
        native.wait(timeout=9)
        report["graceful_tun_removed"] = not any(v.get("ifname") == device for v in json_command(["ip", "-j", "link", "show"]))
        report["launcher"]["final_marker_removed"] = not marker.exists() and not generated.exists()
        report["rules"] = {f: json_command(["ip", f, "-j", "rule", "show"]) for f in ("-4", "-6")}
        report["pass"] = report["graceful_tun_removed"] and report["launcher"]["final_marker_removed"]
        # Mihomo can emit runtime-ready even when no TUN exists. A TUN
        # launcher must fail instead of presenting that as a usable TUN.
        disabled = yaml.replace("tun:\n  enable: true", "tun:\n  enable: false")
        if disabled == yaml:
            raise RuntimeError("negative TUN config did not change")
        (product / "configs/native-tun.yaml").write_text(disabled)
        failed = subprocess.run(launcher, capture_output=True, text=True, timeout=20)
        still_listening = False
        try:
            with socket.create_connection(("127.0.0.1", 17890), timeout=.25):
                still_listening = True
        except OSError:
            pass
        report["launcher"]["missing_tun_refused"] = {
            "exit_code": failed.returncode,
            "mihomo_runtime_ready": "Mihomo runtime ready" in failed.stdout,
            "launcher_reported_failure": "TUN interface failed to start" in failed.stderr,
            "mixed_port_closed": not still_listening,
            "marker_removed": not marker.exists(),
            "generated_config_removed": not generated.exists(),
        }
        missing_gate = report["launcher"]["missing_tun_refused"]
        report["pass"] = bool(report["pass"] and missing_gate["exit_code"] == 1 and all(missing_gate[k] for k in ("mihomo_runtime_ready", "launcher_reported_failure", "mixed_port_closed", "marker_removed", "generated_config_removed")))
    except Exception as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        for proc in reversed(processes):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
        for output in outputs:
            output.close()
        report["processes_stopped"] = all(p.poll() is not None for p in processes)
        report["logs"] = {p.name: p.read_text(errors="replace")[-18000:] for p in ROOT.glob("*.log")}
        report["fixture_events"] = fixture_events()
        report["captures"] = {}
        for name in ("tun", "lo"):
            try:
                packets = list(harness.pcap_packets(str(EVIDENCE / (name + ".pcap"))))
                counts = Counter((p["protocol"], p["src"], p["dst"], p["sport"], p["dport"]) for p in packets)
                report["captures"][name] = {"available": True, "packets": len(packets), "flows": [{"network": k[0], "src": k[1], "dst": k[2], "sport": k[3], "dport": k[4], "packets": n} for k, n in counts.items()]}
            except Exception as exc:
                report["captures"][name] = {"available": False, "error": str(exc)}
        for row in report["tun_rows"]:
            def contains(name, destination):
                return any(v["dst"] == destination and v["dport"] == 18080 and v["network"] == row["network"] for v in report["captures"].get(name, {}).get("flows", []))
            row["tun_packet_observed"] = contains("tun", row["address"])
            row["backend_packet_observed"] = contains("lo", row["backend"])
        report["carrier_reentry_absent"] = report["captures"].get("tun", {}).get("available") is True and not any(v["dport"] == 51880 or v["sport"] == 51880 for v in report["captures"]["tun"]["flows"])
        report["pass"] = bool(report["pass"] and len(report["tun_rows"]) == 8 and all(v["tun_packet_observed"] and v["backend_packet_observed"] for v in report["tun_rows"]) and report["carrier_reentry_absent"])
        for path in EVIDENCE.iterdir():
            if path.is_file():
                os.chmod(path, 0o600)
        (EVIDENCE / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
        os.chmod(EVIDENCE / "result.json", 0o600)
    print(json.dumps({"pass": report["pass"], "error": report.get("error"), "tun_rows": len(report["tun_rows"])}), flush=True)


if __name__ == "__main__":
    run()
