"""Run the packaged native Mihomo BFP outbound over the two-host WAN matrix.

The root BFP WAN harness exercises ``bfp probe`` directly.  This harness keeps
the same run-owned topology but puts Mihomo and its BFP outbound on the
Singapore sender.  A held SOCKS TCP connection and one SOCKS UDP association
are used per proxy-mode scenario so a carrier handover must preserve both
logical flows. TUN mode uses ordinary kernel sockets, automatic routes and
DNS hijack in a run-owned network-none container. A private Unix fixture
passes the encrypted carriers to host WAN sockets without host route changes.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import pathlib
import re
import socket
import struct
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lab"))
from remote import (
    Remote,
    RemoteRun,
    LabError,
    SANITIZER,
    WORKSPACE,
    load_hosts,
    new_run_id,
    write_public,
    compare_snapshots,
)
from wan import credentials, free_port, random_probe, target_opens


def wait_native(run: RemoteRun, mixed_port: int, timeout: float = 20.0):
    """Wait for Mihomo's structured readiness log and mixed SOCKS port."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = run.remote.python(
            run._check()
            + "import pathlib,socket\n"
            + "log=(p/'mihomo.log').read_text(errors='replace') if (p/'mihomo.log').exists() else ''\n"
            + "ready='Mihomo runtime ready' in log\n"
            + "open=False\n"
            + "try:\n"
            + " s=socket.create_connection(('127.0.0.1',%d),.2); s.close(); open=True\n" % mixed_port
            + "except OSError: pass\n"
            + "print(json.dumps({'ready':ready,'open':open}))\n"
        )
        if state.get("ready") and state.get("open"):
            return state
        time.sleep(0.25)
    raise LabError("native Mihomo did not become ready")


def server_stats(run: RemoteRun):
    rows = []
    try:
        text = run.read("server.log")
    except Exception:
        return rows
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if value.get("event") == "stats":
            rows.append(value)
    return rows


def native_probe_source(mixed_port: int, fixture_port: int, count: int, interval: float):
    """Return a bounded remote Python probe using one TCP and UDP logical flow."""
    # The source is deliberately self-contained so no probe code is installed
    # on either host and no credentials can enter an artifact.
    return r'''
import json,socket,struct,time,hashlib
mixed=%d
target=('127.0.0.1',%d)
count=%d
interval=%r

def exact(sock,n):
    out=b''
    while len(out)<n:
        part=sock.recv(n-len(out))
        if not part: raise RuntimeError('unexpected eof')
        out+=part
    return out

def tcp_flow():
    sock=socket.create_connection(('127.0.0.1',mixed),5)
    sock.settimeout(6)
    try:
        sock.sendall(b'\x05\x01\x00')
        if exact(sock,2)!=b'\x05\x00': raise RuntimeError('socks greeting')
        sock.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(target[0])+struct.pack('!H',target[1]))
        reply=exact(sock,4)
        if reply[:2]!=b'\x05\x00': raise RuntimeError('socks connect')
        # The first four bytes include RSV/REP/RSV/ATYP. Consume the
        # variable-length bound address that follows it.
        atyp=reply[3]
        if atyp==1: exact(sock,4)
        elif atyp==3:
            length=exact(sock,1)[0]
            exact(sock,length)
        elif atyp==4: exact(sock,16)
        else: raise RuntimeError('socks reply address')
        exact(sock,2)
        observations=[]
        for i in range(count):
            payload=(('bfp-native-tcp-%%04d-'%%i).encode()+bytes([i%%251])*1024)[:1024]
            sock.sendall(payload)
            echo=exact(sock,len(payload))
            observations.append({'iteration':i,'ok':echo==payload,'bytes':len(echo)})
            if echo!=payload: raise RuntimeError('tcp echo mismatch')
            if i+1<count: time.sleep(interval)
        return observations
    finally: sock.close()

def udp_flow():
    control=socket.create_connection(('127.0.0.1',mixed),5)
    control.settimeout(6)
    try:
        control.sendall(b'\x05\x01\x00')
        if exact(control,2)!=b'\x05\x00': raise RuntimeError('udp greeting')
        control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
        head=exact(control,4)
        if head[:2]!=b'\x05\x00': raise RuntimeError('udp associate')
        atyp=head[3]
        if atyp==1: relay_host=socket.inet_ntoa(exact(control,4))
        elif atyp==3: relay_host=exact(control,exact(control,1)[0]).decode()
        elif atyp==4: relay_host=socket.inet_ntop(socket.AF_INET6,exact(control,16))
        else: raise RuntimeError('udp relay address')
        relay_port=struct.unpack('!H',exact(control,2))[0]
        if relay_host in ('0.0.0.0','::'): relay_host='127.0.0.1'
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.settimeout(6)
        try:
            sock.connect((relay_host,relay_port))
            observations=[]
            for i in range(count):
                payload=(('bfp-native-udp-%%04d-'%%i).encode()+bytes([(i+17)%%251])*1024)[:1024]
                packet=b'\x00\x00\x00\x01'+socket.inet_aton(target[0])+struct.pack('!H',target[1])+payload
                sock.send(packet)
                reply=sock.recv(4096)
                if len(reply)<10 or reply[:4]!=b'\x00\x00\x00\x01': raise RuntimeError('udp reply header')
                got=reply[10:]
                observations.append({'iteration':i,'ok':got==payload,'bytes':len(got)})
                if got!=payload: raise RuntimeError('udp echo mismatch')
                if i+1<count: time.sleep(interval)
            return observations
        finally: sock.close()
    finally: control.close()

started=time.monotonic()
result={'pass':False,'tcp':[],'udp':[],'tcp_completed':0,'udp_completed':0,'udp_failed':0}
try:
    # Run both flows concurrently.  This keeps the UDP black-hole clock
    # independent of TCP progress and exercises the shared BFP Session.
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        ft=pool.submit(tcp_flow)
        fu=pool.submit(udp_flow)
        result['tcp']=ft.result()
        result['udp']=fu.result()
    result['tcp_completed']=sum(x.get('ok') for x in result['tcp'])
    result['udp_completed']=sum(x.get('ok') for x in result['udp'])
    result['udp_failed']=count-result['udp_completed']
    result['pass']=result['tcp_completed']==count and result['udp_completed']==count
except Exception as exc:
    result['error']=type(exc).__name__+': '+str(exc)
    result['udp_failed']=count-result.get('udp_completed',0)
result['elapsed_ms']=round((time.monotonic()-started)*1000,1)
print(json.dumps(result))
''' % (mixed_port, fixture_port, count, interval)


def run_probe(run: RemoteRun, mixed_port: int, fixture_port: int, count=12, interval=1.0):
    return run.remote.python(native_probe_source(mixed_port, fixture_port, count, interval), timeout=90)


def scenario_config(template: str, client_name: str, mixed_port: int, dns_port: int):
    text = template
    text = text.replace("mixed-port: 17890", f"mixed-port: {mixed_port}")
    text = text.replace("client-config-file: ./credentials/client.json", f"client-config-file: ./{client_name}")
    text = text.replace("listen: 127.0.0.1:1053", f"listen: 127.0.0.1:{dns_port}")
    # Numeric fixture targets are used in this WAN gate.  Keep DNS enabled so
    # this is the packaged proxy mode, while using a bounded local resolver
    # list avoids making public DNS part of the carrier result.
    return text.replace("nameserver: [1.1.1.1, 8.8.8.8]", "nameserver: [1.1.1.1]")


def process_observation(run: RemoteRun, process_name: str):
    return run.remote.python(
        run._check()
        + "import pathlib,json\n"
        + "m=json.loads((p/(%r+'.process.json')).read_text())\n" % process_name
        + "print(json.dumps({'pid':m.get('pid'),'log_sha256':__import__('hashlib').sha256((p/(%r+'.log')).read_bytes()).hexdigest()}))\n" % process_name
    )


def upload_cached(run: RemoteRun, path: pathlib.Path, name: str):
    """Upload a public ELF once per sender host and copy it into this run."""
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if data[:4] != b"\x7fELF":
        raise LabError(f"not an ELF payload: {path}")
    # The cache is content-addressed and owned by the current SSH user. It
    # contains only public programs, never credentials or configs.
    state_source = (
        run._check()
        + "import pathlib,os,json,hashlib,shutil\n"
        + "cache=pathlib.Path('/tmp/bfp-native-wan-cache')\n"
        + "if cache.is_symlink() or str(cache.resolve())!='/tmp/bfp-native-wan-cache': raise RuntimeError('unsafe cache')\n"
        + "if not cache.exists(): cache.mkdir(mode=0o700)\n"
        + "if cache.stat().st_uid!=os.getuid() or cache.stat().st_mode&0o777!=0o700: raise RuntimeError('cache ownership')\n"
        + "f=cache/%r\n"
        + "hit=f.is_file() and not f.is_symlink() and hashlib.sha256(f.read_bytes()).hexdigest()==%r\n"
        + "print(json.dumps({'hit':hit}))\n"
    ) % (digest, digest)
    state = run.remote.python(state_source)
    if not state.get("hit"):
        compressed = gzip.compress(data, compresslevel=6, mtime=0)
        run.write(name + ".gz", compressed, 0o600)
        cache_source = (
            run._check()
            + "import pathlib,os,gzip,hashlib,shutil\n"
            + "raw=gzip.decompress((p/%r).read_bytes())\n"
            + "if hashlib.sha256(raw).hexdigest()!=%r: raise RuntimeError('payload hash')\n"
            + "cache=pathlib.Path('/tmp/bfp-native-wan-cache'); f=cache/%r\n"
            + "if f.exists():\n"
            + " if f.is_symlink() or hashlib.sha256(f.read_bytes()).hexdigest()!=%r: raise RuntimeError('cache collision')\n"
            + "else:\n"
            + " fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o700)\n"
            + " with os.fdopen(fd,'wb') as out: out.write(raw)\n"
            + "print(json.dumps({'cached':True}))\n"
        )
        run.remote.python(cache_source % (name + ".gz", digest, digest, digest))
    copy_source = (
        run._check()
        + "import pathlib,os,shutil,hashlib\n"
        + "cache=pathlib.Path('/tmp/bfp-native-wan-cache'); src=cache/%r; dst=p/%r\n"
        + "if hashlib.sha256(src.read_bytes()).hexdigest()!=%r: raise RuntimeError('cached hash')\n"
        + "fd=os.open(dst,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o700)\n"
        + "with os.fdopen(fd,'wb') as out: out.write(src.read_bytes())\n"
        + "print(json.dumps({'copied':True}))\n"
    )
    run.remote.python(copy_source % (digest, name, digest))
    return {"name": name, "bytes": len(data), "sha256": digest, "cache_hit": bool(state.get("hit"))}


def classification_policy(profile):
    if profile == "standard":
        return None
    if profile != "low-bandwidth":
        raise LabError("unsupported classification profile")
    return {
        "default_class": "normal",
        "rules": [
            {"name": "dns", "network": "udp", "ports": [{"first": 53, "last": 53}], "class": "interactive", "locked": True},
            {"name": "ssh", "network": "tcp", "ports": [{"first": 22, "last": 22}], "class": "interactive", "locked": True},
        ],
        "behavior": {"min_total_bytes": 32768, "bulk_bytes_per_second": 8192, "restore_bytes_per_second": 2048},
    }


def run(package: pathlib.Path, count=12, interval=1.0, mode="proxy", classification_profile="standard"):
    package = package.resolve(strict=True)
    work = WORKSPACE / "verification/product-mihomo"
    hosts = load_hosts()
    run_id = new_run_id()
    evidence = work / "runs" / run_id
    evidence.mkdir(parents=True)
    inputs = {
        "bfp": package / "bin/bfp-linux-amd64",
        "mihomo": package / "bin/mihomo-bfp-linux-amd64",
        "template": package / f"configs/native-{mode}.yaml",
    }
    if mode == "tun":
        inputs["launcher"] = package / "start-native.sh"
    for path in inputs.values():
        if not path.is_file():
            raise LabError(f"missing packaged input: {path}")
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in inputs.items()}
    manifest = json.loads((package / "release-manifest.json").read_text(encoding="utf-8"))
    expected = {item["path"]: item["sha256"] for item in manifest["files"]}
    for name, path in inputs.items():
        if hashes[name] != expected.get(path.relative_to(package).as_posix()):
            raise LabError("packaged WAN input does not match release manifest")
    policy = classification_policy(classification_profile)
    report = {
        "run_id": run_id,
        "package": str(package),
        "version": manifest["version"],
        "scope": "packaged native Mihomo BFP outbound over Singapore -> Los Angeles; " + ("kernel TUN with automatic routes inside a network-none container and a Unix carrier fixture" if mode == "tun" else "proxy mode, no TUN"),
        "pass": False,
        "input_hashes": hashes,
        "classification_profile": classification_profile,
        "load": {"count_per_scenario": count, "bytes_per_operation": 1024, "interval": f"{interval:g}s"},
        "scenarios": {},
        "cleanup": {},
    }
    harness_files = [pathlib.Path(__file__)]
    if mode == "tun":
        harness_files += [work / "wan_tun_host.py", work / "wan_tun_container.py"]
    report["harness_hashes"] = {}
    harness_payloads = {path.name: path.read_bytes() for path in harness_files}
    for path in harness_files:
        report["harness_hashes"][path.name] = hashlib.sha256(harness_payloads[path.name]).hexdigest()
        (evidence / path.name).write_bytes(harness_payloads[path.name])
    print(json.dumps({"stage": "native_wan_started", "run_id": run_id, "mode": mode, "count": count, "interval": interval}), flush=True)
    receiver = sender = None
    receiver_run = None
    sender_runs = []
    sender_cleanup_done = set()
    try:
        receiver = Remote(hosts["receiver"]).connect()
        sender = Remote(hosts["sender"]).connect()
        report["before"] = {"receiver": receiver.snapshot(), "sender": sender.snapshot()}
        receiver_run = RemoteRun(receiver, run_id)
        receiver_run.create()
        receive_bfp = receiver_run.upload_binary(inputs["bfp"])
        server_port = free_port(receiver, 51880, "0.0.0.0")
        fixture_port = free_port(receiver, 19180, "127.0.0.1")
        server_creds, client_creds = credentials()
        receiver_config = {
                "listen": f"0.0.0.0:{server_port}",
                "credentials": server_creds,
                "policy": {"AllowPrivate": True, "AllowedCIDRs": ["127.0.0.0/8"] + (["::1/128", hosts["receiver"].hostname + "/32"] if mode == "tun" else []), "AllowedPorts": [fixture_port], "MaxConcurrent": 4, "Timeout": 10000000000},
                "max_sessions": 4,
            }
        if policy is not None:
            receiver_config["classification"] = policy
        receiver_run.config(
            "server.json",
            receiver_config,
        )
        # localhost resolves to both loopback families. The dual-stack
        # fixture serves both validated answers without changing host DNS.
        fixture_host = "[::]" if mode == "tun" else "127.0.0.1"
        receiver_run.start(["fixture", "-listen", f"{fixture_host}:{fixture_port}"], name="fixture")
        receiver_run.start(["server", "-config", "server.json", "-stats", "1s"], name="server")
        report["ports"] = {"server": server_port, "fixture": fixture_port}
        template = inputs["template"].read_text(encoding="utf-8")
        for index, (name, blackhole) in enumerate((("normal_udp", "0s"), ("udp_to_tcp", "8s"), ("initial_udp_blocked", "1ns"))):
            print(json.dumps({"stage": "scenario_started", "scenario": name, "mode": mode}), flush=True)
            scenario_id = new_run_id()
            run = RemoteRun(sender, scenario_id)
            sender_runs.append(run)
            run.create()
            for program in ("bfp", "mihomo"):
                upload = upload_cached(run, inputs[program], program)
                print(json.dumps({"stage": "program_ready", "program": program, "cache_hit": upload["cache_hit"]}), flush=True)
            relay_port = free_port(sender, 19181 + index, "127.0.0.1")
            mixed_port = free_port(sender, 17890 + index, "127.0.0.1")
            dns_port = free_port(sender, 10530 + index, "127.0.0.1")
            if mode == "proxy":
                client_config = {"server": f"127.0.0.1:{relay_port}", "tcp_server": f"{hosts['receiver'].hostname}:{server_port}", "credentials": client_creds}
                if policy is not None:
                    client_config["classification"] = policy
                run.write("client.json", json.dumps(client_config, separators=(",", ":")).encode(), 0o600)
                run.write("native.yaml", scenario_config(template, "client.json", mixed_port, dns_port).encode(), 0o600)
                run.start(["relay", "-listen", f"127.0.0.1:{relay_port}", "-target", f"{hosts['receiver'].hostname}:{server_port}", "-blackhole-after", blackhole], name="relay")
                run.start(["-d", "runtime", "-f", "native.yaml"], name="mihomo", binary="mihomo")
                wait_native(run, mixed_port)
            else:
                run.config("client.json", {"server": "127.0.0.1:51880", "tcp_server": "127.0.0.1:51880", "credentials": client_creds})
                for path in harness_files[1:]:
                    run.write(path.name, harness_payloads[path.name])
                run.write("start-native.sh", inputs["launcher"].read_bytes())
                run.write("native-tun.yaml", template.encode())
                run.config("tun-job.json", {"scenario": name, "count": count, "interval": interval,
                           "server_host": hosts["receiver"].hostname, "server_port": server_port, "fixture_port": fixture_port,
                           "image": "sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f"})
                run.write("runtime.container.json", json.dumps({"run_id": run.run_id, "name": "bfp-race-" + run.run_id}).encode())
            before_stats = server_stats(receiver_run)
            before_open = target_opens(receiver_run)
            before_session_ids = {
                session.get("session_id")
                for row in before_stats
                for session in row.get("sessions", [])
                if session.get("session_id")
            }
            tun_result = None
            if mode == "proxy":
                probe = run_probe(run, mixed_port, fixture_port, count=count, interval=interval)
            else:
                source = run._check() + "cfg=json.loads((p/'tun-job.json').read_text())\nnamespace={'__name__':'bfp_tun_fixture'}\nexec(compile((p/'wan_tun_host.py').read_bytes(),'wan_tun_host.py','exec'),namespace)\nprint(json.dumps(namespace['execute'](p,rid,cfg)))\n"
                tun_result = run.remote.python(source, timeout=115)
                probe = tun_result.get("business", {}).get("probe", {"pass": False})
            # Allow the one-second server stats writer to record the final
            # carrier before collecting evidence.
            time.sleep(1.5)
            after_stats = server_stats(receiver_run)
            after_open = target_opens(receiver_run)
            # The receiver remains alive across scenarios. Select only the
            # Session IDs created by this scenario, then keep the last stats
            # row for each ID. Historical suspended Sessions must not make a
            # fresh scenario look like it broke Session continuity.
            latest_by_id = {}
            active_by_id = {}
            timeline = []
            last_signature = {}
            for row in after_stats:
                for session in row.get("sessions", []):
                    sid = session.get("session_id")
                    if sid and sid not in before_session_ids:
                        latest_by_id[sid] = session
                        if session.get("carrier") in ("udp", "tcp"):
                            active_by_id[sid] = session
                        signature = (session.get("carrier"), session.get("generation"), session.get("switches"))
                        if last_signature.get(sid) != signature:
                            timeline.append({k: session.get(k) for k in ("session_id", "client_address", "server_address", "carrier", "generation", "switches", "opened")})
                            last_signature[sid] = signature
            sessions = list(latest_by_id.values())
            terminal = sessions[-1] if sessions else {}
            # TUN verifies the launcher shutdown and route restoration before
            # returning. A suspended state after that shutdown is expected;
            # evaluate the recorded active carrier during the completed I/O
            # and preserve both the transition timeline and terminal state.
            latest = active_by_id.get(terminal.get("session_id"), {}) if mode == "tun" else terminal
            carrier = latest.get("carrier")
            generation = latest.get("generation", 0)
            same_session = len(sessions) == 1
            if name == "normal_udp":
                carrier_ok = carrier == "udp"
            elif name == "udp_to_tcp":
                carrier_ok = carrier == "tcp" and generation >= 2
            else:
                carrier_ok = carrier == "tcp"
            expected_open = after_open - before_open == 1
            row = {
                "pass": bool(probe.get("pass") and carrier_ok and same_session and expected_open and (tun_result is None or tun_result.get("pass"))),
                "blackhole_after": blackhole,
                "probe": probe,
                "server_stats_before": before_stats[-2:],
                "server_stats_after": after_stats[-3:],
                "carrier": carrier,
                "generation": generation,
                "same_session": same_session,
                "target_open_before": before_open,
                "target_open_after": after_open,
                "one_target_connection": expected_open,
                "carrier_expectation_met": carrier_ok,
                "terminal_carrier": terminal.get("carrier"),
                "session_timeline": timeline,
                "active_session_snapshot": latest,
                "process": process_observation(run, "mihomo") if mode == "proxy" else None,
            }
            if tun_result is not None:
                row["tun"] = tun_result
            report["scenarios"][name] = row
            write_public(evidence / f"{name}.json", row)
            report["cleanup"][name] = run.cleanup()
            sender_cleanup_done.add(run.run_id)
            print(json.dumps({"stage": "scenario_finished", "scenario": name, "pass": row["pass"], "carrier": carrier, "generation": generation,
                              "tcp_completed": probe.get("tcp_completed"), "udp_completed": probe.get("udp_completed"),
                              "error": (tun_result or {}).get("error") or (tun_result or {}).get("business", {}).get("error") or probe.get("error")}), flush=True)
            if mode == "tun" and not (tun_result or {}).get("business", {}).get("probe"):
                raise LabError("TUN fixture did not reach the application probe; remaining scenarios not started")
        before_probe = target_opens(receiver_run)
        report["random_probe"] = random_probe(sender, hosts["receiver"].hostname, server_port)
        after_probe = target_opens(receiver_run)
        report["random_probe"].update({"target_open_before": before_probe, "target_open_after": after_probe, "no_target_side_effect": before_probe == after_probe})
        report["random_probe"]["pass"] = bool(report["random_probe"].get("no_application_response") and report["random_probe"].get("tcp_connected") == 8 and before_probe == after_probe)
        report["pass"] = bool(all(row.get("pass") for row in report["scenarios"].values()) and report["random_probe"].get("pass"))
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {SANITIZER.text(str(exc))[:2048]}"
    finally:
        # A failed scenario may leave a process before its per-scenario cleanup;
        # cleanup is owner-checked and safe to retry for that exact run.
        for run in reversed(sender_runs):
            if run.run_id not in sender_cleanup_done:
                try:
                    report.setdefault("cleanup_recovery", []).append(run.cleanup())
                except Exception as exc:
                    report.setdefault("cleanup_recovery_errors", []).append(f"{type(exc).__name__}: {SANITIZER.text(str(exc))[:1024]}")
        if receiver_run is not None:
            try:
                report["receiver_cleanup"] = receiver_run.cleanup()
            except Exception as exc:
                report["receiver_cleanup_error"] = f"{type(exc).__name__}: {SANITIZER.text(str(exc))[:1024]}"
        if receiver is not None and sender is not None:
            try:
                report["after"] = {"receiver": receiver.snapshot(), "sender": sender.snapshot()}
                report["snapshot_comparison"] = {
                    "receiver": compare_snapshots(report["before"]["receiver"], report["after"]["receiver"]),
                    "sender": compare_snapshots(report["before"]["sender"], report["after"]["sender"]),
                }
            except Exception as exc:
                report["snapshot_error"] = f"{type(exc).__name__}: {SANITIZER.text(str(exc))[:1024]}"
            receiver.close()
            sender.close()
        report["pass"] = bool(report.get("pass") and report.get("receiver_cleanup", {}).get("directory_removed") and all(v.get("directory_removed") for v in report.get("cleanup", {}).values()) and all(v.get("unchanged") for v in report.get("snapshot_comparison", {}).values()))
        write_public(evidence / "native-wan-result.json", report)
    return report, evidence / "native-wan-result.json"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True)
    parser.add_argument("--count", type=int, default=12)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--mode", choices=("proxy", "tun"), default="proxy")
    parser.add_argument("--classification-profile", choices=("standard", "low-bandwidth"), default="standard")
    args = parser.parse_args()
    result, path = run(pathlib.Path(args.package), args.count, args.interval, args.mode, args.classification_profile)
    print(json.dumps({"pass": result.get("pass"), "run_id": result.get("run_id"), "path": str(path), "scenarios": {k: v.get("pass") for k, v in result.get("scenarios", {}).items()}, "error": result.get("error")}, ensure_ascii=False))
    raise SystemExit(0 if result.get("pass") else 1)
