"""Run one local, source-bound actual CLI DNS/SOCKS smoke check.

Credentials stay in a keygen-created private directory and are removed on exit.
Only owned child processes are stopped. No host routes or system DNS are changed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
DIRS = ("adapter", "classification", "clientconfig", "cmd", "gateway", "internal", "obfuscation", "protocol", "scheduler", "security", "session", "tests")

def manifest(stage):
    files = [stage / "go.mod", stage / "go.sum"]
    for directory in DIRS:
        files.extend((stage / directory).rglob("*.go"))
    return [{"path": p.relative_to(stage).as_posix(), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(files)]

def ready(log, event, process, deadline):
    while time.monotonic() < deadline:
        for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("event") == event:
                return row
        if process.poll() is not None:
            raise RuntimeError("owned CLI exited before readiness")
        time.sleep(.05)
    raise TimeoutError("owned CLI readiness deadline")

def read_exact(conn, size):
    result = bytearray()
    while len(result) < size:
        chunk = conn.recv(size-len(result))
        if not chunk:
            raise EOFError("short loopback response")
        result.extend(chunk)
    return bytes(result)

def dns_name(message, offset):
    """Read a bounded DNS name, including RFC 1035 compression pointers."""
    labels, visited = [], set()
    end, size = None, 1
    while True:
        if offset >= len(message) or offset in visited:
            raise RuntimeError("truncated or cyclic DNS name")
        visited.add(offset)
        length = message[offset]
        if length & 0xc0 == 0xc0:
            if offset+1 >= len(message):
                raise RuntimeError("truncated DNS pointer")
            pointer = ((length & 0x3f) << 8) | message[offset+1]
            if pointer >= offset:
                raise RuntimeError("DNS pointer must refer backwards")
            if end is None:
                end = offset+2
            offset = pointer
            continue
        if length & 0xc0:
            raise RuntimeError("unsupported DNS label type")
        offset += 1
        if length == 0:
            return b".".join(labels).lower(), end if end is not None else offset
        if offset+length > len(message):
            raise RuntimeError("truncated DNS label")
        size += length+1
        if size > 255:
            raise RuntimeError("DNS name exceeds wire limit")
        labels.append(message[offset:offset+length])
        offset += length

def parse_dns_response(response):
    if len(response) < 12:
        raise RuntimeError("short DNS response header")
    identifier, flags, qd, an, ns, ar = struct.unpack("!6H", response[:12])
    if identifier != 317 or flags & 15 or not flags & 0x8000 or flags & 0x200 or (qd, an, ns, ar) != (1,1,0,0):
        raise RuntimeError("DNS positive response header mismatch")
    question, offset = dns_name(response, 12)
    if question != b"localhost" or offset+4 > len(response) or struct.unpack("!2H", response[offset:offset+4]) != (1,1):
        raise RuntimeError("DNS question mismatch")
    owner, offset = dns_name(response, offset+4)
    if owner != question or offset+10 > len(response):
        raise RuntimeError("DNS answer name/header mismatch")
    kind, family, ttl, size = struct.unpack("!2HIH", response[offset:offset+10])
    if (kind, family, size) != (1,1,4) or ttl < 1 or offset+10+size != len(response):
        raise RuntimeError("DNS lease/type mismatch")
    ip = response[offset+10:offset+14]
    if ip[0] != 198 or ip[1] not in (18,19):
        raise RuntimeError("DNS returned non-fake address")
    return ip, ttl

def query_dns(address, network):
    query = struct.pack("!6H", 317, 0x100, 1, 0, 0, 0) + b"\x09localhost\x00" + struct.pack("!2H", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if network == "udp" else socket.SOCK_STREAM)
    with sock:
        sock.settimeout(2)
        sock.connect(address)
        if network == "tcp":
            sock.sendall(struct.pack("!H", len(query))+query)
            response = read_exact(sock, struct.unpack("!H", read_exact(sock, 2))[0])
        else:
            sock.send(query)
            response = sock.recv(1232)
    return parse_dns_response(response)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True)
    parser.add_argument("--attempt", default="01")
    args = parser.parse_args()
    stage = (ROOT / args.stage).resolve()
    if not stage.is_relative_to(ROOT):
        raise ValueError("candidate outside workspace")
    out = stage / "verification" / stage.name / ("cli-dns-smoke-attempt"+args.attempt)
    out.mkdir(parents=True, exist_ok=False)
    runtime = out / "runtime"
    runtime.mkdir()
    binary = out / "bfp.exe"
    report = {"candidate":stage.name, "pass":False, "no_remote":True, "acceptance_complete":False, "production_ready":False, "released":False}
    rows = manifest(stage)
    processes, logs = [], []
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    def launch(command, name):
        output = (out / (name+".jsonl")).open("xb")
        errors = (out / (name+".err")).open("xb")
        logs.extend((output,errors))
        process = subprocess.Popen(command, cwd=stage, stdout=output, stderr=errors, creationflags=flags)
        processes.append(process)
        return process
    try:
        result = subprocess.run(["go","build","-trimpath","-o",str(binary),"./cmd/bfp"], cwd=stage, env=dict(os.environ,GOTOOLCHAIN="local",GOPROXY="off",GOSUMDB="off",CGO_ENABLED="0"), capture_output=True, timeout=60, creationflags=flags)
        (out/"build.log").write_bytes(result.stdout+result.stderr)
        if result.returncode:
            raise RuntimeError("actual CLI build failed")
        report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        credentials = runtime / "credentials"
        result = subprocess.run([str(binary),"keygen","-out",str(credentials)], capture_output=True, timeout=5, creationflags=flags)
        if result.returncode:
            raise RuntimeError("actual CLI keygen failed")
        fixture = launch([str(binary),"fixture","-listen","127.0.0.1:0"],"fixture")
        fixture_row = ready(out/"fixture.jsonl","fixture",fixture,time.monotonic()+5)
        target_port = int(fixture_row["address"].rsplit(":",1)[1])
        server_path = credentials / "server.json"
        config = json.loads(server_path.read_text())
        config["listen"]="127.0.0.1:0"
        config["policy"].update(AllowPrivate=True,AllowedCIDRs=["127.0.0.0/8","::1/128"],AllowedPorts=[target_port])
        server_path.write_text(json.dumps(config),encoding="utf-8")
        del config
        server = launch([str(binary),"server","-config",str(server_path),"-stats","250ms"],"server")
        server_row = ready(out/"server.jsonl","listening",server,time.monotonic()+5)
        client_path = credentials / "client.json"
        config = json.loads(client_path.read_text())
        config.update(server=server_row["address"],tcp_server=server_row["address"],socks="127.0.0.1:0",dns={"listen":"127.0.0.1:0","mapping_ttl":"30s"})
        client_path.write_text(json.dumps(config),encoding="utf-8")
        del config
        client = launch([str(binary),"client","-config",str(client_path)],"client")
        dns_row = ready(out/"client.jsonl","dns_listening",client,time.monotonic()+5)
        socks_row = ready(out/"client.jsonl","socks_listening",client,time.monotonic()+5)
        dns_peer = ("127.0.0.1",int(dns_row["address"].rsplit(":",1)[1]))
        udp_ip, udp_ttl = query_dns(dns_peer,"udp")
        report.update(dns_udp_pass=True, dns_udp_ttl=udp_ttl)
        tcp_ip, tcp_ttl = query_dns(dns_peer,"tcp")
        report.update(dns_tcp_pass=True, dns_tcp_ttl=tcp_ttl)
        if udp_ip != tcp_ip:
            raise RuntimeError("DNS transports did not share mapping")
        report["shared_address"] = True
        peer=("127.0.0.1",int(socks_row["address"].rsplit(":",1)[1]))
        with socket.create_connection(peer,timeout=2) as sock:
            sock.sendall(b"\x05\x01\x00")
            if read_exact(sock,2)!=b"\x05\x00": raise RuntimeError("SOCKS greeting")
            sock.sendall(b"\x05\x01\x00\x01"+udp_ip+struct.pack("!H",target_port))
            reply = read_exact(sock,10)
            report["socks_reply_code"] = reply[1]
            if reply[1]!=0: raise RuntimeError("SOCKS fake-IP CONNECT reply code "+str(reply[1]))
            payload=b"actual CLI DNS -> SOCKS -> encrypted BFP -> echo"
            sock.sendall(payload)
            if read_exact(sock,len(payload))!=payload: raise RuntimeError("CLI echo mismatch")
        report.update(dns_udp_pass=True,dns_tcp_pass=True,shared_address=True,dns_ttl_max=max(udp_ttl,tcp_ttl),socks_fake_ip_echo_pass=True,initial_carrier=socks_row["session"]["carrier"],source_unchanged=rows==manifest(stage))
        report["pass"]=report["source_unchanged"]
    except Exception as error:
        report["error_type"]=type(error).__name__
        report["error"]=str(error)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill();process.wait(timeout=3)
        for stream in logs:stream.close()
        report["owned_processes_stopped"]=all(p.poll() is not None for p in processes)
        if runtime.resolve().parent != out.resolve():raise RuntimeError("runtime cleanup path mismatch")
        shutil.rmtree(runtime)
        report["private_runtime_removed"]=not runtime.exists()
        report["pass"]=report["pass"] and report["owned_processes_stopped"] and report["private_runtime_removed"]
        (out/"source-manifest.json").write_text(json.dumps(rows,indent=2)+"\n",encoding="utf-8")
        (out/"summary.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report,ensure_ascii=False),flush=True)
    return 0 if report["pass"] else 1

if __name__=="__main__":raise SystemExit(main())
