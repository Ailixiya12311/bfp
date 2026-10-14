"""Manage the operator's BFP pilot on the two authorized hosts.

Remote resources use lab.remote's pinned SSH and exact run ownership. The pilot
is retained between commands. It does not install a system service; stop removes
only the recorded instance. Private profiles are generated in a protected local
directory and are never included in public release archives.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lab"))
sys.path.insert(0, str(ROOT / "verification/product-mihomo"))
from remote import (LabError, Remote, RemoteRun, RUN_ID, SANITIZER, load_hosts,
                    new_run_id)
from wan_native import upload_cached
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

CURRENT = ROOT / "deploy/current.json"
LOCK = ROOT / "deploy/pilot.lock"


@contextmanager
def command_lock(path=None):
    """Serialize local CLI commands across their complete remote lifecycle."""
    path = pathlib.Path(path) if path is not None else LOCK
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        if stream.seek(0, os.SEEK_END) == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise LabError("another pilot command is active; retry when it finishes") from exc
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def write_public_atomic(path, value):
    """Keep the last complete sanitized record if serialization or replace fails."""
    path = pathlib.Path(path)
    payload = json.dumps(SANITIZER.obj(value), ensure_ascii=False, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=path.name + ".", suffix=".tmp", delete=False) as stream:
            temporary = pathlib.Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def connect_remote(hosts, role, via_receiver=False):
    """Keep the optional SSH tunnel alive under the sender's pinned SSH session."""
    host = hosts[role]
    with ExitStack() as connections:
        if via_receiver and role == "sender":
            receiver = connections.enter_context(Remote(hosts["receiver"]))
            channel = receiver.client.get_transport().open_channel(
                "direct-tcpip", (host.hostname, host.port), ("127.0.0.1", 0), timeout=10)
            connections.callback(channel.close)
            remote = Remote(host)
            connections.callback(remote.close)
            remote.connect(sock=channel)
        else:
            remote = connections.enter_context(Remote(host))
        yield remote


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_file(package, relative):
    package = package.resolve(strict=True)
    path = package / relative
    entries = json.loads((package / "release-manifest.json").read_text(encoding="utf-8-sig"))["files"]
    expected = {item["path"]: item["sha256"] for item in entries}
    if path.is_symlink() or digest(path) != expected.get(relative):
        raise LabError("package payload does not match its release manifest")
    return path


def save(state):
    target = ROOT / "deploy/runs" / state["instance_id"] / "state.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    write_public_atomic(target, state)
    write_public_atomic(CURRENT, {"state": str(target)})


def load():
    pointer = json.loads(CURRENT.read_text(encoding="utf-8"))
    target = pathlib.Path(pointer["state"]).resolve(strict=True)
    if not target.is_relative_to((ROOT / "deploy/runs").resolve()):
        raise LabError("pilot state path escaped the deployment directory")
    state = json.loads(target.read_text(encoding="utf-8"))
    if not RUN_ID.fullmatch(state.get("instance_id", "")):
        raise LabError("invalid pilot instance identity")
    expected = ROOT / ("credentials-pilot-" + state["instance_id"])
    if pathlib.Path(state["private_directory"]).resolve() != expected.resolve():
        raise LabError("unexpected private profile directory")
    for role, host in load_hosts().items():
        if state["hosts"][role]["host"] != host.hostname:
            raise LabError("pilot state endpoint mismatch")
    return state


def prepare(root_package, native_package):
    if CURRENT.exists():
        raise LabError("a pilot state already exists; use start/status/stop for that instance")
    hosts = load_hosts()
    receiver_host = hosts["receiver"].hostname
    public_endpoint = f"[{receiver_host}]:51880" if ":" in receiver_host else f"{receiver_host}:51880"
    root_package, native_package = root_package.resolve(strict=True), native_package.resolve(strict=True)
    linux = checked_file(root_package, "bin/bfp-linux-amd64")
    keygen = checked_file(root_package, "bin/bfp-windows-amd64.exe")
    native_files = ["bin/bfp-windows-amd64.exe", "bin/mihomo-bfp-windows-amd64.exe",
                    "start-native.ps1", "configs/native-proxy.yaml", "configs/native-tun.yaml"]
    for name in ("windows-tun-support.ps1", "windows-tun-cleanup.ps1"):
        if (native_package / name).is_file():
            native_files.append(name)
    payload = {name: checked_file(native_package, name) for name in native_files}
    instance_id = new_run_id()
    private = ROOT / ("credentials-pilot-" + instance_id)
    if private.exists():
        raise LabError("private pilot directory already exists")
    proc = subprocess.run([str(keygen), "keygen", "-out", str(private),
                           "-server-listen", "0.0.0.0:51880", "-server", public_endpoint,
                           "-tcp-server", public_endpoint, "-socks", "127.0.0.1:1080",
                           "-classification-profile", "low-bandwidth"], capture_output=True, text=True)
    if proc.returncode:
        raise LabError("private credential generation failed")
    server = json.loads((private / "server.json").read_text())
    sender = json.loads((private / "client.json").read_text())
    SANITIZER.config(server)
    SANITIZER.config(sender)
    # The desktop and Singapore sender have separate keys. Only the server
    # admission material and pinned server public key are shared.
    key = X25519PrivateKey.generate()
    public = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    desktop = json.loads(json.dumps(sender))
    desktop["credentials"]["public"] = public
    desktop["credentials"]["private"] = base64.b64encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
    SANITIZER.config(desktop)
    server["credentials"]["allowed_clients"].append(public)
    server["policy"]["MaxConcurrent"] = 4
    server["max_sessions"] = 4
    (private / "server.json").write_text(json.dumps(server, indent=2), encoding="utf-8")
    native = private / "windows-client"
    for relative, source in payload.items():
        target = native / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    credentials_dir = native / "credentials"
    credentials_dir.mkdir()
    (credentials_dir / "client.json").write_text(json.dumps(desktop, indent=2), encoding="utf-8")
    (native / "start-proxy.cmd").write_text(
        '@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-native.ps1" -Mode proxy\r\nif errorlevel 1 pause\r\n', encoding="ascii")
    (native / "使用说明.md").write_text(
        "# BFP Windows 客户端\n\n双击 `start-proxy.cmd`，保持窗口运行。"
        "应用填写 HTTP 或 SOCKS5 `127.0.0.1:17890`，关闭启动窗口会回收代理进程。\n\n"
        f"服务端是 `{public_endpoint}`；默认 UDP，失败后 TCP。"
        "本目录只包含该电脑的客户端密钥，不能分享；公共 ZIP 不包含这些密钥。\n\n"
        "TUN 需管理员启动，尚未完成 Windows 系统生命周期验收。"
        "服务器实例状态和停止命令见项目 `deploy/README.md`。\n", encoding="utf-8")
    manifest = json.loads((root_package / "release-manifest.json").read_text(encoding="utf-8-sig"))
    state = {"instance_id": instance_id, "created_utc": utc(), "private_directory": str(private),
             "root_package": str(root_package), "native_package": str(native_package),
             "root_version": manifest["version"], "linux_sha256": digest(linux),
             "windows_client": str(native), "public_endpoint": public_endpoint,
             "expected_exit_ip": os.environ.get("BFP_EXPECTED_EXIT_IP", receiver_host).strip(),
             "sender_socks": "127.0.0.1:1080", "desktop_proxy": "127.0.0.1:17890",
             "auto_start_on_boot": False, "production_ready": False,
             "hosts": {role: {"host": h.hostname, "run_id": instance_id, "phase": "prepared"}
                       for role, h in hosts.items()}, "events": []}
    save(state)
    return {"prepared": True, "instance_id": instance_id, "windows_client": str(native),
            "public_endpoint": state["public_endpoint"], "desktop_proxy": state["desktop_proxy"]}


def status_remote(run):
    source = "import json,pathlib\np=pathlib.Path(%r)\nif not p.exists():\n print(json.dumps({'exists':False,'running':False})); raise SystemExit(0)\n" % run.directory
    source += run._check() + r'''
import hashlib,time
role=%r
manifest=p/(role+'.process.json')
running=False
owned=False
pid=None
if manifest.exists():
 m=json.loads(manifest.read_text())
 if m.get('run_id')!=rid: raise RuntimeError('process record owner mismatch')
 pid=m['pid']; proc=pathlib.Path('/proc')/str(pid)
 if proc.exists():
  try:
   stat=(proc/'stat').read_text().rsplit(')',1)[1].split()
   if stat[0]!='Z':
    exe=str((proc/'exe').resolve())
    cmd=(proc/'cmdline').read_bytes()
    owned=stat[19]==m['starttime'] and hashlib.sha256(cmd).hexdigest()==m['command_sha256'] and exe==m['exe'] and exe==str(p/'bfp') and os.getpgid(pid)==pid
    if not owned:
     if (proc/'stat').read_text().rsplit(')',1)[1].split()[0]!='Z':raise RuntimeError('PID ownership mismatch')
    else:running=True
  except (FileNotFoundError,ProcessLookupError):pass
log=p/(role+'.log')
events=[]
if log.exists():
 with log.open('rb') as f:
  f.seek(max(0,log.stat().st_size-262144)); lines=f.read().decode(errors='replace').splitlines()
 for line in lines:
  try: row=json.loads(line)
  except ValueError:continue
  if row.get('event') in ('listening','socks_listening','stats'):
   events.append(row)
allowed=('id','session_id','state','carrier','generation','flows','streams','datagrams')
sessions=[]
snapshot_event='socks_listening' if role=='sender' else 'stats'
snapshot=next((row for row in reversed(events) if row.get('event')==snapshot_event),None)
if snapshot is not None:
 row=snapshot
 for s in row.get('sessions',[]) or ([row['session']] if isinstance(row.get('session'),dict) else []):
  sessions.append({k:v for k,v in s.items() if k in allowed})
print(json.dumps({'exists':True,'running':running,'owner_verified':True,'pid':pid,
 'binary_sha256':hashlib.sha256((p/'bfp').read_bytes()).hexdigest() if (p/'bfp').is_file() else None,
 'log_bytes':log.stat().st_size if log.exists() else 0,'sessions':sessions,
 'sessions_source':('initial_connection' if role=='sender' else 'latest_server_stats') if snapshot is not None else 'unavailable',
 'sessions_are_live':False}))
''' % run.remote.host.role
    return run.remote.python(source, timeout=12)


def operate(action, roles, via_receiver=False):
    state = load()
    hosts = load_hosts()
    private = pathlib.Path(state["private_directory"])
    if action == "start":
        linux = checked_file(pathlib.Path(state["root_package"]), "bin/bfp-linux-amd64")
        if digest(linux) != state["linux_sha256"]:
            raise LabError("pilot binary input changed")
    report = {"action": action, "instance_id": state["instance_id"], "roles": {}}
    for role in roles:
        host = hosts[role]
        access_route = "via_receiver" if via_receiver and role == "sender" else "direct"
        print(json.dumps({"stage": action, "role": role, "host": host.hostname}), flush=True)
        try:
            with connect_remote(hosts, role, via_receiver) as remote:
                run = RemoteRun(remote, state["instance_id"])
                before = status_remote(run)
                if action == "start":
                    if before["running"]:
                        if before["binary_sha256"] != state["linux_sha256"]:
                            raise LabError("running pilot binary differs from the recorded package")
                        result = before
                    else:
                        if before["exists"]:
                            run.cleanup()
                        # Check only the pilot's two ports before allocating its directory.
                        port = 51880 if role == "receiver" else 1080
                        kind = "socket.SOCK_STREAM,socket.SOCK_DGRAM" if role == "receiver" else "socket.SOCK_STREAM"
                        address = "0.0.0.0" if role == "receiver" else "127.0.0.1"
                        remote.python("import socket,json\nss=[]\ntry:\n for k in (%s,):\n  s=socket.socket(socket.AF_INET,k);ss.append(s);s.bind((%r,%r))\n print(json.dumps({'ports_available':True}))\nfinally:\n for s in ss:s.close()\n" % (kind,address,port))
                        run.create()
                        upload = upload_cached(run, linux, "bfp")
                        print(json.dumps({"stage":"binary_ready","role":role,"cache_hit":upload["cache_hit"]}), flush=True)
                        config = json.loads((private / ("server.json" if role == "receiver" else "client.json")).read_text())
                        run.config("config.json", config)
                        args = ["server" if role == "receiver" else "client", "-config", "config.json"]
                        if role == "receiver": args += ["-stats", "30s"]
                        run.start(args, name=role)
                        result = status_remote(run)
                    state["hosts"][role]["phase"] = "running" if result["running"] else "exited"
                elif action == "stop":
                    result = run.cleanup() if before["exists"] else {"directory_removed":True,"already_absent":True}
                    state["hosts"][role]["phase"] = "stopped"
                else:
                    result = before
                    state["hosts"][role]["phase"] = "running" if result["running"] else "stopped"
                report["roles"][role] = {**result, "access_route": access_route}
                state["hosts"][role]["last_verified_utc"] = utc()
                state["hosts"][role].pop("last_error", None)
        except Exception as exc:
            report["roles"][role] = {"error": SANITIZER.text(str(exc))[:640], "access_route": access_route}
            state["hosts"][role]["last_error"] = report["roles"][role]["error"]
        state["hosts"][role]["access_route"] = access_route
        state["events"].append({"time_utc":utc(),"action":action,"role":role,"result":report["roles"][role]})
        save(state)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    p = commands.add_parser("prepare")
    p.add_argument("--root-package", type=pathlib.Path, default=ROOT/"dist/BFP-0.1.0-preview.22")
    p.add_argument("--native-package", type=pathlib.Path, default=ROOT/"dist/BFP-Mihomo-0.1.0-preview.31")
    for action in ("start", "status", "stop"):
        p = commands.add_parser(action)
        p.add_argument("--role", choices=("receiver","sender","both"), default="both")
        p.add_argument("--via-receiver", action="store_true",
                       help="connect to sender through the receiver's SSH tunnel; both host keys stay pinned")
    args = parser.parse_args()
    try:
        with command_lock():
            result = prepare(args.root_package, args.native_package) if args.action=="prepare" else operate(args.action, ["receiver","sender"] if args.role=="both" else [args.role], via_receiver=args.via_receiver)
        print(json.dumps(result, ensure_ascii=False), flush=True)
        if any("error" in r for r in result.get("roles",{}).values()): return 1
        return 0
    except Exception as exc:
        print(json.dumps({"error":SANITIZER.text(str(exc))[:640]}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
