"""Pinned SSH and run-owned two-host WAN lab helpers.

Only the two explicitly authorized inventory rows are parsed. Passwords and
temporary protocol secrets remain in memory/0600 files and never enter artifacts.
Import this module to stage binaries/configs after the CLI contract is available.
`python lab/remote.py prepare` performs read-only remote snapshots only.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import dataclasses
import hashlib
import io
import json
import logging
import os
import pathlib
import re
import secrets
import shlex
import socket
import time
from datetime import datetime, timezone

import paramiko

# SSH transport diagnostics are handled through sanitized structured results.
logging.getLogger('paramiko').addHandler(logging.NullHandler())
logging.getLogger('paramiko').propagate = False
logging.getLogger('paramiko').setLevel(logging.CRITICAL)

WORKSPACE = pathlib.Path(__file__).resolve().parents[1]
def _find_server_workspace(desktop: pathlib.Path | None = None) -> pathlib.Path:
    """Locate the operator's server workspace without assuming its display name.

    The workspace directory has been renamed over time, while the pinned
    ``latency-plan-24`` directory is stable.  Resolving it from the user's
    Desktop also avoids depending on a source-file encoding for a non-ASCII
    Windows path.
    """
    desktop = desktop or (pathlib.Path.home() / "Desktop")
    preferred = desktop / "服务器整理及优化"
    if preferred.is_dir() and (preferred / "latency-plan-24").is_dir():
        return preferred
    candidates = sorted(
        path for path in desktop.iterdir()
        if path.is_dir() and (path / "latency-plan-24").is_dir()
    )
    if len(candidates) == 1:
        return candidates[0]
    # Keep a deterministic path for the error message when the workspace is
    # missing or ambiguous; callers will fail closed before using credentials.
    return preferred


def _find_inventory(workspace: pathlib.Path) -> pathlib.Path:
    """Resolve the operator-approved inventory without exposing its contents.

    ``BFP_INVENTORY_PATH`` is an explicit override for machines that keep the
    unredacted inventory outside the server-notes directory.  The historical
    ``Desktop\\cold`` location is checked before the maintained summary table:
    the latter intentionally does not contain SSH credentials.
    """
    override = os.environ.get("BFP_INVENTORY_PATH", "").strip()
    if override:
        return pathlib.Path(override)
    candidates = (
        workspace / "servers-unredacted.md",
        workspace.parent / "cold" / "servers-unredacted.md",
        workspace / "服务器清单.md",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return workspace / "servers-unredacted.md"


SERVER_WORKSPACE = _find_server_workspace()
INVENTORY = _find_inventory(SERVER_WORKSPACE)
ENDPOINTS = {
    # Addresses are operator inputs, never public source-code defaults.
    "receiver": ("BFP_RECEIVER_HOST", "BFP_RECEIVER_SSH_PORT", "known_hosts-192"),
    "sender": ("BFP_SENDER_HOST", "BFP_SENDER_SSH_PORT", "known_hosts-sg"),
}
RUN_ID = re.compile(r"^[a-f0-9]{32}$")
FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,100}$")


class LabError(RuntimeError):
    pass


class Sanitizer:
    _sensitive_key = re.compile(
        r"(?i)(?:password|passphrase|private(?:[_ -]?key)?|secret|token|credential|psk|admission|"
        r"[a-z0-9_-]+_(?:secret|token|credential|psk|key))"
    )
    _sensitive_label = re.compile(
        r'(?i)("?(?:password|passphrase|private(?:[_ -]?key)?|secret|token|credential|psk|admission|'
        r'[a-z0-9_-]+_(?:secret|token|credential|psk|key))"?\s*[:=]\s*)'
        r'("[^"\n]*"|\S+)'
    )

    def __init__(self):
        self._values: set[str] = set()

    def add(self, value):
        if isinstance(value, bytes):
            value = value.decode("utf-8", "ignore")
        if isinstance(value, str) and value:
            self._values.add(value)

    def config(self, obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if re.search(r"password|passphrase|secret|token|credential|psk|key", str(key), re.I):
                    self._register_nested(value)
                else:
                    self.config(value)
        elif isinstance(obj, (list, tuple)):
            for value in obj:
                self.config(value)

    def _register_nested(self, value):
        if isinstance(value, dict):
            for child in value.values():
                self._register_nested(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                self._register_nested(child)
        else:
            self.add(value)

    def text(self, text: str) -> str:
        for value in sorted(self._values, key=len, reverse=True):
            text = text.replace(value, "[REDACTED]")
        # Defense in depth for labeled values from an unexpected remote log.
        text = self._sensitive_label.sub(lambda m: m.group(1) + '"[REDACTED]"', text)
        text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", text, flags=re.S)
        return text

    def obj(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.obj(item) for item in value]
        if isinstance(value, dict):
            return {key: ("[REDACTED]" if self._sensitive_key.fullmatch(str(key)) else self.obj(item)) for key, item in value.items()}
        return value


SANITIZER = Sanitizer()


@dataclasses.dataclass(frozen=True)
class Host:
    role: str
    hostname: str
    port: int
    username: str
    password: str = dataclasses.field(repr=False)
    pin_file: pathlib.Path = dataclasses.field(repr=False)
    source_line: int = 0

    @property
    def lookup(self):
        return self.hostname if self.port == 22 else f"[{self.hostname}]:{self.port}"

    def public(self):
        return {"role": self.role, "host": self.hostname, "port": self.port, "username": self.username, "inventory_line": self.source_line, "host_key_source": str(self.pin_file)}


def load_hosts(inventory=None) -> dict[str, Host]:
    endpoints = {}
    for role, (host_variable, port_variable, pin_name) in ENDPOINTS.items():
        hostname = os.environ.get(host_variable, "").strip()
        port_value = os.environ.get(port_variable, "22").strip()
        if not hostname:
            raise LabError(f"{role}: set {host_variable} before using remote tools")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]*", hostname):
            raise LabError(f"{role}: invalid {host_variable}")
        if not port_value.isascii() or not port_value.isdecimal() or not 1 <= int(port_value) <= 65535:
            raise LabError(f"{role}: invalid {port_variable}")
        pin_override = os.environ.get(f"BFP_{role.upper()}_KNOWN_HOSTS", "").strip()
        pin_file = pathlib.Path(pin_override) if pin_override else SERVER_WORKSPACE / "latency-plan-24" / pin_name
        endpoints[role] = (hostname, int(port_value), pin_file)
    inventory = _find_inventory(SERVER_WORKSPACE) if inventory is None else inventory
    found: dict[str, list[tuple[int, list[str]]]] = {role: [] for role in endpoints}
    # Do not preserve or expose notes/other rows. Never return the source line.
    with pathlib.Path(inventory).open(encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.startswith("|"):
                continue
            columns = line.split("|")
            if len(columns) < 6:
                continue
            address = columns[2].strip().strip("`")
            for role, (hostname, port, _) in endpoints.items():
                if address not in (hostname, f"{hostname}:{port}"):
                    continue
                # Copy only the SSH username/password columns, not notes.
                found[role].append((line_number, [columns[3], columns[4]]))
    hosts = {}
    for role, rows in found.items():
        if len(rows) != 1:
            raise LabError(f"{role}: expected exactly one current inventory row; found {len(rows)}")
        hostname, port, pin_file = endpoints[role]
        line_number, columns = rows[0]
        username, password = [value.strip().strip("`") for value in columns]
        SANITIZER.add(password)
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_.-]*", username) or not password:
            raise LabError(f"{role}: unsupported SSH credential structure")
        hosts[role] = Host(role, hostname, port, username, password, pin_file, line_number)
    return hosts


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def expected_keys(host: Host):
    if not host.pin_file.is_file():
        raise LabError(f"{host.role}: verified known_hosts file not found")
    keys = paramiko.HostKeys(str(host.pin_file)).lookup(host.lookup)
    if not keys:
        raise LabError(f"{host.role}: no existing pin for authorized endpoint")
    return {kind: fingerprint(key) for kind, key in keys.items()}


def discover_key(host: Host):
    """Unauthenticated fingerprint discovery; does not trust or persist a key."""
    transport = None
    connection = socket.create_connection((host.hostname, host.port), timeout=10)
    try:
        transport = paramiko.Transport(connection)
        transport.start_client(timeout=10)
        key = transport.get_remote_server_key()
        return {"type": key.get_name(), "sha256": fingerprint(key), "trusted": False, "authenticated": False}
    finally:
        if transport:
            transport.close()
        else:
            connection.close()


class Remote:
    def __init__(self, host: Host):
        self.host = host
        self.client: paramiko.SSHClient | None = None

    def connect(self, sock=None):
        expected_keys(self.host)  # Missing pins fail before credential use.
        client = paramiko.SSHClient()
        client.load_host_keys(str(self.host.pin_file))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(self.host.hostname, port=self.host.port, username=self.host.username, password=self.host.password, look_for_keys=False, allow_agent=False, timeout=12, auth_timeout=12, banner_timeout=12, sock=sock)
        except Exception:
            client.close()
            raise
        self.client = client
        self.client.get_transport().set_keepalive(15)
        return self

    def close(self):
        if self.client:
            self.client.close()
            self.client = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *_):
        self.close()

    def execute(self, command: str, timeout=30, max_output=262144):
        if not self.client:
            raise LabError("SSH session is not connected")
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        stdin.close()
        channel = stdout.channel
        out, err = bytearray(), bytearray()
        deadline = time.monotonic() + timeout
        while not channel.exit_status_ready() or channel.recv_ready() or channel.recv_stderr_ready():
            if time.monotonic() >= deadline:
                channel.close()
                raise LabError(f"{self.host.role}: bounded remote command timed out")
            if channel.recv_ready():
                chunk = channel.recv(32768)
                if len(out)+len(chunk) > max_output:
                    channel.close()
                    raise LabError(f"{self.host.role}: remote stdout limit exceeded")
                out.extend(chunk)
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(32768)
                if len(err)+len(chunk) > max_output:
                    channel.close()
                    raise LabError(f"{self.host.role}: remote stderr limit exceeded")
                err.extend(chunk)
            time.sleep(.01)
        return {"exit_code": channel.recv_exit_status(), "stdout": SANITIZER.text(out.decode("utf-8", "replace")), "stderr": SANITIZER.text(err.decode("utf-8", "replace"))}

    def python(self, source: str, timeout=30):
        encoded = base64.b64encode(source.encode()).decode()
        command = "python3 -c " + shlex.quote("import base64;exec(compile(base64.b64decode(" + repr(encoded) + "),'<bfp-owned-lab>','exec'))")
        result = self.execute(command, timeout)
        if result["exit_code"]:
            raise LabError(f"{self.host.role}: remote helper failed: {result['stderr'][:2048]}")
        try:
            return SANITIZER.obj(json.loads(result["stdout"]))
        except json.JSONDecodeError:
            raise LabError(f"{self.host.role}: remote helper returned non-JSON output") from None

    def snapshot(self):
        value = self.python(SNAPSHOT, timeout=35)
        key = self.client.get_transport().get_remote_server_key()
        return {**self.host.public(), "host_key_verified": True, "host_key_type": key.get_name(), "host_key_sha256": fingerprint(key), "snapshot": value}


SNAPSHOT = r'''
import os,json,subprocess,shutil,time,hashlib
def run(argv):
    try:
        p=subprocess.run(argv,capture_output=True,text=True,timeout=5)
        return {"code":p.returncode,"stdout":p.stdout[:65536]}
    except (OSError,subprocess.TimeoutExpired) as e:
        return {"code":-1,"error":type(e).__name__}
def iptables_summary(argv):
    r=run(argv)
    if r["code"]: return {"available":False,"code":r["code"]}
    lines=r.get("stdout","").splitlines()
    return {"available":True,"policies":[l for l in lines if l.startswith("-P ")],"chain_count":sum(l.startswith("-N ") for l in lines),"rule_count":sum(l.startswith("-A ") for l in lines),"configuration_sha256":hashlib.sha256(r['stdout'].encode()).hexdigest()}
mem={}
for l in open('/proc/meminfo'):
    k,v=l.split(':',1)
    if k in ('MemTotal','MemAvailable','SwapTotal','SwapFree'): mem[k+"_KiB"]=int(v.strip().split()[0])
os_release={}
for l in open('/etc/os-release'):
    if l.startswith(('ID=','VERSION_ID=','PRETTY_NAME=')):
        k,v=l.strip().split('=',1);os_release[k]=v.strip('"')
listeners=run(['ss','-H','-lntup'])
containers=run(['docker','ps','--format','{{json .}}'])
container_rows=[]
if containers['code']==0:
    for l in containers['stdout'].splitlines():
        try:
            d=json.loads(l);container_rows.append({k:d.get(k) for k in ('ID','Names','Image','State','Status','Ports')})
        except ValueError:pass
routes=run(['ip','-j','route','show','table','main'])
default_routes=[]
if routes['code']==0:
    try:default_routes=[{k:r.get(k) for k in ('dst','gateway','dev','prefsrc','metric') if k in r} for r in json.loads(routes['stdout']) if r.get('dst')=='default']
    except ValueError:pass
fs=shutil.disk_usage('/tmp')
sudo=run(['sudo','-n','true']) if os.geteuid()!=0 else {"code":0}
prefix=['sudo','-n'] if os.geteuid()!=0 and sudo['code']==0 else []
firewall=iptables_summary(prefix+['iptables','-S'])
nft=run(prefix+['nft','-j','list','ruleset'])
nft_summary={"available":nft['code']==0,"code":nft['code']}
if nft['code']==0:
    try:
        entries=json.loads(nft['stdout']).get('nftables',[])
        nft_summary.update({"table_count":sum('table' in x for x in entries),"chain_count":sum('chain' in x for x in entries),"rule_count":sum('rule' in x for x in entries)})
        def stable(x):
            if isinstance(x,dict):return {k:stable(v) for k,v in x.items() if k not in ('packets','bytes','handle')}
            if isinstance(x,list):return [stable(v) for v in x]
            return x
        nft_summary['configuration_sha256']=hashlib.sha256(json.dumps(stable(entries),sort_keys=True,separators=(',',':')).encode()).hexdigest()
    except ValueError:nft_summary['parseable']=False
print(json.dumps({"time_unix":time.time(),"os":os_release,"kernel":os.uname().release,"arch":os.uname().machine,"cpu_count":os.cpu_count(),"memory":mem,"tmp_free_bytes":fs.free,"effective_uid":os.geteuid(),"sudo_noninteractive":sudo['code']==0,"loadavg":list(os.getloadavg()),"listeners":listeners.get('stdout','').splitlines(),"listener_exit":listeners['code'],"containers":container_rows,"docker_exit":containers['code'],"default_routes":default_routes,"firewall":firewall,"nft":nft_summary,"python3":True,"process_count":sum(n.isdigit() for n in os.listdir('/proc'))}))
'''


def new_run_id():
    return secrets.token_hex(16)


def owned_dir(run_id: str):
    if not RUN_ID.fullmatch(run_id):
        raise LabError("invalid run ID")
    return f"/tmp/bfp-lab-{run_id}"


def file_name(name: str):
    if not FILE_NAME.fullmatch(name) or name in (".", ".."):
        raise LabError("invalid owned artifact name")
    return name


class RemoteRun:
    """A single host's exact run directory, never a service installation.

    create() refuses existing directories. Process manifests bind PID, Linux
    starttime, exact executable path and command digest before cleanup signals.
    """
    def __init__(self, remote: Remote, run_id: str):
        self.remote = remote
        self.run_id = run_id
        self.directory = owned_dir(run_id)

    def _check(self):
        return """import os,json,pathlib\np=pathlib.Path(%r)\nrid=%r\nif p.is_symlink() or str(p.resolve())!=str(p):raise RuntimeError('unsafe run directory')\nm=json.loads((p/'owner.json').read_text())\nif m.get('run_id')!=rid or m.get('host')!=%r:raise RuntimeError('run owner mismatch')\n""" % (self.directory, self.run_id, self.remote.host.hostname)

    def create(self):
        result = self.remote.python("import pathlib,os,json\np=pathlib.Path(%r)\np.mkdir(mode=0o700)\nos.chmod(p,0o700)\nf=p/'owner.json'\nfd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\nwith os.fdopen(fd,'w') as stream:json.dump({'run_id':%r,'host':%r},stream)\nprint(json.dumps({'directory':str(p),'mode':oct(p.stat().st_mode&0o777),'created':True}))\n" % (self.directory, self.run_id, self.remote.host.hostname))
        return result

    def write(self, name: str, data: bytes, mode=0o600):
        name = file_name(name)
        if mode not in (0o600, 0o700):
            raise LabError("owned files require 0600 or 0700")
        self.remote.python(self._check() + "print(json.dumps({'owner_verified':True}))")
        sftp = self.remote.client.open_sftp()
        sftp.get_channel().settimeout(30)
        try:
            dest = self.directory + "/" + name
            # Directory 0700 protects the file before chmod; no public temp path.
            with sftp.open(dest, "wx") as stream:
                sftp.chmod(dest, mode)
                # Drain after each bounded 256 KiB pipeline. The first 32 KiB
                # non-pipelined write drains outstanding responses from the
                # previous chunk and prevents unbounded queued SSH requests.
                for offset in range(0, len(data), 256*1024):
                    chunk = data[offset:offset+256*1024]
                    stream.set_pipelined(False)
                    stream.write(chunk[:32768])
                    stream.set_pipelined(True)
                    stream.write(chunk[32768:])
            return {"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mode": oct(mode)}
        finally:
            sftp.close()

    def upload_binary(self, local_path, name="bfp"):
        data = pathlib.Path(local_path).read_bytes()
        if data[:4] != b"\x7fELF":
            raise LabError("remote binary must be Linux ELF")
        report = self.write(name, data, 0o700)
        remote_digest = self.remote.python(self._check()+"import hashlib\nf=p/%r\nprint(json.dumps({'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}))" % file_name(name))
        if remote_digest['sha256'] != report['sha256']:
            raise LabError("uploaded binary hash mismatch")
        return report

    def config(self, name: str, value: dict):
        SANITIZER.config(value)
        return self.write(name, json.dumps(value, separators=(",", ":")).encode(), 0o600)

    def start(self, args: list[str], name="server", binary="bfp"):
        name, binary = file_name(name), file_name(binary)
        if any(not isinstance(arg, str) or "\0" in arg for arg in args):
            raise LabError("invalid process arguments")
        source = self._check()+r'''
import subprocess,hashlib,time
name=%r
argv=[str(p/%r)]+%r
manifest=p/(name+'.process.json')
if manifest.exists():raise RuntimeError('process name already used')
fd=os.open(p/(name+'.log'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as log:
    proc=subprocess.Popen(argv,cwd=str(p),stdout=log,stderr=subprocess.STDOUT,start_new_session=True,stdin=subprocess.DEVNULL)
time.sleep(.2)
if proc.poll() is not None:raise RuntimeError('owned process exited during startup; collect its sanitized log')
pid=proc.pid
start=pathlib.Path('/proc/%%d/stat'%%pid).read_text().rsplit(')',1)[1].split()[19]
cmd=pathlib.Path('/proc/%%d/cmdline'%%pid).read_bytes()
record={'run_id':rid,'pid':pid,'starttime':start,'command_sha256':hashlib.sha256(cmd).hexdigest(),'exe':str(p/%r)}
fd=os.open(manifest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as stream:json.dump(record,stream)
print(json.dumps({'name':name,'pid':pid,'running':True}))
''' % (name, binary, args, binary)
        return self.remote.python(source)

    def read(self, name: str, limit=1048576):
        name = file_name(name)
        self.remote.python(self._check()+"print(json.dumps({'owner_verified':True}))")
        sftp = self.remote.client.open_sftp()
        sftp.get_channel().settimeout(30)
        try:
            with sftp.open(self.directory+"/"+name, "rb") as file:
                data = file.read(limit+1)
            if len(data) > limit:
                raise LabError("owned artifact exceeds collection budget")
            return SANITIZER.text(data.decode("utf-8", "replace"))
        finally:
            sftp.close()

    def cleanup(self):
        source = self._check()+r'''
import signal,time,hashlib,shutil,subprocess
reports=[]
containers=[]
for marker in p.glob('*.container.json'):
    m=json.loads(marker.read_text())
    if m.get('run_id')!=rid or m.get('name')!='bfp-race-'+rid:raise RuntimeError('container manifest owner mismatch')
    name=m['name']
    inspect=subprocess.run(['docker','inspect',name],capture_output=True,text=True,timeout=5)
    if inspect.returncode==0:
        entries=json.loads(inspect.stdout)
        if len(entries)!=1:raise RuntimeError('container inspection mismatch')
        data=entries[0]
        if data.get('Config',{}).get('Labels',{}).get('bfp.run')!=rid:raise RuntimeError('container label owner mismatch')
        for mount in data.get('Mounts',[]):
            if mount.get('Type')=='bind' and not pathlib.Path(mount.get('Source','')).is_relative_to(p):raise RuntimeError('container mount owner mismatch')
        stop=subprocess.run(['docker','rm','-f',name],capture_output=True,text=True,timeout=10)
        if stop.returncode:raise RuntimeError('owned container cleanup failed')
    containers.append({'name':name,'removed':True})
def match(m):
    proc=pathlib.Path('/proc')/str(m['pid'])
    try:
        start=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
        cmd=(proc/'cmdline').read_bytes()
        exe=str((proc/'exe').resolve())
        return start==m['starttime'] and hashlib.sha256(cmd).hexdigest()==m['command_sha256'] and exe==m['exe'] and pathlib.Path(exe).parent==p and os.getpgid(m['pid'])==m['pid']
    except (OSError,ProcessLookupError):return False
for f in p.glob('*.process.json'):
    m=json.loads(f.read_text())
    if m.get('run_id')!=rid:raise RuntimeError('process manifest owner mismatch')
    pid=m['pid']
    exists=pathlib.Path('/proc')/str(pid)
    if exists.exists() and not match(m):raise RuntimeError('PID ownership mismatch; cleanup refused')
    if match(m):
        os.killpg(pid,signal.SIGTERM)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and match(m):time.sleep(.05)
        if match(m):os.killpg(pid,signal.SIGKILL)
        deadline=time.monotonic()+2
        while time.monotonic()<deadline and match(m):time.sleep(.05)
        if match(m):raise RuntimeError('owned process did not stop')
    reports.append({'pid':pid,'stopped':True})
shutil.rmtree(p)
print(json.dumps({'run_id':rid,'directory_removed':not p.exists(),'processes':reports,'containers':containers}))
'''
        return self.remote.python(source, timeout=25)


def write_public(path, obj):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(SANITIZER.obj(obj), ensure_ascii=False, indent=2)+"\n", encoding="utf-8")


def compare_snapshots(before, after):
    """Compare existing services/configuration, excluding uptime and RSS noise.

    Container identity, image, ports and listener endpoints must stay stable;
    process counters/load/memory are observations, not equality requirements.
    """
    def split_listeners(snapshot):
        """Separate exact listeners from observed ephemeral UDP sockets.

        A bounded Linux run can create short-lived unconnected UDP sockets in
        the kernel ephemeral range. They are retained in the report for audit,
        while TCP listeners and well-known UDP ports remain exact checks.
        """
        listeners = [re.sub(r"users:.*$", "", line).strip() for line in snapshot.get('listeners', [])]
        stable, dynamic_udp = [], []
        for line in listeners:
            if line.startswith("udp "):
                match = re.search(r"(?::|])(\d+)\s+\S+\s*$", line)
                # These are known fixed listeners on the receiver; a change
                # to one must remain visible even though it is numerically in
                # the ephemeral range.
                if match and int(match.group(1)) >= 32768 and int(match.group(1)) not in {41641}:
                    dynamic_udp.append(line)
                    continue
            stable.append(line)
        return sorted(stable), sorted(dynamic_udp)

    def stable(snapshot):
        if 'snapshot' in snapshot:
            snapshot = snapshot['snapshot']
        listeners, dynamic_udp = split_listeners(snapshot)
        containers = sorted((row.get('ID'), row.get('Names'), row.get('Image'), row.get('State'), row.get('Ports')) for row in snapshot.get('containers', []))
        return {'listeners': listeners, 'containers': containers, 'default_routes': snapshot.get('default_routes', []), 'firewall': snapshot.get('firewall', {}), 'nft': snapshot.get('nft', {})}, dynamic_udp
    left, left_dynamic = stable(before)
    right, right_dynamic = stable(after)
    changes = {key: {'before': left[key], 'after': right[key]} for key in left if left[key] != right[key]}
    return {'unchanged': not changes, 'changes': changes, 'dynamic_udp_listeners': {'ignored': True, 'before': left_dynamic, 'after': right_dynamic}}


def prepare(output=None):
    hosts = load_hosts()
    run_id = new_run_id()
    result = {"run_id": run_id, "time_utc": datetime.now(timezone.utc).isoformat(), "read_only": True, "remote_directory": owned_dir(run_id), "remote_directory_created": False, "hosts": {}}
    def probe(host):
        try:
            with Remote(host) as remote:
                return remote.snapshot()
        except Exception as error:
            return {**host.public(), "host_key_verified": False, "error_type": type(error).__name__, "error": SANITIZER.text(str(error))[:2048]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = {pool.submit(probe, host): role for role, host in hosts.items()}
        for future in concurrent.futures.as_completed(futures):
            result['hosts'][futures[future]] = future.result()
    result['prepared'] = all(item.get('host_key_verified') and item.get('snapshot',{}).get('python3') for item in result['hosts'].values())
    output = pathlib.Path(output or WORKSPACE/'lab'/'runs'/run_id/'prepared.json')
    write_public(output, result)
    return {"run_id":run_id,"prepared":result['prepared'],"path":str(output),"hosts":[{"role":role,"host_key_verified":entry.get('host_key_verified'),"arch":entry.get('snapshot',{}).get('arch'),"cpu_count":entry.get('snapshot',{}).get('cpu_count'),"error_type":entry.get('error_type')} for role,entry in result['hosts'].items()]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['prepare'])
    parser.add_argument('--output')
    args=parser.parse_args()
    try:
        print(json.dumps(prepare(args.output),ensure_ascii=False))
    except Exception as error:
        print(json.dumps({"ok":False,"error_type":type(error).__name__,"error":SANITIZER.text(str(error))[:2048]},ensure_ascii=False))
        raise SystemExit(1) from None


if __name__=='__main__':
    main()
