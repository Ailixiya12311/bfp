"""Upload the exact release to LA and exercise it in an owned Docker netns."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lab"))
import remote


def upload_compressed(owned, path, name):
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or len(data) > 64 * 1024 * 1024:
        raise RuntimeError("invalid packaged Linux program")
    digest = hashlib.sha256(data).hexdigest()
    # Cache only content-addressed public programs, never keys or configs.
    cache_setup = r'''
import hashlib,shutil
cache=pathlib.Path('/tmp/bfp-native-payload-cache')
if cache.is_symlink() or str(cache.resolve())!='/tmp/bfp-native-payload-cache':raise RuntimeError('unsafe program cache')
if not cache.exists():
    cache.mkdir(mode=0o700)
    fd=os.open(cache/'owner.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as output:json.dump({'purpose':'bfp-native-public-programs','uid':os.getuid()},output)
marker=json.loads((cache/'owner.json').read_text())
if marker!={'purpose':'bfp-native-public-programs','uid':os.getuid()} or cache.stat().st_uid!=os.getuid() or cache.stat().st_mode&0o777!=0o700:raise RuntimeError('program cache ownership mismatch')
'''
    cached = owned.remote.python(owned._check() + cache_setup + "name=%r\ndigest=%r\nf=cache/digest\nhit=f.is_file()\nif hit:\n    if f.is_symlink() or hashlib.sha256(f.read_bytes()).hexdigest()!=digest:raise RuntimeError('cached program mismatch')\n    fd=os.open(p/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o700)\n    with os.fdopen(fd,'wb') as output:output.write(f.read_bytes())\nprint(json.dumps({'hit':hit}))\n" % (name, digest))
    if cached["hit"]:
        return {"name": name, "bytes": len(data), "sha256": digest, "mode": "0o700", "transfer_bytes": 0, "cache_hit": True}
    uploaded = owned.write(name + ".gz", gzip.compress(data, compresslevel=6, mtime=0))
    verified = owned.remote.python(owned._check() + "import gzip,hashlib\nname=%r\nraw=gzip.decompress((p/(name+'.gz')).read_bytes())\nif len(raw)>67108864 or raw[:4]!=b'\\x7fELF' or hashlib.sha256(raw).hexdigest()!=%r:raise RuntimeError('program hash mismatch')\nfd=os.open(p/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o700)\nwith os.fdopen(fd,'wb') as output:output.write(raw)\n(p/(name+'.gz')).unlink()\nprint(json.dumps({'name':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'mode':'0o700'}))\n" % (name, digest))
    owned.remote.python(owned._check() + cache_setup + "digest=%r\nraw=(p/%r).read_bytes()\nif hashlib.sha256(raw).hexdigest()!=digest:raise RuntimeError('cache input mismatch')\nf=cache/digest\ntry:\n    fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o700)\n    with os.fdopen(fd,'wb') as output:output.write(raw)\nexcept FileExistsError:\n    if f.is_symlink() or hashlib.sha256(f.read_bytes()).hexdigest()!=digest:raise RuntimeError('cache conflict')\nprint(json.dumps({'cached':True}))\n" % (digest, name))
    return {**verified, "transfer_bytes": uploaded["bytes"], "transfer_sha256": uploaded["sha256"], "cache_hit": False}


def run(package, image, scope="full"):
    package = pathlib.Path(package).resolve(strict=True)
    work = ROOT / "verification/product-mihomo"
    run_id = remote.new_run_id()
    evidence = work / "runs" / run_id
    evidence.mkdir(parents=True)
    inputs = {
        "bfp": package / "bin/bfp-linux-amd64",
        "mihomo": package / "bin/mihomo-bfp-linux-amd64",
        "native-proxy.yaml": package / "configs/native-proxy.yaml",
        "native-tun.yaml": package / "configs/native-tun.yaml",
        "start-native.sh": package / "start-native.sh",
        "runtime_smoke.py": work / "runtime_smoke.py",
        "container_runtime.py": work / "container_runtime.py",
        "launcher_faults.py": work / "launcher_faults.py",
        "launcher_auto_routes.py": work / "launcher_auto_routes.py",
        "tun_probe.py": work / "tun_probe.py",
        "tun_harness.py": ROOT / "verification/tun-next26/tun_harness.py",
    }
    manifest = json.loads((package / "release-manifest.json").read_text(encoding="utf-8"))
    expected = {v["path"]: v["sha256"] for v in manifest["files"]}
    for name in ("bfp", "mihomo", "native-proxy.yaml", "native-tun.yaml", "start-native.sh"):
        path = inputs[name]
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected[path.relative_to(package).as_posix()]:
            raise RuntimeError("release payload mismatch")
    report = {"run_id": run_id, "package": str(package), "version": manifest["version"], "image": image, "scope": scope,
              "pass": False, "singapore_traffic": False, "input_hashes": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in inputs.items()}}
    helper_bytes = {name: path.read_bytes() for name, path in inputs.items() if name.endswith(".py")}
    for name, data in helper_bytes.items():
        if hashlib.sha256(data).hexdigest() != report["input_hashes"][name]:
            raise RuntimeError("helper changed while freezing inputs")
        (evidence / name).write_bytes(data)
    hosts = remote.load_hosts(inventory=pathlib.Path(r"C:\Users\developer\Desktop\cold\servers-unredacted.md"))
    with remote.Remote(hosts["receiver"]) as conn:
        report["before"] = conn.snapshot()
        owned = remote.RemoteRun(conn, run_id)
        report["created"] = owned.create()
        try:
            print(json.dumps({"stage": "uploading", "run_id": run_id}), flush=True)
            report["uploads"] = {}
            for name, path in inputs.items():
                if name in ("bfp", "mihomo"):
                    report["uploads"][name] = upload_compressed(owned, path, name)
                else:
                    report["uploads"][name] = owned.write(name, helper_bytes[name] if name in helper_bytes else path.read_bytes())
                print(json.dumps({"stage": "uploaded", "name": name, "bytes": report["uploads"][name]["bytes"]}), flush=True)
            conn.python(owned._check() + r'''
(p/'configs').mkdir(mode=0o700)
(p/'evidence').mkdir(mode=0o700)
for name in ('native-proxy.yaml','native-tun.yaml'):
    (p/name).rename(p/'configs'/name)
print(json.dumps({'prepared':True}))
''')
            # The cleanup API requires this exact name and verifies its label
            # and all bind mounts before stopping a container after a failure.
            owned.write("runtime.container.json", json.dumps({"run_id": run_id, "name": "bfp-race-" + run_id}).encode())
            print(json.dumps({"stage": "running", "run_id": run_id}), flush=True)
            entrypoint = {"launcher": "launcher_faults.py", "auto-route": "launcher_auto_routes.py", "full": "container_runtime.py"}[scope]
            report["container"] = conn.python(owned._check() + "image=%r\nentrypoint=%r\n" % (image, entrypoint) + r'''
import subprocess
argv=['docker','run','--rm','--pull=never','--network','none','--name','bfp-race-'+rid,
      '--label','bfp.run='+rid,'--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--cap-add','SETUID','--cap-add','SETGID',
      '--security-opt','no-new-privileges','--read-only','--pids-limit','128','--memory','512m','--cpus','0.75',
      '--tmpfs','/tmp:rw,exec,nosuid,size=96m','--device','/dev/net/tun:/dev/net/tun:rwm',
      '--sysctl','net.ipv6.conf.all.disable_ipv6=0','--sysctl','net.ipv6.conf.default.disable_ipv6=0',
      '--sysctl','net.ipv4.conf.all.accept_local=1','--sysctl','net.ipv4.conf.default.accept_local=1',
      '--sysctl','net.ipv4.conf.all.rp_filter=0','--sysctl','net.ipv4.conf.default.rp_filter=0',
      '--add-host','bfp-v4.test:192.0.2.10','--add-host','bfp-v6.test:fd77:25::10',
      '-v',str(p)+':/bfp:ro','-v',str(p/'evidence')+':/evidence:rw',image,
      'python3','/bfp/'+entrypoint]
try:
    result=subprocess.run(argv,capture_output=True,text=True,timeout=150)
    print(json.dumps({'exit_code':result.returncode,'stdout':result.stdout[-10000:],'stderr':result.stderr[-4096:]}))
except subprocess.TimeoutExpired:
    print(json.dumps({'timeout':True,'pass':False}))
''', timeout=175)
            sftp = conn.client.open_sftp()
            sftp.get_channel().settimeout(30)
            try:
                for name in sftp.listdir(owned.directory + "/evidence"):
                    if name not in {"result.json", "echo.jsonl", "dns.jsonl", "tun.pcap", "lo.pcap"}:
                        raise RuntimeError("unexpected evidence file")
                    sftp.get(owned.directory + "/evidence/" + name, str(evidence / name))
            finally:
                sftp.close()
            if (evidence / "result.json").is_file():
                business = json.loads((evidence / "result.json").read_text(encoding="utf-8"))
                report["business"] = remote.SANITIZER.obj(business)
                remote.write_public(evidence / "result.json", business)
        except Exception as exc:
            report["error"] = type(exc).__name__ + ": " + remote.SANITIZER.text(str(exc))
        finally:
            report["cleanup"] = owned.cleanup()
        report["after"] = conn.snapshot()
    report["snapshot_comparison"] = remote.compare_snapshots(report["before"], report["after"])
    report["pass"] = bool(report.get("business", {}).get("pass") is True and report.get("container", {}).get("exit_code") == 0
                          and report["cleanup"].get("directory_removed") is True and report["snapshot_comparison"].get("unchanged") is True)
    report["evidence_files"] = [{"name": p.name, "bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(evidence.iterdir()) if p.is_file()]
    artifact = evidence / "remote-result.json"
    remote.write_public(artifact, report)
    print(json.dumps({"stage": "finished", "pass": report["pass"], "artifact": str(artifact), "error": report.get("error") or report.get("business", {}).get("error")}), flush=True)
    return report["pass"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True)
    parser.add_argument("--image", default="ded31c68586d")
    parser.add_argument("--scope", choices=("full", "launcher", "auto-route"), default="full")
    args = parser.parse_args()
    raise SystemExit(0 if run(args.package, args.image, args.scope) else 1)
