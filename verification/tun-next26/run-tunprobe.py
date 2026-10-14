"""Run the self-contained TUN probe in one owned, network-none container."""
from __future__ import annotations

import json
import pathlib
import shlex
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lab"))
import remote  # noqa: E402


def main() -> None:
    hosts = remote.load_hosts(inventory=pathlib.Path(r"C:\Users\developer\Desktop\cold\servers-unredacted.md"))
    host = hosts["receiver"]
    binary = ROOT / "verification" / "tun-next26" / "tunprobe-linux-amd64"
    if not binary.is_file():
        binary = ROOT / "verification" / "tun-next26" / "tunprobe-linux-amd64.exe"
    data = binary.read_bytes()
    run_id = remote.new_run_id()
    report = {"run_id": run_id, "role": "receiver", "image": "ded31c68586d"}
    with remote.Remote(host) as conn:
        before = conn.snapshot()
        run = remote.RemoteRun(conn, run_id)
        run.create()
        try:
            uploaded = run.write("tunprobe", data, 0o700)
            command = run._check() + r'''
import json,subprocess
argv=['docker','run','--rm','--pull=never','--network','none','--name','bfp-tunprobe-'+rid,
      '--label','bfp.run='+rid,'--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','NET_RAW',
      '--security-opt','no-new-privileges','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=16m',
      '--device','/dev/net/tun:/dev/net/tun:rwm','-v',str(p)+':/bfp:ro','ded31c68586d','/bfp/tunprobe']
r=subprocess.run(argv,capture_output=True,text=True,timeout=30)
print(json.dumps({'upload':%r,'exit_code':r.returncode,'stdout':r.stdout[:4096],'stderr':r.stderr[:4096]}))
''' % ({"bytes": len(data), "sha256": uploaded["sha256"]},)
            result = conn.python(command, timeout=40)
            report["probe"] = result
        finally:
            report["cleanup"] = run.cleanup()
        after = conn.snapshot()
    report["snapshot_comparison"] = remote.compare_snapshots(before, after)
    report["pass"] = bool(report.get("probe", {}).get("exit_code") == 0 and report.get("snapshot_comparison", {}).get("unchanged"))
    path = ROOT / "verification" / "tun-next26" / "tun-probe.json"
    remote.write_public(path, report)
    print(json.dumps({"pass": report["pass"], "artifact": str(path), "probe_exit": report.get("probe", {}).get("exit_code")}))


if __name__ == "__main__":
    main()
