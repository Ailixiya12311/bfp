"""Run one real Mihomo+BFP TUN TCP/UDP smoke in an owned container."""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lab"))
import remote  # noqa: E402


def main() -> None:
    hosts = remote.load_hosts(inventory=pathlib.Path(r"C:\Users\developer\Desktop\cold\servers-unredacted.md"))
    host = hosts["receiver"]
    paths = {
        "bfp": ROOT / ".staging" / "r9-next25" / "verification" / "r9-next25" / "local-gate-attempt01" / "bfp-linux-amd64",
        "mihomo": ROOT / ".staging" / "mihomo-next26-proxy-graph" / "verification" / "local-attempt03" / "mihomo-next26-with-gvisor-linux-amd64",
        "entrypoint.sh": ROOT / "verification" / "tun-next26" / "entrypoint.sh",
        "dnsfixture.py": ROOT / "verification" / "tun-next26" / "dnsfixture.py",
        "probe.py": ROOT / "verification" / "tun-next26" / "probe.py",
        "mihomo.yaml": ROOT / "verification" / "tun-next26" / "mihomo.yaml",
    }
    run_id = remote.new_run_id()
    report = {"run_id": run_id, "role": "receiver", "image": "ded31c68586d", "source_revision": "r9-next25 BFP + mihomo-next26-proxy-graph local-attempt03 with_gvisor/no_tailscale"}
    with remote.Remote(host) as conn:
        before = conn.snapshot()
        run = remote.RemoteRun(conn, run_id)
        run.create()
        try:
            uploads = {}
            for name, path in paths.items():
                # Keep all uploaded inputs root-owned.  entrypoint.sh reads
                # probe.py before it drops to UID 20001, so the source does
                # not need a wider mode on the read-only bind mount.
                mode = 0o700 if name in ("bfp", "mihomo", "entrypoint.sh") else 0o600
                uploads[name] = run.write(name, path.read_bytes(), mode)
            command = run._check() + r'''
import json,subprocess
argv=['docker','run','--rm','--pull=never','--network','none','--name','bfp-tun-'+rid,
      '--label','bfp.run='+rid,'--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--cap-add','SETUID','--cap-add','SETGID',
      '--security-opt','no-new-privileges','--read-only','--pids-limit','128','--memory','512m','--cpus','0.75',
      '--tmpfs','/tmp:rw,exec,nosuid,size=96m','--device','/dev/net/tun:/dev/net/tun:rwm',
      '--add-host','echo.test:127.0.0.1','-v',str(p)+':/bfp:ro','ded31c68586d','/bin/bash','/bfp/entrypoint.sh']
r=subprocess.run(argv,capture_output=True,text=True,timeout=55)
print(json.dumps({'exit_code':r.returncode,'stdout':r.stdout[-20000:],'stderr':r.stderr[-4096:]}))
'''
            result = conn.python(command, timeout=70)
            report["uploads"] = uploads
            report["container"] = result
        finally:
            report["cleanup"] = run.cleanup()
        after = conn.snapshot()
    report["snapshot_comparison"] = compare_tun_snapshots(before, after)
    container = report.get("container", {})
    stdout = container.get("stdout", "")
    try:
        report["business"] = json.loads(stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        report["business"] = {"parse_error": True, "stdout_tail": stdout[-20000:]}
    business = report.get("business", {})
    probe_log = business.get("probe_log", "")
    server_log = business.get("server_log", "")
    route_evidence = {
        "fake_ip_in_pool": '"fake_ip": "198.18.' in probe_log,
        "server_session_observed": '"sessions":[{' in server_log,
        "tun_started": "Tun adapter listening" in business.get("mihomo_log", ""),
    }
    report["route_evidence"] = route_evidence
    report["pass"] = bool(business.get("pass") is True and all(route_evidence.values()) and report.get("snapshot_comparison", {}).get("unchanged") is True)
    # Keep every attempt independently reviewable and never overwrite the
    # historical fixed artifact from an earlier run.
    path = ROOT / "verification" / "tun-next26" / f"mihomo-tun-smoke-{run_id}.json"
    report["artifact"] = str(path)
    remote.write_public(path, report)
    print(json.dumps({"pass": report["pass"], "artifact": str(path), "container_exit": container.get("exit_code")}))


def _ephemeral_udp_listener(line: str) -> bool:
    """Return true for Linux ephemeral UDP entries known to churn."""
    fields = line.split()
    if len(fields) < 5 or fields[0] != "udp" or fields[1] != "UNCONN":
        return False
    try:
        port = int(fields[4].rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return False
    return port >= 32768


def compare_tun_snapshots(before: dict, after: dict) -> dict:
    """Compare host state while recording only known UDP socket churn.

    The container is ``--network none`` and cannot create a host listener.
    Persistent TCP listeners, containers, routes, firewall and nftables remain
    exact requirements.  High-port UDP entries are the receiver's known
    ephemeral listener noise and are retained in the evidence for review.
    """
    comparison = remote.compare_snapshots(before, after)
    changes = comparison.get("changes", {})
    listener_change = changes.get("listeners")
    if listener_change is None:
        return comparison
    left = listener_change.get("before", [])
    right = listener_change.get("after", [])
    left_stable = [line for line in left if not _ephemeral_udp_listener(line)]
    right_stable = [line for line in right if not _ephemeral_udp_listener(line)]
    if left_stable != right_stable:
        return comparison
    changes.pop("listeners", None)
    comparison["ignored_udp_listener_churn"] = {
        "before": [line for line in left if _ephemeral_udp_listener(line)],
        "after": [line for line in right if _ephemeral_udp_listener(line)],
        "rule": "udp UNCONN endpoint in Linux ephemeral range (port >=32768)",
    }
    comparison["unchanged"] = not changes
    return comparison


if __name__ == "__main__":
    main()
