"""One source-bound, explicit phase-budget WAN experiment; no retries."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".staging/r9-next19"
OUT = STAGE / "verification/r9-next19"
INVENTORY = Path(r"C:\Users\developer\Desktop\cold\servers-unredacted.md")
sys.path.insert(0, str(ROOT / "lab"))
import remote
import wan


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--race-result", required=True)
    args = parser.parse_args()
    gate = read(OUT / "local-gate-attempt01/local-summary.json")
    frozen = read(OUT / "local-gate-attempt01/source-manifest.json")
    race = read(args.race_result)
    if not gate.get("local_checks_pass") or not gate.get("source_unchanged"):
        raise RuntimeError("next19 complete source-bound local gate required")
    rows = [{"path": r["path"], "sha256": r["sha256"]} for r in race["source_manifest"]]
    binary_info = next(b for b in gate["binaries"] if b["platform"] == "linux")
    binary = ROOT / binary_info["path"]
    live_matches = all(hashlib.sha256((STAGE / r["path"]).read_bytes()).hexdigest() == r["sha256"]
                       for r in frozen["source_manifest"])
    binary_matches = hashlib.sha256(binary.read_bytes()).hexdigest() == binary_info["sha256"]
    if not (race.get("pass") and rows == frozen["source_manifest"] and live_matches
            and binary_matches and race["related_binary_sha256"] == binary_info["sha256"]):
        raise RuntimeError("next19 source/binary/race binding mismatch")

    remote.WORKSPACE = wan.WORKSPACE = STAGE
    remote.INVENTORY = INVENTORY
    wan.load_hosts = lambda: remote.load_hosts(inventory=INVENTORY)
    original_run = wan.RemoteRun

    class PhaseRun(original_run):
        def start(self, arguments, name="server", binary="bfp"):
            arguments = list(arguments)
            if arguments and arguments[0] == "probe":
                arguments.extend(["-setup-duration", "8s"])
            return super().start(arguments, name=name, binary=binary)

    wan.RemoteRun = PhaseRun
    contract = {
        "revision": "v0.1-r9-next19",
        "source_manifest_sha256": frozen["manifest_sha256"],
        "linux_binary_sha256": binary_info["sha256"],
        "race_run_id": race["run_id"],
        "experiment": "new explicit phase-budget experiment; not the old 20s total-budget gate",
        "probe_count": 12, "tcp_bytes_each": 1024, "interval": "1s",
        "setup_duration": "8s", "business_duration": "30s",
        "tcp_operation_max": "8s", "udp_operation_max": "1s",
        "single_udp_send_each": True, "ticket_lifecycle": False, "fec_policy": "off",
        "automatic_retry": False, "uploads": "one binary upload per endpoint; sequential",
        "original_next18_wan": "9c596cee534aab23b53d1e194e8f7696 strict FAIL preserved",
        "runner_fingerprints": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (Path(__file__), ROOT / "lab/wan.py", ROOT / "lab/remote.py")
        },
    }
    with (OUT / "wan-experiment-contract.json").open("x", encoding="utf-8") as stream:
        json.dump(contract, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"stage": "dispatch", "setup_duration": "8s", "business_duration": "30s",
                      "count": 12, "size": 1024, "retry": False}), flush=True)
    with (OUT / "wan-dispatch.log").open("x", encoding="utf-8") as log:
        with contextlib.redirect_stdout(log):
            report, path = wan.run_wan(str(binary), 12, 1024, "1s", "30s")
    phase_match = len(report["scenarios"]) == 3 and all(
        s.get("result", {}).get("budget_mode") == "separate_setup"
        and s.get("result", {}).get("duration_ms") == 30000
        and s.get("result", {}).get("setup_duration_ms") == 8000
        for s in report["scenarios"].values()
    )
    binding = {**contract, "run_id": report["run_id"], "raw_result": str(path),
               "raw_result_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
               "phase_contract_matches_results": phase_match,
               "strict_experiment_pass": report.get("pass") is True and phase_match,
               "acceptance_complete": False, "production_ready": False, "released": False}
    with (path.parent / "next19-experiment-binding.json").open("x", encoding="utf-8") as stream:
        json.dump(binding, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"run_id": report["run_id"], "pass": binding["strict_experiment_pass"],
                      "path": str(path), "phase_match": phase_match,
                      "scenarios": {n: {"pass": s.get("pass"),
                                        "tcp": s.get("result", {}).get("tcp_completed"),
                                        "udp": s.get("result", {}).get("udp_completed"),
                                        "failure_phase": s.get("result", {}).get("failure_phase")}
                                    for n, s in report["scenarios"].items()},
                      "error_type": report.get("error_type")}), flush=True)
    return 0 if binding["strict_experiment_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
