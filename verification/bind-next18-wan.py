"""Bind the bounded next18 WAN sample without rewriting strict failures."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".staging/r9-next18"
INDEX = STAGE / "verification/r9-next18/evidence-index-attempt03.json"
RUN_ID = "9c596cee534aab23b53d1e194e8f7696"
RESULT = ROOT / "lab/runs" / RUN_ID / "wan-result.json"
BINARY = STAGE / "verification/r9-next18/local-gate-attempt03/bfp-linux-amd64"


def main():
    index = json.loads(INDEX.read_text(encoding="utf-8"))
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    local = json.loads((STAGE / "verification/r9-next18/local-gate-attempt03/local-summary.json").read_text(encoding="utf-8"))
    local_hash = next(row["sha256"] for row in local["binaries"] if row["platform"] == "linux")
    binary_hash = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    if result["binary_sha256"] != binary_hash or binary_hash != local_hash:
        raise RuntimeError("WAN binary does not match next18 attempt03 local Linux build")
    scenarios = {}
    for name, value in result.get("scenarios", {}).items():
        probe = value.get("result", {})
        scenarios[name] = {
            "pass": value.get("pass"),
            "probe_count": value.get("probe_count"),
            "probe_bytes": value.get("probe_bytes"),
            "udp_completed": probe.get("udp_completed"),
            "udp_failed": probe.get("udp_failed"),
            "tcp_completed": probe.get("tcp_completed"),
            "same_session": probe.get("same_session"),
            "initial_carrier": probe.get("initial", {}).get("carrier"),
            "final_carrier": probe.get("final", {}).get("carrier"),
            "generation": probe.get("final", {}).get("generation"),
            "switches": probe.get("final", {}).get("switches"),
            "carrier_expectation_met": value.get("carrier_expectation_met"),
            "one_target_connection": value.get("one_target_connection"),
            "failure": probe.get("failure", ""),
        }
    index["wan"] = {
        "status": "strict_fail",
        "run_id": RUN_ID,
        "path": str(RESULT.resolve()),
        "binary_sha256": result["binary_sha256"],
        "binary_matches_next18_attempt03_local_linux": result["binary_sha256"] == local_hash,
        "roles": {"sender": "Singapore 198.51.100.20", "receiver_exit_test": "Los Angeles 192.0.2.10"},
        "scope": "one small bounded sample; Singapore sends 12 x 1 KiB at 1 s interval; no FEC policy enabled",
        "scenarios": scenarios,
        "random_probe_pass": result.get("random_probe", {}).get("pass"),
        "cleanup": {role: value.get("directory_removed") for role, value in result.get("cleanup", {}).items()},
        "snapshot_unchanged": {role: value.get("comparison", {}).get("unchanged") for role, value in result.get("snapshots", {}).items()},
        "strict_gate_reason": "normal_udp completed 12/12; udp_to_tcp and initial_udp_blocked each completed 11/12 and hit the probe deadline; preserve both failures",
        "singapore_transfer_or_business": "one binary upload and one bounded three-scenario sample",
    }
    INDEX.write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(index["wan"], ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
