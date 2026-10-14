"""Bind the single bounded next16 WAN result into the evidence index."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".staging/r9-next16"
INDEX = STAGE / "verification/r9-next16/evidence-index.json"
RUN_ID = "8f71118b9265c444a242f26066c77e43"
RESULT = ROOT / "lab/runs" / RUN_ID / "wan-result.json"
BINARY = STAGE / "bfp-r9-next16-attempt01-linux-amd64"


def main():
    index = json.loads(INDEX.read_text(encoding="utf-8"))
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    local = json.loads((STAGE / "verification/r9-next16/local-gate-attempt01/local-summary.json").read_text(encoding="utf-8"))
    local_hash = next(row["sha256"] for row in local["binaries"] if row["platform"] == "linux")
    binary_hash = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    if result["binary_sha256"] != binary_hash or binary_hash != local_hash:
        raise RuntimeError("WAN binary does not match the next16 local Linux build")
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
            "carrier_expectation_met": value.get("carrier_expectation_met"),
            "one_target_connection": value.get("one_target_connection"),
            "failure": probe.get("failure", ""),
        }
    index["wan"] = {
        "status": "strict_fail",
        "run_id": RUN_ID,
        "path": str(RESULT.resolve()),
        "binary_sha256": result["binary_sha256"],
        "binary_matches_next16_local_linux": result["binary_sha256"] == local_hash,
        "scope": "one small baseline sample; Singapore sends 12 x 1 KiB at 1 s interval, no FEC policy enabled",
        "scenarios": scenarios,
        "random_probe_pass": result.get("random_probe", {}).get("pass"),
        "cleanup": {role: value.get("directory_removed") for role, value in result.get("cleanup", {}).items()},
        "snapshot_unchanged": {role: value.get("comparison", {}).get("unchanged") for role, value in result.get("snapshots", {}).items()},
        "strict_gate_reason": "initial_udp_blocked completed 11/12 UDP operations and hit probe deadline; preserve failure rather than reinterpret the sample",
        "singapore_transfer_or_business": "one binary upload and one bounded three-scenario sample",
    }
    INDEX.write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(index["wan"], ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
