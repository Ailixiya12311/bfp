"""Bind the r9-next17 local gate, bounded fuzz, and Linux race evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".staging/r9-next17"
OUT = STAGE / "verification/r9-next17"
SOURCE_DIRS = (
    "adapter", "classification", "cmd", "gateway", "internal", "obfuscation",
    "protocol", "scheduler", "security", "session", "tests",
)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def manifest():
    paths = [STAGE / "go.mod", STAGE / "go.sum"]
    for directory in SOURCE_DIRS:
        paths.extend((STAGE / directory).rglob("*.go"))
    return [{"path": p.relative_to(STAGE).as_posix(),
             "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in sorted(paths)]


def main():
    gate_dir = OUT / "local-gate-attempt01"
    frozen = read(gate_dir / "source-manifest.json")
    local = read(gate_dir / "local-summary.json")
    fuzz = read(OUT / "fuzz/summary.json")
    race_run = "ff1b5a528f0e23ac0dde3921e53a2b07"
    race_dir = STAGE / "lab/runs" / race_run
    race = read(race_dir / "race-result.json")
    race_log_text = read(race_dir / "race-log.json")["text"]
    expected = frozen["source_manifest"]
    live = manifest()
    parent_manifest_path = ROOT / ".staging/r9-next16/verification/r9-next16/local-gate-attempt01/source-manifest.json"
    parent = read(parent_manifest_path)
    parent_stage = ROOT / ".staging/r9-next16"
    parent_unchanged = all(
        hashlib.sha256((parent_stage / row["path"]).read_bytes()).hexdigest() == row["sha256"]
        for row in parent["source_manifest"]
    )
    race_rows = [{"path": row["path"], "sha256": row["sha256"]}
                 for row in race["source_manifest"]]
    linux = next(row for row in local["binaries"] if row["platform"] == "linux")
    race_log = race["execution"]
    report = {
        "revision": "v0.1-r9-next17",
        "source_manifest_sha256": frozen["manifest_sha256"],
        "source_file_count": len(expected),
        "current_source_matches_frozen": live == expected,
        "parent_next16_source_unchanged": parent_unchanged,
        "local_checks_pass": local["local_checks_pass"],
        "local_packages_passed": local["checks"]["go_test"]["packages_passed"],
        "local_top_level_tests_passed": local["checks"]["go_test"]["top_level_tests_passed"],
        "local_gate": {
            "path": str((gate_dir / "local-summary.json").resolve()),
            "failed_tests": local["checks"]["go_test"]["failed_tests"],
        },
        "bounded_parser_fuzz": {
            "status": "pass" if fuzz["pass"] else "fail",
            "exit_code": fuzz["exit_code"],
            "source_unchanged": fuzz["source_unchanged"],
            "source_matches_local_manifest": fuzz["source_manifest_sha256"] == frozen["manifest_sha256"],
            "scope": fuzz["scope"],
            "result_path": str((OUT / "fuzz/summary.json").resolve()),
        },
        "independent_linux_race": {
            "status": "pass" if race["pass"] else "fail",
            "run_id": race_run,
            "strict_pass": race["pass"],
            "program_exit_code": race_log["exit_code"],
            "data_race_report_present": "DATA RACE" in race_log_text,
            "source_matches_local_manifest": race_rows == expected,
            "related_binary_matches": race["related_binary_sha256"] == linux["sha256"] == hashlib.sha256((ROOT / linux["path"]).read_bytes()).hexdigest(),
            "owned_container_removed": race_log["owned_container_removed"],
            "owned_directory_removed": race["cleanup"]["directory_removed"],
            "snapshot_unchanged": race["snapshot_comparison"]["unchanged"],
            "result_path": str((race_dir / "race-result.json").resolve()),
        },
        "wan": {"status": "not_run", "singapore_transfer_or_business": "none_in_this_revision"},
        "four_categories": {"core_implemented": 2, "partially_implemented": 2, "finally_accepted": 0},
        "acceptance_complete": False,
        "production_ready": False,
        "released": False,
        "pending": [
            "small-volume Singapore-to-Los Angeles WAN validation for the next frozen candidate",
            "Clash/Mihomo/sing-box native outbound and real application metadata bridge",
            "mixed-class fairness, FEC overhead, goodput, and p95/p99 tail latency on WAN",
            "complete close/recovery/READY failure matrix and repeated long-duration resource checks",
            "client DNS proxy, fake-IP/reverse-NAT, TUN, IPv6, and native outbound integration",
            "extended parser fuzz, independent security review, and cross-implementation interoperability",
        ],
    }
    report["source_bound_local_and_race_pass"] = all((
        report["current_source_matches_frozen"], report["parent_next16_source_unchanged"],
        report["local_checks_pass"], report["independent_linux_race"]["strict_pass"],
        report["independent_linux_race"]["source_matches_local_manifest"],
        report["independent_linux_race"]["related_binary_matches"],
        report["independent_linux_race"]["owned_container_removed"],
        report["independent_linux_race"]["owned_directory_removed"],
        report["independent_linux_race"]["snapshot_unchanged"],
    ))
    report["source_bound_local_fuzz_and_race_pass"] = all((
        report["source_bound_local_and_race_pass"],
        report["bounded_parser_fuzz"]["status"] == "pass",
        report["bounded_parser_fuzz"]["source_unchanged"],
        report["bounded_parser_fuzz"]["source_matches_local_manifest"],
    ))
    path = OUT / "evidence-index.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
