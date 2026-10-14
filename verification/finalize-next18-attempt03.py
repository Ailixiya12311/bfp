"""Bind next18 attempt03 local, fuzz, and source-bound race evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".staging/r9-next18"
OUT = STAGE / "verification/r9-next18"
GATE = OUT / "local-gate-attempt03"
FUZZ = OUT / "fuzz-attempt03"
RACE_ID = "9391710973e090a609b17f355bc877c2"
RACE_DIR = STAGE / "lab/runs" / RACE_ID


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def live_manifest():
    paths = [STAGE / "go.mod", STAGE / "go.sum"]
    for directory in ("adapter", "classification", "cmd", "gateway", "internal", "obfuscation",
                      "protocol", "scheduler", "security", "session", "tests"):
        paths.extend((STAGE / directory).rglob("*.go"))
    return [{"path": path.relative_to(STAGE).as_posix(),
             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in sorted(paths)]


def main():
    frozen = read(GATE / "source-manifest.json")
    local = read(GATE / "local-summary.json")
    fuzz = read(FUZZ / "summary.json")
    race = read(RACE_DIR / "race-result.json")
    race_log = race["execution"]
    race_rows = [{"path": row["path"], "sha256": row["sha256"]}
                 for row in race["source_manifest"]]
    expected = frozen["source_manifest"]
    live = live_manifest()
    linux = next(item for item in local["binaries"] if item["platform"] == "linux")
    race_binary = race.get("related_binary_sha256", "")
    report = {
        "revision": "v0.1-r9-next18",
        "source_manifest_sha256": frozen["manifest_sha256"],
        "source_file_count": len(expected),
        "current_source_matches_frozen": live == expected,
        "local_checks_pass": local["local_checks_pass"],
        "local_packages_passed": local["checks"]["go_test"]["packages_passed"],
        "local_top_level_tests_passed": local["checks"]["go_test"]["top_level_tests_passed"],
        "local_gate": {
            "path": str((GATE / "local-summary.json").resolve()),
            "failed_tests": local["checks"]["go_test"]["failed_tests"],
        },
        "bounded_parser_fuzz": {
            "status": "pass" if fuzz["pass"] else "fail",
            "exit_code": fuzz["exit_code"],
            "source_unchanged": fuzz["source_unchanged"],
            "source_matches_local_manifest": fuzz["source_manifest_sha256"] == frozen["manifest_sha256"],
            "scope": fuzz["scope"],
            "result_path": str((FUZZ / "summary.json").resolve()),
        },
        "independent_linux_race": {
            "status": "pass" if race["pass"] else "fail",
            "run_id": RACE_ID,
            "strict_pass": race["pass"],
            "program_exit_code": race_log["exit_code"],
            "owned_container_removed": race_log["owned_container_removed"],
            "owned_directory_removed": race["cleanup"]["directory_removed"],
            "snapshot_unchanged": race["snapshot_comparison"]["unchanged"],
            "source_matches_local_manifest": race_rows == expected,
            "related_binary_matches": race_binary == linux["sha256"],
            "result_path": str((RACE_DIR / "race-result.json").resolve()),
        },
        "wan": {"status": "not_run", "singapore_transfer_or_business": "none_in_this_revision"},
        "four_categories": {"core_implemented": 2, "partially_implemented": 2, "finally_accepted": 0},
        "acceptance_complete": False,
        "production_ready": False,
        "released": False,
        "pending": [
            "small-volume Singapore-to-Los Angeles WAN business validation for this exact source",
            "Clash/Mihomo/sing-box native outbound and real application metadata bridge",
            "client DNS proxy, fake-IP allocator/reverse-NAT, TUN, IPv6, and real software matrix",
            "mixed-class fairness, FEC overhead, goodput, and p95/p99 WAN measurements",
            "complete close/recovery/READY loss matrix and long-duration resource checks",
            "extended fuzz, independent security review, wire vectors, and cross-implementation interoperability",
        ],
    }
    report["source_bound_local_and_race_pass"] = all((
        report["current_source_matches_frozen"],
        report["local_checks_pass"],
        report["independent_linux_race"]["strict_pass"],
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
    path = OUT / "evidence-index-attempt03.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
