"""Bind next16 local, fuzz, and Linux race evidence without rewriting raw results."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".staging/r9-next16"
OUT = STAGE / "verification/r9-next16"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def current_manifest():
    paths = [STAGE / "go.mod", STAGE / "go.sum"]
    for directory in ("adapter", "classification", "cmd", "gateway", "internal",
                      "obfuscation", "protocol", "scheduler", "security", "session", "tests"):
        paths.extend((STAGE / directory).rglob("*.go"))
    return [{"path": p.relative_to(STAGE).as_posix(),
             "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(paths)]


def focused(path):
    events = []
    if path.exists():
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                pass
    return {
        "path": str(path.resolve()),
        "raw_sha256": hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None,
        "scope": "focused next16 evidence; final frozen source is checked by the local gate and race",
        "top_level_tests_passed": sum(e.get("Action") == "pass" and "Test" in e and "/" not in e["Test"] for e in events),
        "failed_events": [e for e in events if e.get("Action") == "fail"],
        "package_pass": any(e.get("Action") == "pass" and "Test" not in e for e in events),
        "present": path.exists(),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{32}", args.run_id):
        raise ValueError("invalid race run ID")

    gate_dir = OUT / "local-gate-attempt01"
    frozen = read(gate_dir / "source-manifest.json")
    local = read(gate_dir / "local-summary.json")
    parent = read(STAGE / "verification/parent-source-manifest.json")
    expected = frozen["source_manifest"]
    live = current_manifest()
    parent_unchanged = all(
        hashlib.sha256((ROOT / ".staging/r9-next15" / row["path"]).read_bytes()).hexdigest() == row["sha256"]
        for row in parent["copied_source_manifest"]
    )

    focused_files = {
        "session_policy": OUT / "focused/session-policy-attempt01.jsonl",
        "session_policy_regression": OUT / "focused/session-policy-regression-attempt01.jsonl",
        "cli_fec_attempt01": OUT / "focused/cli-fec-attempt01.jsonl",
        "cli_fec_attempt02": OUT / "focused/cli-fec-attempt02.jsonl",
        "cli_fec_default_regression": OUT / "focused/cli-fec-default-regression-attempt01.jsonl",
        "cli_classification_regression": OUT / "focused/cli-classification-regression-attempt01.jsonl",
        "cli_socks_runtime": OUT / "focused/cli-socks-runtime-attempt01.jsonl",
    }
    focused_report = {name: focused(path) for name, path in focused_files.items()}

    fuzz_path = OUT / "fuzz/summary.json"
    fuzz = read(fuzz_path)
    run = STAGE / "lab/runs" / args.run_id
    race = read(run / "race-result.json")
    race_log = read(run / "race-log.json")["text"]
    linux = next(row for row in local["binaries"] if row["platform"] == "linux")
    race_rows = [{"path": row["path"], "sha256": row["sha256"]} for row in race["source_manifest"]]

    race_report = {
        "status": "pass" if race["pass"] else "fail",
        "run_id": args.run_id,
        "strict_pass": race["pass"],
        "program_exit_code": race["execution"].get("exit_code"),
        "packages_passed": len(re.findall(r"^ok\s+", race_log, re.MULTILINE)),
        "race_report_present": "DATA RACE" in race_log,
        "source_matches_local_manifest": race_rows == expected,
        "related_binary_matches": race["related_binary_sha256"] == linux["sha256"] == hashlib.sha256((ROOT / linux["path"]).read_bytes()).hexdigest(),
        "binary_binding_scope": "associated local build metadata; race recompiles the frozen source rather than executing the prebuilt binary",
        "owned_container_removed": race["execution"].get("owned_container_removed"),
        "owned_directory_removed": race.get("cleanup", {}).get("directory_removed"),
        "snapshot_unchanged": race.get("snapshot_comparison", {}).get("unchanged"),
        "result_path": str((run / "race-result.json").resolve()),
    }

    report = {
        "revision": "v0.1-r9-next16",
        "source_manifest_sha256": frozen["manifest_sha256"],
        "source_file_count": len(expected),
        "current_source_matches_frozen": live == expected,
        "parent_next15_source_unchanged": parent_unchanged,
        "local_checks_pass": local["local_checks_pass"],
        "local_packages_passed": local["checks"]["go_test"]["packages_passed"],
        "local_top_level_tests_passed": local["checks"]["go_test"]["top_level_tests_passed"],
        "local_gate": {
            "name": "attempt01",
            "path": str((gate_dir / "local-summary.json").resolve()),
            "failed_tests": local["checks"]["go_test"]["failed_tests"],
        },
        "focused": focused_report,
        "bounded_parser_fuzz": {
            "status": "pass" if fuzz["pass"] else "fail",
            "exit_code": fuzz["exit_code"],
            "source_unchanged": fuzz["source_unchanged"],
            "source_matches_local_manifest": fuzz["source_manifest_sha256"] == frozen["manifest_sha256"],
            "scope": fuzz["scope"],
            "result_path": str(fuzz_path.resolve()),
            "raw_log": fuzz["raw_log"],
        },
        "independent_linux_race": race_report,
        "wan": {"status": "not_run", "singapore_transfer_or_business": "none_in_this_revision"},
        "four_categories": {"core_implemented": 2, "partially_implemented": 2, "finally_accepted": 0},
        "acceptance_complete": False,
        "production_ready": False,
        "released": False,
        "pending": [
            "small-volume Singapore-to-Los Angeles WAN validation for next16, including UDP-first and bounded UDP-to-TCP fallback",
            "trusted Clash rule labels/application identity bridge",
            "mixed-class fairness, FEC overhead, goodput, and p95/p99 tail latency on WAN",
            "complete close/recovery/READY failure matrix and repeated long-duration resource checks",
            "client DNS proxy, fake-IP/reverse-NAT, TUN, IPv6, and native Mihomo/sing-box outbound integration",
            "extended parser fuzz, independent security review, and cross-implementation interoperability",
        ],
    }
    report["source_bound_local_and_race_pass"] = all((
        report["current_source_matches_frozen"], parent_unchanged, local["local_checks_pass"],
        race_report["strict_pass"], race_report["source_matches_local_manifest"],
        race_report["related_binary_matches"], race_report["owned_container_removed"],
        race_report["owned_directory_removed"], race_report["snapshot_unchanged"],
    ))
    report["source_bound_local_fuzz_and_race_pass"] = all((
        report["source_bound_local_and_race_pass"],
        report["bounded_parser_fuzz"]["status"] == "pass",
        report["bounded_parser_fuzz"]["source_unchanged"],
        report["bounded_parser_fuzz"]["source_matches_local_manifest"],
    ))
    path = OUT / "evidence-index.json"
    with path.open("x", encoding="utf-8") as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write("\n")
    print(json.dumps(report, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
