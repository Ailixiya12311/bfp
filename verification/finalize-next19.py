"""Bind next19 evidence without rewriting any previous outcome."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".staging/r9-next19"
OUT = STAGE / "verification/r9-next19"
SOURCE_DIRS = ("adapter", "classification", "cmd", "gateway", "internal",
               "obfuscation", "protocol", "scheduler", "security", "session", "tests")


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def manifest(stage):
    paths = [stage / "go.mod", stage / "go.sum"]
    for name in SOURCE_DIRS:
        paths.extend((stage / name).rglob("*.go"))
    return [{"path": p.relative_to(stage).as_posix(),
             "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(paths)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--race-result", required=True)
    parser.add_argument("--wan-result")
    args = parser.parse_args()
    frozen = read(OUT / "local-gate-attempt01/source-manifest.json")
    local = read(OUT / "local-gate-attempt01/local-summary.json")
    fuzz = read(OUT / "fuzz-attempt01/summary.json")
    race = read(args.race_result)
    parent_stage = ROOT / ".staging/r9-next18"
    parent = read(parent_stage / "verification/r9-next18/local-gate-attempt03/source-manifest.json")
    linux = next(b for b in local["binaries"] if b["platform"] == "linux")
    race_rows = [{"path": r["path"], "sha256": r["sha256"]} for r in race["source_manifest"]]
    live = manifest(STAGE)
    source_ok = live == frozen["source_manifest"]
    gates = {
        "current_source_matches_frozen": source_ok,
        "parent_next18_source_unchanged": manifest(parent_stage) == parent["source_manifest"],
        "local_checks_pass": local.get("local_checks_pass") is True,
        "fuzz_pass": fuzz.get("pass") is True and fuzz.get("source_unchanged") is True,
        "fuzz_manifest_matches": fuzz["source_manifest_sha256"] == frozen["manifest_sha256"],
        "race_strict_pass": race.get("pass") is True,
        "race_source_matches": race_rows == frozen["source_manifest"],
        "race_related_binary_matches": race["related_binary_sha256"] == linux["sha256"],
        "local_binary_unchanged": hashlib.sha256((ROOT / linux["path"]).read_bytes()).hexdigest() == linux["sha256"],
    }
    old_wan_path = ROOT / "lab/runs/9c596cee534aab23b53d1e194e8f7696/wan-result.json"
    diagnosis = read(STAGE / "verification/wan-next18-deadline-diagnosis.json")
    gates["original_next18_wan_unchanged"] = (
        hashlib.sha256(old_wan_path.read_bytes()).hexdigest() == diagnosis["original_result_sha256"]
    )
    report = {
        "revision": "v0.1-r9-next19", "source_manifest_sha256": frozen["manifest_sha256"],
        "source_file_count": len(live), "gates": gates,
        "source_bound_local_fuzz_and_race_pass": all(gates.values()),
        "local_packages_passed": local["checks"]["go_test"]["packages_passed"],
        "local_top_level_tests_passed": local["checks"]["go_test"]["top_level_tests_passed"],
        "binaries": local["binaries"],
        "local_gate": str(OUT / "local-gate-attempt01/local-summary.json"),
        "bounded_parser_fuzz": str(OUT / "fuzz-attempt01/summary.json"),
        "independent_linux_race": {"run_id": race["run_id"], "strict_pass": race["pass"],
                                   "result_path": str(Path(args.race_result).resolve()),
                                   "scope": "complete Go package race run for this source, not a security audit"},
        "old_next18_wan": {"run_id": diagnosis["run_id"], "status": "strict_fail_preserved",
                           "result_path": str(old_wan_path)},
        "wan": {"status": "not_run"},
        "four_categories": {"core_implemented": 2, "partially_implemented": 2, "finally_accepted": 0},
        "acceptance_complete": False, "production_ready": False, "released": False,
        "pending": ["client Session fake-IP and DNS interception/wire mapping synchronization",
                    "TUN/IPv6/NAT and native Mihomo/sing-box integration",
                    "mixed-class/FEC WAN performance and long resource stability",
                    "complete failure/recovery/security matrices and independent security review",
                    "frozen interoperable wire and cross-implementation validation"],
    }
    if args.wan_result:
        path = Path(args.wan_result).resolve()
        wan = read(path)
        binding = read(path.parent / "next19-experiment-binding.json")
        bound = (binding["source_manifest_sha256"] == frozen["manifest_sha256"]
                 and binding["linux_binary_sha256"] == linux["sha256"]
                 and wan["binary_sha256"] == linux["sha256"]
                 and binding["race_run_id"] == race["run_id"]
                 and binding["raw_result_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
                 and binding.get("phase_contract_matches_results") is True)
        report["wan"] = {
            "status": "strict_pass_new_phase_budget" if wan.get("pass") is True and bound else "strict_fail",
            "source_binary_contract_bound": bound, "run_id": wan["run_id"], "result_path": str(path),
            "setup_duration": "8s", "business_duration": "30s", "probe_count": 12,
            "tcp_bytes_each": 1024, "interval": "1s", "fec_policy": "off",
            "scope": "one bounded Singapore to Los Angeles sample under a new explicit budget contract",
            "scenarios": {n: {"strict_pass": s.get("pass"),
                               "tcp_completed": s.get("result", {}).get("tcp_completed"),
                               "udp_completed": s.get("result", {}).get("udp_completed"),
                               "udp_failed": s.get("result", {}).get("udp_failed"),
                               "failure_phase": s.get("result", {}).get("failure_phase")}
                          for n, s in wan["scenarios"].items()},
        }
    path = OUT / "evidence-index.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"path": str(path), "source_bound_checks_pass": all(gates.values()),
                      "wan": report["wan"]["status"], "acceptance_complete": False}), flush=True)
    return 0 if all(gates.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
