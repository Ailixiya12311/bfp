"""Summarize saved UDP probe phases without rewriting the raw WAN result.

This is an offline analysis. The first timeout, original deadline, strict
scenario results and separately rounded timings remain unchanged.
"""
from __future__ import annotations

import argparse
import json
import re
import statistics

from remote import WORKSPACE, owned_dir, write_public
from wan import json_lines


SCENARIOS = ("normal_udp", "udp_to_tcp", "initial_udp_blocked")
PHASES = (
    "stats_before_ms", "write_elapsed_ms", "read_elapsed_ms",
    "exchange_elapsed_ms", "stats_after_ms", "elapsed_ms",
)
ERROR_PHASES = {"", "set_deadline", "before_write", "write", "before_read", "read"}
BOOL_FIELDS = ("success", "timeout", "write_attempted", "write_accepted")
COUNT_FIELDS = ("late_count", "unexpected_count", "unmatched_count")


def require(condition, label):
    if not condition:
        # Only a fixed diagnostic is emitted; never copy a malformed log value.
        raise ValueError("UDP phase evidence invalid: " + label)


def integer(value, low=0, high=None):
    return type(value) is int and value >= low and (high is None or value <= high)


def observation(row):
    iteration = row.get("iteration")
    require(integer(iteration, high=9999), "iteration")
    udp = row.get("udp")
    require(isinstance(udp, dict), "missing UDP observation")
    require(integer(udp.get("expected_iteration"), high=9999) and
            udp["expected_iteration"] == iteration, "expected iteration")
    for key in PHASES + COUNT_FIELDS:
        require(integer(udp.get(key)), "nonnegative phase/count")
    for key in BOOL_FIELDS:
        require(type(udp.get(key)) is bool, "boolean observation")
    require(udp.get("error_phase") in ERROR_PHASES, "error phase")
    require(isinstance(udp.get("error_kind"), str) and
            re.fullmatch(r"[a-z_]{0,32}", udp["error_kind"]), "error kind")
    for key in ("received_iteration", "last_unmatched_iteration"):
        require(udp.get(key) is None or integer(udp[key], high=9999), "reply iteration")
    for key in ("carrier_before", "carrier_after"):
        require(udp.get(key) in {"udp", "tcp", ""}, "carrier")
    for key in ("generation_before", "generation_after"):
        require(integer(udp.get(key)), "generation")
    require(not udp["write_accepted"] or udp["write_attempted"], "write admission")
    if udp["success"]:
        require(udp["error_phase"] == udp["error_kind"] == "" and
                not udp["timeout"] and udp["received_iteration"] == iteration,
                "successful operation")
    else:
        require(udp["error_phase"] != "", "failed operation phase")
    # The allowlist is also a serialization boundary: no message payloads,
    # arbitrary error text or newly added unreviewed fields are copied.
    keys = PHASES + COUNT_FIELDS + BOOL_FIELDS + (
        "error_phase", "error_kind", "expected_iteration", "received_iteration",
        "last_unmatched_iteration", "carrier_before", "carrier_after",
        "generation_before", "generation_after",
    )
    return {"iteration": iteration, "udp": {key: udp[key] for key in keys}}


def analyze(run_id, revision):
    owned_dir(run_id)  # Validate the exact lab run ID before resolving a path.
    require(bool(re.fullmatch(r"v[0-9]+\.[0-9]+-r[1-9][0-9]*", revision)), "revision")
    directory = WORKSPACE / "lab" / "runs" / run_id
    raw = json.loads((directory / "wan-result.json").read_text(encoding="utf-8"))
    require(raw.get("run_id") == run_id, "run identity")
    require(bool(re.fullmatch(r"[a-f0-9]{64}", raw.get("binary_sha256", ""))), "binary hash")
    validation = json.loads((WORKSPACE / "verification" / revision / "validation.json")
                            .read_text(encoding="utf-8"))
    linux = [item for item in validation["binaries"] if item.get("platform") == "linux"]
    require(validation.get("revision") == revision and len(linux) == 1 and
            linux[0]["sha256"] == raw["binary_sha256"], "revision binary identity")
    report = {
        "revision": revision, "run_id": run_id,
        "binary_sha256": raw["binary_sha256"],
        "raw_overall_pass": raw["pass"], "scenarios": {},
        "boundary": (
            "Stage durations are separately rounded monotonic observations in the "
            "sending process. WriteAccepted only means complete net.Conn API return. "
            "ReadElapsed includes correlation and deadline checks, not pure RTT. "
            "Carrier boundary observations do not identify exact relay loss or target "
            "execution. No deadline change/retransmission/result rewriting."
        ),
    }
    for name in SCENARIOS:
        evidence = raw["scenarios"][name]
        require(isinstance(evidence.get("result"), dict), "incomplete scenario result")
        result = evidence["result"]
        log = json.loads((directory / (name + ".probe-log.json")).read_text(encoding="utf-8"))
        rows = [observation(row) for row in json_lines(log["lines"])
                if row.get("event") == "progress"]
        count = evidence.get("probe_count")
        require(integer(count, low=1, high=10000), "probe count")
        require([row["iteration"] for row in rows] == list(range(count)), "ordered complete operations")
        success = sum(row["udp"]["success"] for row in rows)
        failed = count - success
        require(success == result.get("udp_completed") and failed == result.get("udp_failed"),
                "counts differ from raw result")
        stable_tcp = [row for row in rows
                      if row["udp"]["carrier_before"] == row["udp"]["carrier_after"] == "tcp"
                      and row["udp"]["generation_before"] == row["udp"]["generation_after"]]
        phase_stats = {}
        for key in PHASES:
            values = [row["udp"][key] for row in rows]
            phase_stats[key] = {"minimum": min(values), "median": statistics.median(values),
                                "maximum": max(values)}
        report["scenarios"][name] = {
            "scenario_pass": evidence["pass"], "operation_count": count,
            "udp_completed": success, "udp_failed": failed,
            "summary_counts_match_raw_result": True, "phases_ms": phase_stats,
            "stable_tcp_operations": len(stable_tcp),
            "stable_tcp_successes": sum(row["udp"]["success"] for row in stable_tcp),
            "failed_operations": [row for row in rows if not row["udp"]["success"]],
            "unmatched_reply_operations": [row for row in rows if row["udp"]["unmatched_count"]],
        }
    return directory, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    parser.add_argument("--revision", required=True)
    parser.add_argument("--check-only", action="store_true", help="validate saved evidence without writing")
    args = parser.parse_args()
    directory, report = analyze(args.run_id, args.revision)
    destination = directory / "udp-operation-phase-analysis.json"
    if not args.check_only:
        require(not destination.exists(), "preserve existing analysis")
        write_public(destination, report)
    print(json.dumps({
        "path": None if args.check_only else str(destination),
        "check_only": args.check_only, "run_id": args.run_id,
        "counts": {name: {key: item[key] for key in (
            "operation_count", "udp_completed", "udp_failed", "stable_tcp_operations", "stable_tcp_successes"
        )} for name, item in report["scenarios"].items()},
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
