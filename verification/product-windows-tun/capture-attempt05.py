"""Preserve TUN evidence, or parse existing logs without running a client."""
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import shutil

ROOT = pathlib.Path(__file__).resolve().parents[2]
EVENTS = frozenset(("bfp_outbound_started", "bfp_session_started",
                    "bfp_outbound_close_requested", "bfp_session_close_requested",
                    "bfp_session_business_ended"))
BOOL_FIELDS = ("business_ended", "control_ended", "close_intent", "local_close")
SOURCE = re.compile(r"(?:unknown|context_end_without_cancel|fakeip_flush|"
                    r"(?:local_close@|peer_close@|raw_business_stop@|parent_context_end@)?"
                    r"(?:[A-Za-z0-9_.-]{1,96}\.go:[0-9]{1,9}|unknown))\Z")
LOG_LINE = re.compile(r'time="([^"\r\n]+)" level=(?:debug|info|warning|warn|error|fatal|panic|trace) '
                      r'msg="(\[BFP\] [^"\r\n]*)"\Z')


def parsed_time(value):
    """Require a timezone; Go nanoseconds are truncated to microseconds."""
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.datetime.fromisoformat(value)
        return stamp if stamp.utcoffset() is not None else None
    except ValueError:
        return None


def strict_bool(value):
    return value if type(value) is bool else None


def parse_bfp_event(line, number=1):
    """Return fixed fields only, never the log line or arbitrary token values."""
    match = LOG_LINE.fullmatch(line.strip())
    if match:
        stamp, message = match.groups()
        stamp = stamp if parsed_time(stamp) is not None else None
    elif line.startswith("[BFP] "):
        stamp, message = None, line.strip()
    else:
        return None
    tokens = message.split()
    if len(tokens) < 2 or tokens[0] != "[BFP]" or not tokens[1].startswith("event="):
        return None
    event = tokens[1][6:]
    if event not in EVENTS:
        return None
    fields = {}
    for token in tokens[2:]:
        key, separator, value = token.partition("=")
        if separator and key in ("source", "outbound", "owner", *BOOL_FIELDS):
            # Duplicate fields have no trustworthy value.
            fields[key] = None if key in fields else value
    result = {"event": event, "time": stamp, "line": number,
              "source": None, "outbound": None, "owner": None,
              "source_records_exact_cause": False}
    if "source" in fields or event == "bfp_session_business_ended":
        source = fields.get("source")
        result["source"] = source if isinstance(source, str) and SOURCE.fullmatch(source) else "unknown"
    for key in ("outbound", "owner"):
        value = fields.get(key)
        if isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value):
            ordinal = int(value)
            if ordinal <= 2**64 - 1:
                result[key] = ordinal
    for key in BOOL_FIELDS:
        value = fields.get(key)
        result[key] = {"true": True, "false": False}.get(value)
    return result


def ordered_controls(controls):
    latest = datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)
    return {action: sorted(controls.get(action, []), key=lambda entry: (
        parsed_time(entry.get("created_utc")) or latest, entry.get("path", "")))
        for action in ("check", "stop")}


def coverage(result, controls):
    scenarios = result.get("scenarios") or []
    checks = controls.get("check", [])
    control_flags = [strict_bool((entry.get("reply") or {}).get("success")) for entry in checks]
    scenario_flags = [strict_bool(scenario["https"].get("success"))
                      if isinstance(scenario["https"], dict) else None
                      for scenario in scenarios if scenario.get("https") is not None]
    requested = result.get("requested_https_checks")
    requested = requested if type(requested) is int and requested > 0 else None
    # A control and a scenario can represent the same request. Never add counts.
    identities = {entry.get("path", index) for index, entry in enumerate(checks)}
    flags, count = (control_flags, len(identities)) if checks else (scenario_flags, len(scenario_flags))
    if False in control_flags + scenario_flags:
        https_pass = False
    elif (requested is not None and count == requested and flags
          and all(flag is True for flag in flags + scenario_flags)):
        https_pass = True
    else:
        https_pass = None
    force = []
    for scenario in scenarios:
        if scenario.get("name") != "supervisor_and_launcher_force_termination":
            continue
        chain = scenario.get("verified_chain") or {}
        launcher = strict_bool(chain.get("launcher_terminated"))
        supervisor = strict_bool(chain.get("supervisor_terminated"))
        complete = True if launcher is True and supervisor is True else (
            False if launcher is False or supervisor is False else None)
        force.append({"launcher_terminated": launcher, "supervisor_terminated": supervisor,
                      "child_exited": strict_bool(scenario.get("child_exited")),
                      "both_processes_terminated": complete})
    force_flags = [entry["both_processes_terminated"] for entry in force]
    executed = False if not force or False in force_flags else (
        True if all(flag is True for flag in force_flags) else None)
    return {"https_pass": https_pass,
            "https_evidence": {"requested_checks": requested, "control_logs": len(checks),
                               "distinct_control_logs": len(identities),
                               "populated_scenario_https": len(scenario_flags),
                               "coverage_count": count, "unknown_control_replies": control_flags.count(None),
                               "counts_are_not_added": True},
            "force_termination_executed": executed, "force_termination_evidence": force}


def make_audit(result, events, controls, preserved):
    controls = ordered_controls(controls)
    first_stop = controls["stop"][0] if controls["stop"] else None
    stop_time = parsed_time(first_stop.get("created_utc")) if first_stop else None
    if any(parsed_time(entry.get("created_utc")) is None for entry in controls["stop"]):
        stop_time = None  # The earliest stop cannot be established with missing times.
    latest = datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)
    events = [dict(event) for event in events]
    events.sort(key=lambda event: (parsed_time(event.get("time")) or latest,
                                   event.get("log", ""), event["line"]))
    for event in events:
        stamp = parsed_time(event.get("time"))
        event["before_stop"] = stamp < stop_time if stamp is not None and stop_time is not None else None
    terminations = [event for event in events if event["event"] == "bfp_session_business_ended"]
    unknown = sum(event["before_stop"] is None for event in terminations)
    scenarios = result.get("scenarios") or []
    audit = {"time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
             "client_version": result.get("client_version"), "native_version": result.get("native_version"),
             "tun_ready": strict_bool(scenarios[0].get("ready")) if scenarios else None,
             "final_cleanup_pass": strict_bool((result.get("final_cleanup") or {}).get("pass")),
             "elapsed_seconds": result.get("elapsed_seconds"), "instance_events": events,
             "termination_events": terminations,
             "unexpected_termination_count_before_stop": None if unknown else sum(
                 event["before_stop"] is True for event in terminations),
             "unclassified_termination_count": unknown,
             "controls": {action: entries[0] if entries else None for action, entries in controls.items()},
             "control_logs": controls, "preserved_logs": preserved,
             "stop_boundary": {"path": first_stop.get("path") if first_stop else None,
                               "created_utc": first_stop.get("created_utc") if stop_time else None,
                               "definition": "earliest available stop log file creation time; approximate boundary, not exact stop invocation or completion",
                               "comparison": "strictly earlier; timestamp precision is microseconds"},
             "native_event_coverage": "available selected logs only; a later scenario may overwrite earlier runtime logs",
             "root_cause_confirmed": False,
             "next_diagnostic": "correlate local outbound/owner ordinals with parent context and close events"}
    audit.update(coverage(result, controls))
    return audit


def read_controls(folder, result):
    run_id = result["run_id"]
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise RuntimeError("unexpected control run identifier")
    controls = {"check": [], "stop": []}
    for action in controls:
        for log in folder.glob("tun-" + run_id + "-" + action + "-*.out.log"):
            if log.is_symlink():
                raise RuntimeError("unexpected control log path")
            stat = log.stat()
            created = getattr(stat, "st_birthtime", stat.st_ctime)
            try:
                raw = json.loads(log.read_text(encoding="utf-8-sig"))
            except (ValueError, UnicodeError):
                raw = None
            # Control replies may contain other metadata; expose only needed booleans.
            reply = {key: strict_bool(raw.get(key)) for key in ("success", "stopped", "cleanup_complete")} if isinstance(raw, dict) else None
            controls[action].append({"path": log.relative_to(ROOT).as_posix(),
                                     "created_utc": datetime.datetime.fromtimestamp(created, datetime.timezone.utc).isoformat(),
                                     "time_basis": "st_birthtime" if hasattr(stat, "st_birthtime") else "st_ctime",
                                     "reply": reply})
    return ordered_controls(controls)


def demo_audit():
    lines = (
        'time="2026-10-13T11:00:00Z" level=info msg="[BFP] event=bfp_session_started outbound=1 owner=1"',
        'time="2026-10-13T11:00:01Z" level=warning msg="[BFP] event=bfp_session_business_ended outbound=1 owner=1 source=parent_context_end@tunnel.go:613 business_ended=true control_ended=false close_intent=false local_close=false"',
        'time="2026-10-13T11:00:02Z" level=info msg="[BFP] event=bfp_session_started outbound=2 owner=2"')
    result = {"client_version": "synthetic-debug07", "native_version": "synthetic-debug07", "scenarios": []}
    return make_audit(result, [parse_bfp_event(line, number) for number, line in enumerate(lines, 1)], {}, [])


def preflight_outputs(record, targets):
    if any(path.exists() or path.is_symlink() for path in (record, *targets)):
        raise RuntimeError("preserve existing audit and diagnostic logs")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempt", type=int, default=5)
    parser.add_argument("--dry-run", action="store_true", help="read existing evidence; do not copy logs or write an audit")
    parser.add_argument("--demo", action="store_true", help="parse an in-memory multi-owner demo (requires --dry-run)")
    args = parser.parse_args(argv)
    if not 5 <= args.attempt <= 99:
        parser.error("unexpected attempt number")
    if args.demo:
        if not args.dry_run:
            parser.error("--demo requires --dry-run")
        print(json.dumps(demo_audit(), ensure_ascii=False, indent=2))
        return 0
    folder = ROOT / "verification/product-windows-tun"
    tag = f"attempt{args.attempt:02d}"
    record = folder / ("windows-tun-real-" + tag + "-audit.json")
    if not args.dry_run:
        preflight_outputs(record, [])
    result = json.loads((folder / ("windows-tun-real-" + tag + ".json")).read_text(encoding="utf-8-sig"))
    client = pathlib.Path(result["client_root"])
    if client.is_symlink() or (hasattr(client, "is_junction") and client.is_junction()):
        raise RuntimeError("unexpected owned client path")
    client = client.resolve(strict=True)
    if client.parent != (ROOT / "credentials-client-ready").resolve():
        raise RuntimeError("unexpected owned client path")
    runtime = client / "client/runtime"
    pairs = [(runtime / name, runtime / (name + "." + tag)) for name in (
        "native-supervisor.stdout.log", "native-supervisor.stderr.log")]
    if not args.dry_run:
        preflight_outputs(record, [target for _, target in pairs])
    selected = []
    for source, target in pairs:
        chosen = target if args.dry_run and target.exists() else source
        if chosen.is_symlink() or not chosen.is_file():
            raise RuntimeError("unexpected diagnostic log path")
        selected.append(chosen)
    controls = read_controls(folder, result)
    if not args.dry_run:
        for source, target in pairs:
            with source.open("rb") as source_file, target.open("xb") as target_file:
                shutil.copyfileobj(source_file, target_file)
        selected = [target for _, target in pairs]
    preserved, events = [], []
    for selected_log in selected:
        payload = selected_log.read_bytes()
        log_path = selected_log.relative_to(ROOT).as_posix()
        preserved.append({"path": log_path, "bytes": len(payload),
                          "sha256": hashlib.sha256(payload).hexdigest(), "private_runtime_log": True})
        for number, line in enumerate(payload.decode("utf-8-sig").splitlines(), 1):
            event = parse_bfp_event(line, number)
            if event is not None:
                event["log"] = log_path
                events.append(event)
    audit = make_audit(result, events, controls, preserved)
    if args.dry_run:
        print(json.dumps(audit, ensure_ascii=False, indent=2))
    else:
        with record.open("x", encoding="utf-8") as output:
            json.dump(audit, output, ensure_ascii=False, indent=2)
            output.write("\n")
        print(json.dumps({"audit": str(record), "cleanup_pass": audit["final_cleanup_pass"],
                          "unexpected_termination_count_before_stop": audit["unexpected_termination_count_before_stop"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
