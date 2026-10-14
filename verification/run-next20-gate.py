"""Freeze and run the r9-next20 local source gate."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".staging/r9-next20"
OUT = STAGE / "verification/r9-next20/local-gate-attempt01"
SOURCE_DIRS = (
    "adapter", "classification", "cmd", "gateway", "internal", "obfuscation",
    "protocol", "scheduler", "security", "session", "tests",
)


def source_manifest():
    paths = [STAGE / "go.mod", STAGE / "go.sum"]
    for directory in SOURCE_DIRS:
        paths.extend((STAGE / directory).rglob("*.go"))
    return [
        {"path": path.relative_to(STAGE).as_posix(),
         "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for path in sorted(paths)
    ]


def save(path: Path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    OUT.mkdir(parents=True, exist_ok=False)
    rows = source_manifest()
    digest = hashlib.sha256((json.dumps(rows, sort_keys=True, indent=2) + "\n").encode()).hexdigest()
    save(OUT / "source-manifest.json", {
        "revision": "v0.1-r9-next20",
        "file_count": len(rows),
        "manifest_sha256": digest,
        "source_manifest": rows,
    })
    report = {
        "revision": "v0.1-r9-next20",
        "source_manifest_sha256": digest,
        "source_file_count": len(rows),
        "pass": False,
        "acceptance_complete": False,
        "production_ready": False,
        "released": False,
        "checks": {},
        "binaries": [],
        "independent_linux_race": {"status": "not_run"},
        "wan": {"status": "not_run", "singapore_transfer_or_business": "none_in_this_revision"},
    }
    started = time.monotonic()
    env = dict(os.environ, GOTOOLCHAIN="local", CGO_ENABLED="0")
    commands = [
        ("go_test", ["go", "test", "-json", "-p", "1", "./...", "-count=1", "-timeout=240s"], env),
        ("go_vet", ["go", "vet", "./..."], env),
    ]
    for platform in ("windows", "linux"):
        name = f"verification/r9-next20/local-gate-attempt01/bfp-{'windows.exe' if platform == 'windows' else 'linux-amd64'}"
        commands.append(("build_" + platform, ["go", "build", "-trimpath", "-o", name, "./cmd/bfp"],
                         dict(env, GOOS=platform, GOARCH="amd64")))
    try:
        for key, command, environment in commands:
            log = OUT / (key + ".log")
            timed_out = False
            with log.open("xb") as output:
                try:
                    result = subprocess.run(command, cwd=STAGE, env=environment,
                                            stdout=output, stderr=subprocess.STDOUT, timeout=420)
                    exit_code = result.returncode
                except subprocess.TimeoutExpired:
                    exit_code = None
                    timed_out = True
            captured = log.read_text(encoding="utf-8", errors="replace")
            entry = {
                "command": command,
                "exit_code": exit_code,
                "pass": exit_code == 0 and not timed_out,
                "raw_log": log.relative_to(ROOT).as_posix(),
                "outer_timeout": timed_out,
            }
            if key == "go_test":
                events = []
                for line in captured.splitlines():
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        pass
                entry["failed_tests"] = [e.get("Test") for e in events
                                          if e.get("Action") == "fail" and "Test" in e]
                entry["failed_packages"] = [e.get("Package") for e in events
                                             if e.get("Action") == "fail" and "Test" not in e]
                entry["panic_events"] = [
                    {"package": e.get("Package"), "active_test": e.get("Test"),
                     "output": e.get("Output", "").strip()}
                    for e in events if "panic:" in e.get("Output", "")
                ]
                terminal = {(e.get("Package"), e.get("Test")) for e in events
                            if e.get("Action") in ("pass", "fail", "skip") and "Test" in e}
                entry["tests_without_terminal_event"] = [
                    {"package": e.get("Package"), "test": e.get("Test")}
                    for e in events if e.get("Action") == "run" and "Test" in e
                    and (e.get("Package"), e.get("Test")) not in terminal
                ]
                entry["packages_passed"] = sum(e.get("Action") == "pass" and "Test" not in e for e in events)
                entry["top_level_tests_passed"] = sum(
                    e.get("Action") == "pass" and "Test" in e and "/" not in e["Test"]
                    for e in events
                )
            report["checks"][key] = entry
            if key.startswith("build_") and entry["pass"]:
                binary = STAGE / command[4]
                report["binaries"].append({
                    "platform": key[6:],
                    "path": binary.relative_to(ROOT).as_posix(),
                    "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                })
            print(json.dumps({"stage": key, **entry}, ensure_ascii=False), flush=True)
        report["source_unchanged"] = rows == source_manifest()
        report["local_checks_pass"] = report["source_unchanged"] and all(
            check["pass"] for check in report["checks"].values()
        )
        # This is a source-bound local gate only; race/fuzz/WAN are separate evidence.
        report["pass"] = False
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        save(OUT / "local-summary.json", report)
    print(json.dumps({
        "path": str((OUT / "local-summary.json").resolve()),
        "local_checks_pass": report.get("local_checks_pass"),
        "acceptance_pass": False,
    }, ensure_ascii=False), flush=True)
    raise SystemExit(0 if report.get("local_checks_pass") else 1)


if __name__ == "__main__":
    main()

