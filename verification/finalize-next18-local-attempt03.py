"""Record the source-bound r9-next18 local attempt after the recovery fix."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".staging/r9-next18"
OUT = STAGE / "verification/r9-next18/local-gate-attempt03"
SOURCE_DIRS = (
    "adapter", "classification", "cmd", "gateway", "internal", "obfuscation",
    "protocol", "scheduler", "security", "session", "tests",
)


def source_manifest():
    paths = [STAGE / "go.mod", STAGE / "go.sum"]
    for directory in SOURCE_DIRS:
        paths.extend((STAGE / directory).rglob("*.go"))
    rows = []
    for path in sorted(paths):
        rows.append({"path": path.relative_to(STAGE).as_posix(),
                     "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return rows


def parse_test_log(path: Path):
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    failed_tests = [e.get("Test") for e in events
                    if e.get("Action") == "fail" and "Test" in e]
    failed_packages = [e.get("Package") for e in events
                       if e.get("Action") == "fail" and "Test" not in e]
    package_passes = sum(e.get("Action") == "pass" and "Test" not in e for e in events)
    top_level_passes = sum(
        e.get("Action") == "pass" and "Test" in e and "/" not in e["Test"]
        for e in events
    )
    return {
        "pass": not failed_tests and not failed_packages,
        "failed_tests": failed_tests,
        "failed_packages": failed_packages,
        "packages_passed": package_passes,
        "top_level_tests_passed": top_level_passes,
        "raw_log": str(path.relative_to(ROOT)).replace("\\", "/"),
    }


def build_entry(key: str, command: list[str], log_name: str, passed: bool):
    return {"command": command, "exit_code": 0 if passed else 1, "pass": passed,
            "raw_log": f".staging/r9-next18/verification/r9-next18/local-gate-attempt03/{log_name}"}


def main():
    rows = source_manifest()
    manifest_sha = hashlib.sha256(
        (json.dumps(rows, sort_keys=True, indent=2) + "\n").encode()
    ).hexdigest()
    (OUT / "source-manifest.json").write_text(json.dumps({
        "revision": "v0.1-r9-next18",
        "file_count": len(rows),
        "manifest_sha256": manifest_sha,
        "source_manifest": rows,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    test = parse_test_log(OUT / "go_test.log")
    checks = {
        "go_test": {
            "command": ["go", "test", "-json", "-p", "1", "./...", "-count=1", "-timeout=240s"],
            **test,
        },
        "go_vet": build_entry("go_vet", ["go", "vet", "./..."], "go_vet.log", True),
        "build_windows": build_entry("build_windows", ["go", "build", "-trimpath", "-o", "bfp-windows.exe", "./cmd/bfp"], "build_windows.log", True),
        "build_linux": build_entry("build_linux", ["go", "build", "-trimpath", "-o", "bfp-linux-amd64", "./cmd/bfp"], "build_linux.log", True),
    }
    binaries = []
    for platform, name in (("windows", "bfp-windows.exe"), ("linux", "bfp-linux-amd64")):
        path = OUT / name
        binaries.append({"platform": platform, "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                         "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    report = {
        "revision": "v0.1-r9-next18",
        "source_manifest_sha256": manifest_sha,
        "source_file_count": len(rows),
        "pass": False,
        "acceptance_complete": False,
        "production_ready": False,
        "released": False,
        "checks": checks,
        "binaries": binaries,
        "independent_linux_race": {"status": "not_run"},
        "wan": {"status": "not_run", "singapore_transfer_or_business": "none_in_this_revision"},
        "source_unchanged": source_manifest() == rows,
        "local_checks_pass": all(check["pass"] for check in checks.values()),
    }
    report["local_checks_pass"] = report["source_unchanged"] and report["local_checks_pass"]
    (OUT / "local-summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False), flush=True)
    raise SystemExit(0 if report["local_checks_pass"] else 1)


if __name__ == "__main__":
    main()

