"""Promote locally verified next25 Go/module source with a reversible r8 backup."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".staging/r9-next25"
DIRS = ("adapter", "classification", "clientconfig", "cmd", "gateway", "internal", "obfuscation", "protocol", "scheduler", "security", "session", "tests")


def sources(directory):
    paths = [directory / "go.mod", directory / "go.sum"]
    for name in DIRS:
        paths.extend((directory / name).rglob("*.go"))
    return {p.relative_to(directory).as_posix(): p.read_bytes() for p in sorted(paths)}


def manifest(values):
    return [{"path": p, "sha256": hashlib.sha256(b).hexdigest()} for p, b in sorted(values.items())]


def main():
    gate_dir = STAGE / "verification/r9-next25/local-gate-attempt01"
    gate = json.loads((gate_dir / "local-summary.json").read_text(encoding="utf-8"))
    gate_rows = json.loads((gate_dir / "source-manifest.json").read_text(encoding="utf-8"))["source_manifest"]
    smoke_dir = STAGE / "verification/r9-next25/cli-dns-smoke-attempt01"
    smoke = json.loads((smoke_dir / "summary.json").read_text(encoding="utf-8"))
    smoke_rows = json.loads((smoke_dir / "source-manifest.json").read_text(encoding="utf-8"))
    values, before = sources(STAGE), sources(ROOT)
    rows = manifest(values)
    if not gate.get("local_checks_pass") or not gate.get("source_unchanged") or not smoke.get("pass"):
        raise RuntimeError("candidate local gate and actual CLI DNS smoke must pass before promotion")
    if sorted(gate_rows, key=lambda r:r["path"]) != rows or sorted(smoke_rows, key=lambda r:r["path"]) != rows:
        raise RuntimeError("candidate changed since source-bound verification")
    if set(before) - set(values):
        raise RuntimeError("root has extra source files; an explicit removal review is required")
    out = ROOT / "verification/root-promotion-next25-attempt01"
    out.mkdir(parents=True, exist_ok=False)
    backup = out / "source-before"
    for path, body in before.items():
        dest = backup / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(body)
    rollback = [{"path": p, "action": "restore_backup" if p in before else "remove_added", "before_sha256": hashlib.sha256(before[p]).hexdigest() if p in before else None, "after_sha256": hashlib.sha256(b).hexdigest()} for p,b in sorted(values.items()) if before.get(p) != b]
    report = {"promoted": False, "candidate_source": str(STAGE), "source_before": manifest(before), "source_after_expected": rows, "rollback_map": rollback, "source_only": True, "historical_evidence_preserved": True, "acceptance_complete": False, "production_ready": False, "released": False}
    evidence = out / "promotion.json"
    evidence.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    if sources(ROOT) != before or sources(STAGE) != values:
        raise RuntimeError("root or candidate changed during backup")
    for path, body in values.items():
        if before.get(path) == body:
            continue
        dest = ROOT / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(body)
    report["root_matches_candidate"] = sources(ROOT) == values
    report["candidate_unchanged"] = sources(STAGE) == values
    report["promoted"] = report["root_matches_candidate"] and report["candidate_unchanged"]
    evidence.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    if not report["promoted"]:
        raise RuntimeError("promotion binding mismatch; source backup and rollback map are available")
    print(json.dumps({"promoted": True, "source_file_count": len(values), "source_before_count": len(before), "changed_files": len(rollback), "evidence": str(evidence)}), flush=True)


if __name__ == "__main__":
    main()
