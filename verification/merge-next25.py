"""Merge frozen next25 slices by comparison with the exact next24 source parent.

Only Go/module files change. Historical evidence and the pre-merge lifecycle
source remain in place, with an explicit source-only backup for reversal.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PARENT = ROOT / ".staging/r9-next24"
TARGET = ROOT / ".staging/r9-next25"
BRANCHES = (ROOT / ".staging/r9-next25-cli", ROOT / ".staging/r9-next25-connect")
DIRS = ("adapter", "classification", "clientconfig", "cmd", "gateway", "internal", "obfuscation", "protocol", "scheduler", "security", "session", "tests")


def sources(directory):
    paths = [directory / "go.mod", directory / "go.sum"]
    for name in DIRS:
        paths.extend((directory / name).rglob("*.go"))
    return {p.relative_to(directory).as_posix(): p.read_bytes() for p in sorted(paths)}


def manifest(values):
    return [{"path": p, "sha256": hashlib.sha256(b).hexdigest()} for p, b in sorted(values.items())]


def main():
    out = TARGET / "verification/integration-merge"
    if out.exists():
        raise RuntimeError("integration merge evidence already exists")
    parent, before = sources(PARENT), sources(TARGET)
    merged = dict(before)
    participants = []
    for branch in BRANCHES:
        values = sources(branch)
        removed = set(parent) - set(values)
        if removed:
            raise RuntimeError("slice unexpectedly removes source files")
        changes = {p: b for p, b in values.items() if parent.get(p) != b}
        for path, body in changes.items():
            if merged.get(path) != parent.get(path) and merged.get(path) != body:
                raise RuntimeError("source merge conflict: " + path)
            merged[path] = body
        participants.append({"branch": str(branch), "source_manifest": manifest(values), "changes": manifest(changes)})
    out.mkdir(parents=True)
    backup = out / "lifecycle-source-before-merge"
    for path, body in before.items():
        destination = backup / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
    # Complete all conflict/binding checks and the backup before changing source.
    for row in participants:
        if manifest(sources(Path(row["branch"]))) != row["source_manifest"]:
            raise RuntimeError("slice changed during merge preparation")
    if sources(PARENT) != parent or sources(TARGET) != before:
        raise RuntimeError("source changed during merge preparation")
    for path, body in merged.items():
        if before.get(path) == body:
            continue
        destination = TARGET / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
    if sources(TARGET) != merged or sources(PARENT) != parent:
        raise RuntimeError("merged source or parent binding mismatch")
    report = {"candidate": "r9-next25", "parent": str(PARENT), "parent_source_manifest": manifest(parent), "lifecycle_before": manifest(before), "participants": participants, "merged_source_manifest": manifest(merged), "source_file_count": len(merged), "only_go_module_files_changed": True, "inherited_pass_used": False, "acceptance_complete": False, "production_ready": False, "released": False}
    (out / "merge-manifest.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"source_file_count": len(merged), "changes": [r["changes"] for r in participants], "manifest": str(out / "merge-manifest.json")}), flush=True)


if __name__ == "__main__":
    main()
