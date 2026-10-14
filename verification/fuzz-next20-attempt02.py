"""Run the bounded repair-parser fuzz against the r9-next20 local source."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".staging/r9-next20"
OUT = STAGE / "verification/r9-next20/fuzz-attempt02"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def manifest_matches(frozen):
    return all(hashlib.sha256((STAGE / row["path"]).read_bytes()).hexdigest() == row["sha256"]
               for row in frozen["source_manifest"])


def main():
    OUT.mkdir(parents=True, exist_ok=False)
    gate = read(STAGE / "verification/r9-next20/local-gate-attempt02/local-summary.json")
    frozen = read(STAGE / "verification/r9-next20/local-gate-attempt02/source-manifest.json")
    if not gate.get("local_checks_pass"):
        raise RuntimeError("refusing fuzz before the next20 attempt02 local gate passes")
    if not manifest_matches(frozen):
        raise RuntimeError("source changed after next20 attempt02 local gate")
    raw = OUT / "repair-parser.log"
    command = ["go", "test", "./protocol", "-run=^$",
               "-fuzz=^FuzzDatagramRepairDecodeCanonical$", "-fuzztime=5s", "-parallel=2"]
    started = time.monotonic()
    with raw.open("xb") as output:
        result = subprocess.run(command, cwd=STAGE, env={**os.environ,
                                    "GOTOOLCHAIN": "local", "CGO_ENABLED": "0"},
                                 stdout=output, stderr=subprocess.STDOUT, timeout=60)
    after = manifest_matches(frozen)
    summary = {
        "revision": "v0.1-r9-next20",
        "source_manifest_sha256": frozen["manifest_sha256"],
        "command": command,
        "exit_code": result.returncode,
        "pass": result.returncode == 0 and after,
        "source_unchanged": after,
        "source_matches_local_manifest": after,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "raw_log": str(raw.relative_to(ROOT).as_posix()),
        "scope": "bounded 5-second repair-parser fuzz with 2 workers; not an independent security audit or complete fuzz campaign",
    }
    (OUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    raise SystemExit(0 if summary["pass"] else 1)


if __name__ == "__main__":
    main()

