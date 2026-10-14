"""Run one source-bound Linux race for frozen r9-next23.

This wrapper intentionally delegates container ownership, snapshots and cleanup
to lab.race. It adds a strict source-manifest binding for the frozen local gate
and includes clientconfig, which is outside the historical race SOURCE_DIRS.
No source or Go/module file is changed by this script.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".staging/r9-next23"
GATE = STAGE / "verification/r9-next23/local-gate-attempt01"
FROZEN_MANIFEST = GATE / "source-manifest.json"
LOCAL_SUMMARY = GATE / "local-summary.json"
sys.path.insert(0, str(ROOT / "lab"))
import remote  # noqa: E402
import race  # noqa: E402

remote.WORKSPACE = race.WORKSPACE = STAGE
race.SOURCE_DIRS = (
    "adapter", "classification", "clientconfig", "cmd", "gateway", "internal",
    "obfuscation", "protocol", "scheduler", "security", "session", "tests",
)

summary = json.loads(LOCAL_SUMMARY.read_text(encoding="utf-8"))
frozen = json.loads(FROZEN_MANIFEST.read_text(encoding="utf-8"))
if not summary.get("local_checks_pass") or not summary.get("source_unchanged"):
    raise RuntimeError("next23 local gate is not a passing unchanged source boundary")
if summary.get("source_file_count") != 194 or len(frozen.get("source_manifest", [])) != 194:
    raise RuntimeError("next23 local gate must bind exactly 194 source files")
expected = [
    {
        "path": row["path"],
        "bytes": (STAGE / row["path"]).stat().st_size,
        "sha256": row["sha256"],
    }
    for row in frozen["source_manifest"]
]
if not any(row["path"].startswith("clientconfig/") for row in expected):
    raise RuntimeError("frozen local manifest does not include clientconfig")

original_freeze = race.freeze_source


def bound_freeze(output):
    archive, manifest, vendor_hash = original_freeze(output)
    comparable = [
        {"path": row["path"], "bytes": row["bytes"], "sha256": row["sha256"]}
        for row in manifest
    ]
    if comparable != expected:
        raise RuntimeError("race source copy differs from frozen next23 local gate")
    output.joinpath("source-bound.json").write_text(
        json.dumps(
            {
                "revision": frozen.get("revision"),
                "file_count": len(comparable),
                "local_manifest_sha256": hashlib.sha256(FROZEN_MANIFEST.read_bytes()).hexdigest(),
                "race_source_manifest_sha256": hashlib.sha256(
                    json.dumps(comparable, separators=(",", ":")).encode()
                ).hexdigest(),
                "clientconfig_included": True,
                "vendor_tree_sha256": vendor_hash,
                "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "source_unchanged_before_upload": True,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return archive, manifest, vendor_hash


race.freeze_source = bound_freeze

hosts_inventory = Path(r"C:\Users\developer\Desktop\cold\servers-unredacted.md")
race.load_hosts = lambda: remote.load_hosts(inventory=hosts_inventory)

OUT = STAGE / "verification/r9-next23/race-snapshots-attempt01"
OUT.mkdir(parents=True, exist_ok=False)

# Record process/config identity fingerprints only. The helper never returns
# command-line or credential contents and is attached to the existing audited
# receiver snapshot path.
IDENTITY = r'''
import hashlib,json,os,pathlib
records=[]
def digest_file(path,limit):
    try:
        data=path.read_bytes()
        if len(data)>limit:return {'status':'size_limit'}
        return {'status':'ok','sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
    except (OSError,ValueError):return {'status':'unavailable'}
for name in os.listdir('/proc'):
    if not name.isdigit():continue
    p=pathlib.Path('/proc')/name
    try:
        comm=(p/'comm').read_text().strip()
        if comm!='xray':continue
        raw=(p/'cmdline').read_bytes()
        records.append({'pid':int(name),'cmdline_sha256':hashlib.sha256(raw).hexdigest(),'executable':digest_file(p/'exe',64*1024*1024)})
    except (OSError,ValueError):records.append({'pid':int(name),'status':'unavailable'})
print(json.dumps({'processes':sorted(records,key=lambda x:x['pid']),'scope':'xray endpoint fingerprints only; no contents; no continuous identity proof'}))
'''


class AuditedRemote(remote.Remote):
    snapshots = 0

    def snapshot(self):
        value = super().snapshot()
        value["xray_identity_observation"] = self.python(IDENTITY, timeout=20)
        phase = "before" if self.snapshots == 0 else "after"
        self.snapshots += 1
        path = OUT / f"{phase}.json"
        if path.exists():
            raise RuntimeError(f"duplicate persisted {phase} snapshot")
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        return value


race.Remote = AuditedRemote
linux_binary = next(
    row for row in summary["binaries"] if row.get("platform") == "linux"
)
if not isinstance(linux_binary.get("sha256"), str) or len(linux_binary["sha256"]) != 64:
    raise RuntimeError("local gate Linux binary hash is missing or malformed")

print(
    json.dumps(
        {
            "stage": "source_bound_before_remote",
            "revision": frozen.get("revision"),
            "source_file_count": len(expected),
            "clientconfig_included": True,
            "local_manifest_sha256": hashlib.sha256(FROZEN_MANIFEST.read_bytes()).hexdigest(),
            "linux_binary_sha256": linux_binary["sha256"],
            "receiver": "192.0.2.10",
            "image": "ded31c68586d",
            "network": "none",
            "timeout_seconds": 360,
            "inventory_source": str(hosts_inventory),
        },
        ensure_ascii=False,
    ),
    flush=True,
)
report, path = race.execute(linux_binary["sha256"], timeout=360)
public = {
    "run_id": report.get("run_id"),
    "pass": report.get("pass"),
    "path": str(path),
    "source_bound": True,
    "source_file_count": len(expected),
    "clientconfig_included": True,
    "receiver": "192.0.2.10",
    "image": "ded31c68586d",
    "network": "none",
    "before_snapshot": str(OUT / "before.json"),
    "after_snapshot": str(OUT / "after.json"),
    "error": report.get("error"),
}
print(json.dumps(public, ensure_ascii=False), flush=True)
raise SystemExit(0 if report.get("pass") else 1)
