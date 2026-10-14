"""Bind a release's files, ZIP and frozen source to current project inputs."""
import argparse
import hashlib
import json
import pathlib
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def verify(package, baseline_package=None):
    package = pathlib.Path(package).resolve(strict=True)
    manifest = json.loads((package / "release-manifest.json").read_text())
    errors = []
    with zipfile.ZipFile(str(package) + ".zip") as archive:
        names = archive.namelist()
        expected = {v["path"] for v in manifest["files"]} | {"release-manifest.json"}
        if len(names) != len(set(names)) or set(names) != expected:
            errors.append("ZIP member set mismatch")
        for row in manifest["files"]:
            raw = (package / row["path"]).read_bytes()
            if hashlib.sha256(raw).hexdigest() != row["sha256"] or len(raw) != row["bytes"]:
                errors.append("payload:" + row["path"])
            if row["path"] not in names or archive.read(row["path"]) != raw:
                errors.append("ZIP:" + row["path"])
        if archive.read("release-manifest.json") != (package / "release-manifest.json").read_bytes():
            errors.append("ZIP:release-manifest.json")
    frozen = json.loads((package / "source-manifest.json").read_text())
    for row in frozen:
        data = (package / "source" / row["path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != row["sha256"]:
            errors.append("frozen:" + row["path"])
        kind, relative = row["path"].split("/", 1)
        current = (ROOT / relative if kind == "bfp" else ROOT / "integrations/mihomo/source" / relative).read_bytes()
        if kind == "mihomo" and relative == "go.mod":
            current = current.replace(b"replace bfp => ../../..", b"replace bfp => ../bfp")
        if data != current:
            errors.append("current:" + row["path"])
    # File integrity and source comparison are separate from execution tests.
    # A hardcoded old test baseline can lack later files and cannot prove that
    # a newly packaged binary has passed those historical tests.
    baseline = None
    if baseline_package is not None:
        old = pathlib.Path(baseline_package).resolve(strict=True)
        old_manifest = json.loads((old / "source-manifest.json").read_text())
        prior = {row["path"]: row["sha256"] for row in old_manifest}
        current = {row["path"]: row["sha256"] for row in frozen}
        changed = sorted(path for path in prior.keys() | current.keys() if prior.get(path) != current.get(path))
        baseline = {"package": str(old), "source_manifest_sha256": hashlib.sha256((old / "source-manifest.json").read_bytes()).hexdigest(),
                    "changed_sources": changed, "native_sources_unchanged": not any(path.startswith("mihomo/") for path in changed)}
    return {"pass": not errors, "errors": errors, "package": str(package), "version": manifest["version"],
            "zip_sha256": hashlib.sha256(pathlib.Path(str(package) + ".zip").read_bytes()).hexdigest(),
            "payload_files": len(manifest["files"]) + 1, "bfp_source_files": manifest["bfp_source_files"],
            "native_source_files": manifest["native_source_files"], "source_matches_current": not any(x.startswith("current:") for x in errors),
            "baseline_comparison": baseline, "execution_tests_included": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--baseline-package")
    args = parser.parse_args()
    result = verify(args.package, args.baseline_package)
    pathlib.Path(args.result).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result))
    raise SystemExit(0 if result["pass"] else 1)
