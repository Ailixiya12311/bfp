"""Build a portable Mihomo/BFP bundle from frozen source copies."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import uuid
import zipfile

EXCLUDED = {"bin", "dist", "docs", "lab", "verification", "third_party", "vendor"}
TAGS = "with_gvisor,no_tailscale"
UPSTREAM = "88dcbf7f1614a67c3b36b848ee3592dfa92ada36"


def module_sources(root):
    files = [root / name for name in ("go.mod", "go.sum") if (root / name).is_file()]
    for base, directories, names in os.walk(root, followlinks=False):
        base = pathlib.Path(base)
        directories[:] = [name for name in sorted(directories)
                          if not name.startswith((".", "_")) and name not in EXCLUDED
                          and not (base / name).is_symlink() and not (base / name / "go.mod").is_file()]
        files.extend(base / name for name in names if name.endswith(".go"))
    return sorted(files)


def entry(file, base):
    data = file.read_bytes()
    return {"path": file.relative_to(base).as_posix(), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def snapshot(root, files):
    return [entry(file, root) for file in files]


def copy_files(source, destination, files):
    for file in files:
        if file.is_symlink():
            raise RuntimeError("linked source is not supported")
        target = destination / file.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, target)


def defaults():
    base = pathlib.Path(__file__).resolve().parent
    if (base / "source/go.mod").is_file():
        return base.parents[1], base / "source", base
    if (base / "bfp/go.mod").is_file() and (base / "mihomo/go.mod").is_file():
        return base / "bfp", base / "mihomo", base
    raise RuntimeError("BFP and Mihomo source directories are missing")


def build(args):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", args.version):
        raise ValueError("invalid version")
    core, native, assets = defaults()
    output = pathlib.Path(args.output_root).resolve()
    output.mkdir(parents=True, exist_ok=True)
    final = output / ("BFP-Mihomo-" + args.version)
    archive = output / (final.name + ".zip")
    if final.exists() or archive.exists():
        raise RuntimeError("output already exists; choose a new version or output directory")
    stage = output / (".bfp-mihomo-" + uuid.uuid4().hex)
    stage.mkdir()
    stage_archive = output / (stage.name + ".zip")
    core_files = module_sources(core)
    native_files = sorted(p for p in native.rglob("*") if p.is_file() and not any(part.startswith(".") and part != ".github" for part in p.relative_to(native).parts))
    before_core, before_native = snapshot(core, core_files), snapshot(native, native_files)
    try:
        core_copy, native_copy = stage / "source/bfp", stage / "source/mihomo"
        copy_files(core, core_copy, core_files)
        copy_files(native, native_copy, native_files)
        module = native_copy / "go.mod"
        content = module.read_text(encoding="utf-8")
        if len(re.findall(r"^replace bfp => .+$", content, re.M)) != 1:
            raise RuntimeError("unexpected BFP module binding")
        module.write_text(re.sub(r"^replace bfp => .+$", "replace bfp => ../bfp", content, flags=re.M), encoding="utf-8")
        frozen = snapshot(stage / "source", sorted(p for p in (stage / "source").rglob("*") if p.is_file()))
        (stage / "source-manifest.json").write_text(json.dumps(frozen, indent=2), encoding="utf-8")
        shutil.copyfile(__file__, stage / "source/build-mihomo.py")
        shutil.copytree(assets / "templates", stage / "source/templates")
        for file in (assets / "templates").rglob("*"):
            if file.is_file():
                target = stage / file.relative_to(assets / "templates")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(file, target)
        license_dir = stage / "licenses"
        license_dir.mkdir()
        shutil.copyfile(native / "LICENSE", license_dir / "Mihomo-GPL-3.0.txt")
        binaries = stage / "bin"
        binaries.mkdir()
        built = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        environment = dict(os.environ, GOTOOLCHAIN="local", GOWORK="off", GOARCH="amd64", CGO_ENABLED="0", GOFLAGS="")
        if args.offline:
            environment.update(GOPROXY="off", GOSUMDB="off")
        logs = []
        for platform in ("windows", "linux"):
            environment["GOOS"] = platform
            suffix = ".exe" if platform == "windows" else ""
            builds = [
                (core_copy, "bfp", "./cmd/bfp", [], "-s -w -X main.buildVersion=" + args.version + " -X main.buildCommit=uncommitted -X main.buildDate=" + built),
                (native_copy, "mihomo-bfp", "./", ["-tags", TAGS], "-s -w -X github.com/metacubex/mihomo/constant.Version=v1.19.32-bfp-" + args.version + " -X github.com/metacubex/mihomo/constant.BuildTime=" + built),
            ]
            for source, name, package, flags, ldflags in builds:
                target = binaries / (name + "-" + platform + "-amd64" + suffix)
                print(json.dumps({"stage": "building", "platform": platform, "program": name}), flush=True)
                result = subprocess.run(["go", "build", "-mod=readonly", "-trimpath"] + flags + ["-ldflags", ldflags, "-o", str(target), package], cwd=source, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
                logs.append({"platform": platform, "program": name, "exit_code": result.returncode, "output": result.stdout})
                if result.returncode:
                    raise RuntimeError("build failed: " + name + "/" + platform + "\n" + result.stdout[-6000:])
        after = snapshot(stage / "source", [stage / "source" / item["path"] for item in frozen])
        if after != frozen or snapshot(core, core_files) != before_core or snapshot(native, native_files) != before_native:
            raise RuntimeError("source changed while building")
        payload = [entry(p, stage) for p in sorted(stage.rglob("*")) if p.is_file()]
        manifest = {"version": args.version, "built_utc": built, "product": "BFP native Mihomo bundle", "upstream_commit": UPSTREAM, "build_tags": TAGS.split(","), "operator_credentials_included": False, "production_ready": False, "acceptance_complete": False, "bfp_source_files": len(core_files), "native_source_files": len(native_files), "source_matches_frozen_inputs": True, "binaries": [entry(p, stage) for p in sorted(binaries.iterdir())], "files": payload, "builds": logs}
        (stage / "release-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        with zipfile.ZipFile(stage_archive, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
            for file in sorted(stage.rglob("*")):
                if file.is_file():
                    bundle.write(file, file.relative_to(stage).as_posix())
        if stage.parent != output or final.parent != output or archive.parent != output:
            raise RuntimeError("package escaped its output directory")
        stage.rename(final)
        stage_archive.rename(archive)
        print(json.dumps({"stage": "built", "package": str(final), "zip": str(archive), "zip_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}), flush=True)
        return final
    finally:
        for temporary in (stage, stage_archive):
            if temporary.parent != output or not temporary.name.startswith(".bfp-mihomo-"):
                raise RuntimeError("unsafe staging cleanup path")
            if temporary.is_dir():
                shutil.rmtree(temporary)
            elif temporary.is_file():
                temporary.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="0.1.0-preview.11")
    parser.add_argument("--output-root", default="dist")
    parser.add_argument("--offline", action="store_true", help="use already cached Go modules only")
    build(parser.parse_args())
