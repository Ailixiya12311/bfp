"""Build a private diagnostic client from frozen inputs; preserve public releases."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--attempt", required=True, type=int)
args = parser.parse_args()
if args.attempt < 4:
    raise ValueError("use a new diagnostic attempt")
parent = ROOT / "credentials-client-ready"
target = parent / f"tun-debug{args.attempt:02d}"
public = ROOT / "dist/BFP-Client-Windows-0.1.0-preview.7"
profile = parent / "BFP 客户端/client/credentials/client.json"
launcher = ROOT / f"verification/product-windows-tun/launch-debug{args.attempt:02d}.ps1"
if target.exists() or launcher.exists() or target.resolve().parent != parent.resolve() or profile.is_symlink():
    raise RuntimeError("unexpected private diagnostic path")

# Select public module sources using the release builder. The native tree also
# contains embedded assets, notably ca-certificates.crt, so copy all its files.
spec = importlib.util.spec_from_file_location("bfp_native_builder", ROOT / "integrations/mihomo/build.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
native = ROOT / "integrations/mihomo/source"


def native_sources():
    return sorted(p for p in native.rglob("*") if p.is_file()
                  and not any(part.startswith(".") and part != ".github"
                              for part in p.relative_to(native).parts))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reject_links(root, files):
    for file in files:
        for part in (file, *file.parents):
            if part.is_symlink() or getattr(part.stat(), "st_file_attributes", 0) & 0x400:
                raise RuntimeError("linked source input is not supported")
            if part == root:
                break


core_files, native_files = builder.module_sources(ROOT), native_sources()
reject_links(ROOT, core_files)
reject_links(native, native_files)
before_core = builder.snapshot(ROOT, core_files)
before_native = builder.snapshot(native, native_files)
script_hash = sha256(pathlib.Path(__file__))
builder_hash = sha256(ROOT / "integrations/mihomo/build.py")

target.mkdir()
sid = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                      "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
                     capture_output=True, text=True, check=True).stdout.strip()
subprocess.run(["icacls.exe", str(target), "/inheritance:r", "/grant:r",
                "*" + sid + ":(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
               capture_output=True, check=True)
for item in public.iterdir():
    if item.name in {"source", "docs", "README.md", "client-manifest.json", "native-source-manifest.json"}:
        continue
    if item.is_dir():
        shutil.copytree(item, target / item.name)
    else:
        shutil.copyfile(item, target / item.name)
shutil.copyfile(ROOT / "deploy/windows-system-proxy.ps1", target / "deploy/windows-system-proxy.ps1")
descriptor = target / "deploy/portable-client.json"
identity = json.loads(descriptor.read_text(encoding="utf-8-sig"))
identity["instance_id"] = uuid.uuid4().hex
descriptor.write_text(json.dumps(identity, indent=2), encoding="utf-8-sig")
private = target / "client/credentials/client.json"
private.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(profile, private)
version = f"0.1.0-debug-tun{args.attempt:02d}"

core_copy, native_copy = target / "source/bfp", target / "source/mihomo"
builder.copy_files(ROOT, core_copy, core_files)
builder.copy_files(native, native_copy, native_files)
if builder.snapshot(core_copy, [core_copy / item["path"] for item in before_core]) != before_core:
    raise RuntimeError("core source changed during freeze")
if builder.snapshot(native_copy, [native_copy / item["path"] for item in before_native]) != before_native:
    raise RuntimeError("native source changed during freeze")
module = native_copy / "go.mod"
content = module.read_text(encoding="utf-8")
if len(re.findall(r"^replace bfp => .+$", content, re.M)) != 1:
    raise RuntimeError("unexpected BFP module binding")
module.write_text(re.sub(r"^replace bfp => .+$", "replace bfp => ../bfp", content, flags=re.M), encoding="utf-8")
frozen_files = sorted(p for p in (target / "source").rglob("*") if p.is_file())
frozen = builder.snapshot(target / "source", frozen_files)
source_manifest = target / "source-manifest.json"
source_manifest.write_text(json.dumps({
    "original_bfp": before_core, "original_native": before_native,
    "frozen": frozen, "module_binding": "replace bfp => ../bfp",
    "prepare_script_sha256": script_hash, "selection_script_sha256": builder_hash,
}, indent=2), encoding="utf-8")

environment = dict(os.environ, CGO_ENABLED="0", GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="", GOOS="windows", GOARCH="amd64")
binary = target / "client/bin/mihomo-bfp-windows-amd64.exe"
command = ["go", "build", "-mod=readonly", "-trimpath", "-tags", builder.TAGS,
           "-ldflags", "-s -w -X github.com/metacubex/mihomo/constant.Version=v1.19.32-bfp-" + version,
           "-o", str(binary), "./"]
toolchain = subprocess.run(["go", "version"], capture_output=True, text=True, env=environment, check=True).stdout.strip()
print(json.dumps({"stage": "building_frozen_source", "native_version": version,
                  "bfp_source_files": len(core_files), "native_source_files": len(native_files)}), flush=True)
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
build = subprocess.run(command, cwd=native_copy, env=environment, capture_output=True, text=True, timeout=300)
build_log = target / "build-evidence.json"
evidence = {
    "started_utc": started, "completed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "command": command, "cwd": "source/mihomo", "toolchain": toolchain,
    "environment": {key: environment[key] for key in ("CGO_ENABLED", "GOTOOLCHAIN", "GOWORK", "GOFLAGS", "GOOS", "GOARCH")},
    "exit_code": build.returncode, "stdout": build.stdout, "stderr": build.stderr,
    "source_manifest_sha256": sha256(source_manifest), "source_matches_frozen_inputs": False,
}
build_log.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
build.check_returncode()
if (builder.snapshot(target / "source", sorted(p for p in (target / "source").rglob("*") if p.is_file())) != frozen
        or builder.snapshot(ROOT, builder.module_sources(ROOT)) != before_core
        or builder.snapshot(native, native_sources()) != before_native
        or sha256(pathlib.Path(__file__)) != script_hash
        or sha256(ROOT / "integrations/mihomo/build.py") != builder_hash):
    raise RuntimeError("source changed while building")
version_info = subprocess.run(["go", "version", "-m", str(binary)], capture_output=True, text=True, env=environment, check=True).stdout
if "=>\t../bfp\t" not in version_info:
    raise RuntimeError("binary is not bound to the frozen BFP module")
evidence.update(source_matches_frozen_inputs=True, native_binary_sha256=sha256(binary), go_version_m=version_info)
build_log.write_text(json.dumps(evidence, indent=2), encoding="utf-8")

# Runtime checks bind the large source tree through a separate manifest instead
# of rehashing all frozen source files on every status request.
payload = []
for file in sorted(target.rglob("*")):
    relative = file.relative_to(target)
    if file.is_file() and "credentials" not in relative.parts and relative.parts[0] != "source":
        data = file.read_bytes()
        payload.append({"path": relative.as_posix(), "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest()})
manifest = {"version": version, "native_version": version, "product": "Private TUN diagnostic copy",
            "production_ready": False, "frozen_release": False, "files": payload,
            "source_matches_frozen_inputs": True,
            "source_manifest_path": "source-manifest.json", "source_manifest_sha256": sha256(source_manifest),
            "build_evidence_path": "build-evidence.json", "native_binary_sha256": sha256(binary)}
(target / "client-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8-sig")
launcher.write_text("$ErrorActionPreference = 'Stop'\n"
                    "$workspace = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)\n"
                    f"$client = Join-Path $workspace 'credentials-client-ready/tun-debug{args.attempt:02d}'\n"
                    f"$result = Join-Path $PSScriptRoot 'windows-tun-real-attempt{args.attempt:02d}.json'\n"
                    "& (Join-Path $PSScriptRoot 'verify-real.ps1') -ClientRoot $client -ResultPath $result\n"
                    "exit $LASTEXITCODE\n",
                    encoding="utf-8-sig")
print(json.dumps({"private_directory": str(target), "launcher": str(launcher),
                  "native_version": version, "frozen_release_changed": False,
                  "source_matches_frozen_inputs": True, "native_binary_sha256": sha256(binary)}))
