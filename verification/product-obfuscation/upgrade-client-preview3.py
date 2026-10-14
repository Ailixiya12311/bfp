"""Replace the stopped private client with preview.3, retaining its profile."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "deploy"))
import pilot

parent = ROOT / "credentials-client-ready"
current = parent / "BFP 客户端"
backup = parent / "BFP 客户端-preview.2"
stage = parent / "BFP 客户端-preview.3"
public = ROOT / "dist/BFP-Client-Windows-0.1.0-preview.3"
record = ROOT / "deploy/runs/66af4a892648df0a6249d6af3947af68/client-upgrade-preview3.json"
if backup.exists() or stage.exists():
    raise RuntimeError("upgrade targets already exist")
for target in (current, backup, stage):
    if target.resolve().parent != parent.resolve() or target.is_symlink():
        raise RuntimeError("upgrade path escaped the private parent directory")

stop = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                       str(current / "deploy/windows-client.ps1"), "-Action", "stop", "-Json"],
                      capture_output=True, text=True, timeout=30)
if stop.returncode or not json.loads(stop.stdout).get("cleanup_complete"):
    raise RuntimeError("existing client could not be stopped")

stage.mkdir()
sid = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                      "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
                     capture_output=True, text=True, check=True).stdout.strip()
subprocess.run(["icacls.exe", str(stage), "/inheritance:r", "/grant:r",
                "*" + sid + ":(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
               capture_output=True, check=True)
shutil.copytree(public, stage, dirs_exist_ok=True)
old_profile = current / "client/credentials/client.json"
new_profile = stage / "client/credentials/client.json"
if old_profile.is_symlink() or not old_profile.is_file():
    raise RuntimeError("existing profile is not a regular file")
new_profile.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(old_profile, new_profile)
if hashlib.sha256(old_profile.read_bytes()).digest() != hashlib.sha256(new_profile.read_bytes()).digest():
    raise RuntimeError("profile changed during copy")
current.rename(backup)
try:
    stage.rename(current)
except Exception:
    backup.rename(current)
    raise
result = {"time_utc": pilot.utc(), "upgraded": True, "client_version": "0.1.0-preview.3",
          "native_version": "0.1.0-preview.32", "profile_preserved": True,
          "entrypoint": str(current / "BFP客户端.cmd"), "rollback_directory": str(backup),
          "client_is_stopped": True, "public_credentials_included": False}
pilot.write_public_atomic(record, result)
print(json.dumps(result, ensure_ascii=False))
