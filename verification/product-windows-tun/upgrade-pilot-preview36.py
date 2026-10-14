"""Upgrade the existing owned BFP pilot, preserving profiles and rollback."""
import json
import os
import pathlib
import shutil
import sys
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "deploy"))
import pilot

INSTANCE = "66af4a892648df0a6249d6af3947af68"
PACKAGE = ROOT / "dist/BFP-Mihomo-0.1.0-preview.36"
PUBLIC_FILES = ("bin/bfp-windows-amd64.exe", "bin/mihomo-bfp-windows-amd64.exe",
                "start-native.ps1", "windows-tun-support.ps1", "windows-tun-cleanup.ps1",
                "configs/native-proxy.yaml", "configs/native-tun.yaml")


def replace_payload(source, destination):
    """A failed copy must not leave a truncated active or rollback payload."""
    temporary = destination.with_name(".bfp-upgrade-" + uuid.uuid4().hex)
    try:
        shutil.copyfile(source, temporary)
        if pilot.digest(temporary) != pilot.digest(source):
            raise pilot.LabError("staged upgrade payload mismatch")
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def require_role(report, role, running):
    value = report["roles"][role]
    if "error" in value or (running and not value.get("running")) or (
            not running and not value.get("directory_removed")):
        raise pilot.LabError("pilot upgrade step failed: " + role)
    return report


def main():
    record = ROOT / "deploy/runs" / INSTANCE / "upgrade-preview36.json"
    if record.exists():
        raise pilot.LabError("preserve the existing upgrade record")
    evidence = {"time_utc": pilot.utc(), "instance_id": INSTANCE, "steps": [],
                "credentials_preserved": True, "production_ready": False, "pass": False}
    with pilot.command_lock():
        state = pilot.load()
        if state["instance_id"] != INSTANCE or state["root_version"] != "0.1.0-preview.23":
            raise pilot.LabError("unexpected existing pilot version")
        previous = {name: state[name] for name in
                    ("root_package", "root_version", "native_package", "linux_sha256")}
        linux = pilot.checked_file(PACKAGE, "bin/bfp-linux-amd64")
        payload = {name: pilot.checked_file(PACKAGE, name) for name in PUBLIC_FILES}
        native = pathlib.Path(state["windows_client"])
        if native.resolve() != (pathlib.Path(state["private_directory"]) / "windows-client").resolve():
            raise pilot.LabError("unexpected pilot client directory")
        old_package = pathlib.Path(previous["native_package"])
        old_files = {item["path"] for item in json.loads(
            (old_package / "release-manifest.json").read_text(encoding="utf-8-sig"))["files"]}
        old_payload = {name: pilot.checked_file(old_package, name) if name in old_files else None
                       for name in PUBLIC_FILES}
        for name, source in old_payload.items():
            existing = native / name
            if existing.is_symlink() or (source is None and existing.exists()) or (
                    source is not None and (not existing.is_file() or pilot.digest(existing) != pilot.digest(source))):
                raise pilot.LabError("existing pilot client payload mismatch: " + name)
        # Check both pinned hosts and the original process identities before
        # the first stop. An unreachable sender must not interrupt receiver.
        before = pilot.operate("status", ["receiver", "sender"], via_receiver=True)
        for role in ("receiver", "sender"):
            current = require_role(before, role, True)["roles"][role]
            if not current.get("owner_verified") or current.get("binary_sha256") != previous["linux_sha256"]:
                raise pilot.LabError("existing pilot process identity mismatch: " + role)
        evidence["previous"] = previous
        evidence["before"] = before
        pilot.write_public_atomic(record, evidence)
        changed = False
        interrupted = False
        try:
            # Fill the public content-addressed caches while old services are
            # still running. Singapore's upload must not extend downtime.
            evidence["preloaded_public_binary"] = {}
            hosts = pilot.load_hosts()
            for role in ("receiver", "sender"):
                with pilot.connect_remote(hosts, role, via_receiver=True) as remote:
                    run = pilot.RemoteRun(remote, INSTANCE)
                    evidence["preloaded_public_binary"][role] = pilot.upload_cached(
                        run, linux, "upgrade-preview36-ready")
                pilot.write_public_atomic(record, evidence)
            interrupted = True
            for role in ("sender", "receiver"):
                evidence["steps"].append(require_role(pilot.operate("stop", [role], via_receiver=True), role, False))
                pilot.write_public_atomic(record, evidence)
            changed = True
            for name, file in payload.items():
                replace_payload(file, native / name)
            state = pilot.load()
            state.update(root_package=str(PACKAGE), root_version="0.1.0-preview.36",
                         native_package=str(PACKAGE), linux_sha256=pilot.digest(linux))
            state["events"].append({"time_utc": pilot.utc(), "action": "upgrade",
                                    "previous": previous, "root_version": state["root_version"]})
            pilot.save(state)
            for role in ("receiver", "sender"):
                result = require_role(pilot.operate("start", [role], via_receiver=True), role, True)
                if result["roles"][role]["binary_sha256"] != state["linux_sha256"]:
                    raise pilot.LabError("new pilot binary mismatch: " + role)
                evidence["steps"].append(result)
                pilot.write_public_atomic(record, evidence)
            evidence.update(new_root_version=state["root_version"],
                            new_linux_sha256=state["linux_sha256"])
            evidence["pass"] = True
        except Exception as error:
            evidence["error"] = pilot.SANITIZER.text(str(error))[:640]
            if not interrupted:
                evidence["no_service_stop_requested"] = True
                pilot.write_public_atomic(record, evidence)
                raise
            rollback = []
            try:
                for role in ("sender", "receiver"):
                    rollback.append(require_role(pilot.operate("stop", [role], via_receiver=True), role, False))
                if changed:
                    for name, source in old_payload.items():
                        destination = native / name
                        if source is not None:
                            replace_payload(source, destination)
                        elif destination.exists():
                            if destination.is_symlink() or pilot.digest(destination) != pilot.digest(payload[name]):
                                raise pilot.LabError("introduced rollback file was changed: " + name)
                            destination.unlink()
                    state = pilot.load()
                    state.update(previous)
                    pilot.save(state)
                for role in ("receiver", "sender"):
                    rollback.append(require_role(pilot.operate("start", [role], via_receiver=True), role, True))
                evidence["rollback_complete"] = True
            except Exception as rollback_error:
                evidence["rollback_error"] = pilot.SANITIZER.text(str(rollback_error))[:640]
            evidence["rollback"] = rollback
            pilot.write_public_atomic(record, evidence)
            raise
        pilot.write_public_atomic(record, evidence)
    print(json.dumps({"upgraded": True, "record": str(record), "version": "0.1.0-preview.36"}))


if __name__ == "__main__":
    main()
