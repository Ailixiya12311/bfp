"""Apply this specific release to the existing owned pilot; preserve profiles."""
import json
import pathlib
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "deploy"))
import pilot

INSTANCE = "66af4a892648df0a6249d6af3947af68"
PUBLIC_FILES = ("bin/bfp-windows-amd64.exe", "bin/mihomo-bfp-windows-amd64.exe",
                "start-native.ps1", "configs/native-proxy.yaml", "configs/native-tun.yaml")


def require_role(report, role, running):
    result = report["roles"][role]
    if "error" in result or (running and not result.get("running")) or (
            not running and not result.get("directory_removed")):
        raise pilot.LabError("pilot upgrade step failed: " + role)
    return report


def main():
    evidence = {"time_utc": pilot.utc(), "instance_id": INSTANCE, "steps": [],
                "credentials_preserved": True, "production_ready": False}
    record = ROOT / "deploy/runs" / INSTANCE / "upgrade-preview23.json"
    with pilot.command_lock():
        state = pilot.load()
        if state["instance_id"] != INSTANCE or state["root_version"] != "0.1.0-preview.22":
            raise pilot.LabError("upgrade requires the original preview.22 pilot")
        previous = {key: state[key] for key in
                    ("root_package", "root_version", "native_package", "linux_sha256")}
        evidence["previous"] = previous
        root_package = ROOT / "dist/BFP-0.1.0-preview.23"
        native_package = ROOT / "dist/BFP-Mihomo-0.1.0-preview.32"
        linux = pilot.checked_file(root_package, "bin/bfp-linux-amd64")
        payload = {name: pilot.checked_file(native_package, name) for name in PUBLIC_FILES}
        native = pathlib.Path(state["windows_client"])
        if native.resolve() != (pathlib.Path(state["private_directory"]) / "windows-client").resolve():
            raise pilot.LabError("unexpected desktop payload directory")
        changed = False
        try:
            for role in ("sender", "receiver"):
                result = require_role(pilot.operate("stop", [role], via_receiver=True), role, False)
                evidence["steps"].append(result)
            changed = True
            for name, source in payload.items():
                shutil.copyfile(source, native / name)
            state = pilot.load()
            state.update(root_package=str(root_package), root_version="0.1.0-preview.23",
                         native_package=str(native_package), linux_sha256=pilot.digest(linux))
            state["events"].append({"time_utc": pilot.utc(), "action": "upgrade",
                                    "previous": previous, "root_version": state["root_version"]})
            pilot.save(state)
            for role in ("receiver", "sender"):
                result = require_role(pilot.operate("start", [role], via_receiver=True), role, True)
                if result["roles"][role]["binary_sha256"] != state["linux_sha256"]:
                    raise pilot.LabError("started pilot does not match new binary")
                evidence["steps"].append(result)
                pilot.write_public_atomic(record, evidence)
            evidence.update(pass_=True, new_root_version=state["root_version"],
                            new_linux_sha256=state["linux_sha256"])
        except Exception as exc:
            evidence["error"] = pilot.SANITIZER.text(str(exc))[:640]
            rollback = []
            try:
                for role in ("sender", "receiver"):
                    rollback.append(require_role(pilot.operate("stop", [role], via_receiver=True), role, False))
                if changed:
                    old_native = pathlib.Path(previous["native_package"])
                    for name in PUBLIC_FILES:
                        shutil.copyfile(pilot.checked_file(old_native, name), native / name)
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
    print(json.dumps({"upgraded": True, "instance_id": INSTANCE,
                      "root_version": evidence["new_root_version"], "record": str(record)}))


if __name__ == "__main__":
    main()
