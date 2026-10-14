"""Append the completed debug07 TUN run and subsequent local work, read-only to releases."""
import datetime
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
FOLDER = ROOT / "verification/product-windows-tun"
OUTPUT = FOLDER / "release-client-preview7-tun-attempt07.json"
if OUTPUT.exists():
    raise RuntimeError("preserve existing attempt07 handoff")


def read(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8-sig"))


def digest(relative):
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


result_path = "verification/product-windows-tun/windows-tun-real-attempt07.json"
audit_path = "verification/product-windows-tun/windows-tun-real-attempt07-audit.json"
result, audit = read(result_path), read(audit_path)
if (result["native_version"] != "0.1.0-debug-tun07"
        or result["pass"] is not False or audit["final_cleanup_pass"] is not True):
    raise RuntimeError("unexpected attempt07 outcome")
for entry in audit["preserved_logs"]:
    if digest(entry["path"]) != entry["sha256"]:
        raise RuntimeError("attempt07 retained log changed")
baseline = read("verification/product-windows-tun/release-client-preview7.json")
public_zips = {}
for name in ("client", "native"):
    relative = baseline[name + "_zip"]
    value = digest(relative)
    if value != baseline[name + "_zip_sha256"]:
        raise RuntimeError("public release ZIP changed")
    public_zips[name] = {"path": relative, "sha256": value}
diagnostic = read("credentials-client-ready/tun-debug08/client-manifest.json")
build = read("credentials-client-ready/tun-debug08/build-evidence.json")
binary = "credentials-client-ready/tun-debug08/client/bin/mihomo-bfp-windows-amd64.exe"
if (digest(binary) != diagnostic["native_binary_sha256"]
        or diagnostic["native_binary_sha256"] != build["native_binary_sha256"]
        or digest("credentials-client-ready/tun-debug08/source-manifest.json") != diagnostic["source_manifest_sha256"]):
    raise RuntimeError("next diagnostic build binding mismatch")
local_paths = ["verification/product-windows-tun/raw-business-boundary-source.json",
               "verification/product-windows-tun/gvisor-relay-local.json"]
local = [{"path": path, "sha256": digest(path), "evidence": read(path)} for path in local_paths]
record = {
    "time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "supplements": "verification/product-windows-tun/release-client-preview7.json",
    "current_delivered_client_version": "0.1.0-preview.7",
    "current_delivered_native_version": "0.1.0-preview.36",
    "public_zips_unchanged": True, "public_zips": public_zips,
    "windows_tun": {
        "result": result_path, "result_sha256": digest(result_path),
        "audit": audit_path, "audit_sha256": digest(audit_path),
        "run_id": result["run_id"], "executed_native_version": result["native_version"],
        "ready": audit["tun_ready"], "https_verified": audit["https_pass"],
        "force_termination_executed": audit["force_termination_executed"],
        "final_cleanup_verified": audit["final_cleanup_pass"],
        "elapsed_seconds": result["elapsed_seconds"], "time_budget_met": result["time_budget_met"],
        "termination_events": audit["termination_events"],
        "root_cause_confirmed": False, "tun_fixed": False,
        "stop_boundary": audit["stop_boundary"],
    },
    "local_followup": local,
    "next_diagnostic": {
        "version": diagnostic["native_version"], "root": "credentials-client-ready/tun-debug08",
        "native_binary_sha256": diagnostic["native_binary_sha256"],
        "source_manifest_sha256": diagnostic["source_manifest_sha256"],
        "source_matches_frozen_inputs": build["source_matches_frozen_inputs"],
        "tun_executed": False, "new_uac_authorization_required": True,
        "scope": "raw business cancellation caller before cancellation; invalid Fake-IP retry fix; launcher exit-code propagation",
        "not_confirmed_tls_fix": True, "private_credentials_included": True, "safe_to_share": False,
    },
    "singapore_used": False, "remote_servers_modified": False,
    "client_final_state_at_attempt07_cleanup": "stopped",
    "acceptance_complete": False, "production_ready": False,
}
with OUTPUT.open("x", encoding="utf-8") as handle:
    json.dump(record, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
print(json.dumps({"handoff": str(OUTPUT), "tun_fixed": False,
                  "cleanup_pass": True, "public_zips_unchanged": True}))
