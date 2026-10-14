"""Retain attempt06 and debug07 evidence without overwriting any previous run."""
import datetime
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
FOLDER = ROOT / "verification/product-windows-tun"
HANDOFF = FOLDER / "release-client-preview7-tun-attempt06.json"
PROXY_AUDIT = FOLDER / "proxy-debug07-real-audit.json"
if HANDOFF.exists() or PROXY_AUDIT.exists():
    raise RuntimeError("preserve existing supplemental evidence")


def read(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8-sig"))


def digest(relative):
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


tun = read("verification/product-windows-tun/windows-tun-real-attempt06.json")
audit = read("verification/product-windows-tun/windows-tun-real-attempt06-audit.json")
proxy = read("verification/product-windows-tun/proxy-debug07-real.json")
debug = read("credentials-client-ready/tun-debug07/client-manifest.json")
build = read("credentials-client-ready/tun-debug07/build-evidence.json")
baseline = read("verification/product-windows-tun/release-client-preview7.json")
for name in ("client", "native"):
    if digest(baseline[name + "_zip"]) != baseline[name + "_zip_sha256"]:
        raise RuntimeError("frozen public ZIP changed")
for item in audit["preserved_logs"]:
    if digest(item["path"]) != item["sha256"]:
        raise RuntimeError("retained attempt06 log changed")
if tun["client_version"] != "0.1.0-debug-tun06" or tun["native_version"] != "0.1.0-debug-tun06":
    raise RuntimeError("unexpected actual TUN version")
binary_path = "credentials-client-ready/tun-debug07/client/bin/mihomo-bfp-windows-amd64.exe"
binary_hash = digest(binary_path)
if (binary_hash != build["native_binary_sha256"] or binary_hash != debug["native_binary_sha256"]
        or binary_hash != proxy["native_binary_sha256"] or not build["source_matches_frozen_inputs"]
        or not debug["source_matches_frozen_inputs"]):
    raise RuntimeError("diagnostic binary does not match built and observed input")
source_path = "credentials-client-ready/tun-debug07/source-manifest.json"
if digest(source_path) != build["source_manifest_sha256"] or digest(source_path) != debug["source_manifest_sha256"]:
    raise RuntimeError("frozen source manifest changed")
source = read(source_path)
for item in source["frozen"]:
    if digest("credentials-client-ready/tun-debug07/source/" + item["path"]) != item["sha256"]:
        raise RuntimeError("frozen source file changed")
version = subprocess.run([str(ROOT / binary_path), "-v"], capture_output=True, text=True, timeout=10,
                         creationflags=subprocess.CREATE_NO_WINDOW)
version_verified = version.returncode == 0 and "v1.19.32-bfp-0.1.0-debug-tun07" in version.stdout
# The first observer wrongly expected the version string in startup logs.
# Keep its raw FAIL; audit the same HTTPS run using the executable's actual
# -v output plus its matching built/observed SHA256. No second network request.
proxy_pass = (version_verified and proxy["https"]["success"]
              and proxy["https"]["exit_ip"] == "192.0.2.10"
              and proxy["dns_reply_verified"] and proxy["dns_only_owner_registered"]
              and not proxy["termination_before_stop"] and proxy["cleanup_complete"]
              and proxy["launcher_exited"] and proxy["final_cleanup_verified"])
proxy_audit = {
    "time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "original_evidence": "verification/product-windows-tun/proxy-debug07-real.json",
    "original_evidence_sha256": digest("verification/product-windows-tun/proxy-debug07-real.json"),
    "original_observer_pass": proxy["pass"],
    "observer_defect": "startup does not emit native version; version log presence was an invalid criterion",
    "original_result_preserved": True, "network_request_repeated": False,
    "native_binary_sha256": binary_hash, "native_binary_version_output": version.stdout.strip(),
    "native_binary_version_verified": version_verified, "source_binding_verified": True,
    "https_pass": proxy["https"]["success"], "dns_only_owner_registered": proxy["dns_only_owner_registered"],
    "instance_events_before_stop": proxy["instance_events_before_stop"],
    "termination_before_stop": proxy["termination_before_stop"],
    "cleanup_verified": proxy["final_cleanup_verified"], "pass": proxy_pass,
    "does_not_verify_windows_tun": True, "singapore_used": False,
}
PROXY_AUDIT.write_text(json.dumps(proxy_audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
supplement = {
    "time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "supplements": "verification/product-windows-tun/release-client-preview7.json",
    "current_delivered_client_version": "0.1.0-preview.7",
    "current_delivered_native_version": "0.1.0-preview.36", "public_zips_unchanged": True,
    "windows_tun": {
        "executed_client_version": tun["client_version"], "executed_native_version": tun["native_version"],
        "ready": tun["scenarios"][0]["ready"], "https_verified": False,
        "force_termination_executed": False, "final_cleanup_verified": tun["final_cleanup"]["pass"],
        "elapsed_seconds": tun["elapsed_seconds"], "root_cause_confirmed": False,
        "unexpected_termination_count_before_stop": audit["unexpected_termination_count_before_stop"],
        "termination_events_after_stop": sum(not value["before_stop"] for value in audit["termination_events"]),
        "failure": audit["controls"]["check"]["reply"]["error"],
        "evidence": "verification/product-windows-tun/windows-tun-real-attempt06.json",
        "audit": "verification/product-windows-tun/windows-tun-real-attempt06-audit.json",
        "interpretation": "one pre-stop unrecorded closure; normal close instrumentation did not identify its origin",
    },
    "diagnostic_copy": {
        "version": debug["native_version"], "root": "credentials-client-ready/tun-debug07",
        "tun_launcher": "verification/product-windows-tun/launch-debug07.ps1",
        "tun_executed": False, "new_uac_authorization_required": True,
        "private_credentials_included": True, "safe_to_share": False,
        "native_binary_sha256": binary_hash,
        "source_manifest_sha256": debug["source_manifest_sha256"], "source_matches_frozen_inputs": True,
        "frozen_source_file_count": len(source["frozen"]),
        "build_evidence": "credentials-client-ready/tun-debug07/build-evidence.json",
        "instrumentation": ["Client parent cancellation caller before raw cancel",
                            "process-local outbound and owner ordinals",
                            "business/control ended and close intent/local close fixed booleans",
                            "DNS-only Session watcher registration"],
        "local_parent_test": "TestClientParentTerminationDiagnostic PASS",
        "local_native_tests": "fake-IP lifecycle, Next23 and mixed setup tests PASS",
        "limitations": ["state fields are independent observations",
                        "outbound Close owner ordinal is latest registered snapshot",
                        "outbound context shutdown can suppress business-end watcher log",
                        "frozen source binding is not a byte-for-byte reproducible build claim"],
        "does_not_fix_tun_fault": True,
    },
    "diagnostic_proxy": {"pass": proxy_pass, "scope": proxy["scope"],
                         "evidence": "verification/product-windows-tun/proxy-debug07-real.json",
                         "audit": "verification/product-windows-tun/proxy-debug07-real-audit.json",
                         "original_observer_defect_retained": True,
                         "host_tun_started": False, "system_proxy_changed": False, "singapore_used": False},
    "client_final_state": "stopped", "acceptance_complete": False,
    "production_ready": False, "goal_status": "active",
}
HANDOFF.write_text(json.dumps(supplement, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"handoff": str(HANDOFF), "tun_fixed": False,
                  "tun_cleanup_verified": tun["final_cleanup"]["pass"],
                  "diagnostic_proxy_audited_pass": proxy_pass, "public_zips_unchanged": True}))
