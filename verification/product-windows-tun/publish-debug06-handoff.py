"""Supplement the immutable preview.7 record with its actual TUN result."""
import datetime
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
FOLDER = ROOT / "verification/product-windows-tun"
RECORD = FOLDER / "release-client-preview7-tun-attempt05.json"
if RECORD.exists():
    raise RuntimeError("preserve the existing handoff")


def read(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


tun = read("verification/product-windows-tun/windows-tun-real-attempt05.json")
audit = read("verification/product-windows-tun/windows-tun-real-attempt05-audit.json")
proxy = read("verification/product-windows-tun/native-mixed-debug06.json")
debug = read("credentials-client-ready/tun-debug06/client-manifest.json")
baseline = read("verification/product-windows-tun/release-client-preview7.json")
for name in ("client", "native"):
    if digest(baseline[name + "_zip"]) != baseline[name + "_zip_sha256"]:
        raise RuntimeError("frozen public ZIP changed")
for item in debug["source_files"]:
    if digest(item["path"]) != item["sha256"]:
        raise RuntimeError("diagnostic source changed since build")
version_executed = tun["client_version"] == "0.1.0-preview.7" and tun["native_version"] == "0.1.0-preview.36"
if not version_executed:
    raise RuntimeError("unexpected actual TUN version")
supplement = {
    "time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "supplements": "verification/product-windows-tun/release-client-preview7.json",
    "current_delivered_client_version": "0.1.0-preview.7",
    "current_delivered_native_version": "0.1.0-preview.36",
    "public_zips_unchanged": True,
    "windows_tun": {"current_version_executed": True, "ready": tun["scenarios"][0]["ready"],
                    "https_verified": False, "force_termination_executed": False,
                    "final_cleanup_verified": tun["final_cleanup"]["pass"],
                    "elapsed_seconds": tun["elapsed_seconds"],
                    "root_cause_confirmed": False,
                    "unexpected_termination_count_before_stop": audit["unexpected_termination_count_before_stop"],
                    "failure": audit["controls"]["check"]["reply"]["error"],
                    "evidence": "verification/product-windows-tun/windows-tun-real-attempt05.json",
                    "audit": "verification/product-windows-tun/windows-tun-real-attempt05-audit.json"},
    "diagnostic_copy": {"version": debug["native_version"], "frozen_release": False,
                        "private_credentials_included": True, "safe_to_share": False,
                        "root": "credentials-client-ready/tun-debug06",
                        "tun_launcher": "verification/product-windows-tun/launch-debug06.ps1",
                        "tun_executed": False,
                        "native_binary_sha256": digest("credentials-client-ready/tun-debug06/client/bin/mihomo-bfp-windows-amd64.exe"),
                        "source_files": debug["source_files"],
                        "instrumentation": ["local_close and peer_close before BusinessDone",
                                            "fixed fakeip_flush and outbound_close events"],
                        "does_not_fix_tun_fault": True},
    "diagnostic_proxy": {"pass": proxy["pass"], "final_cleanup_verified": proxy["final_cleanup_verified"],
                         "dns_fakeip_families_verified": proxy["dns_fakeip_families_verified"],
                         "https_ipv4_before": proxy["https_ipv4_before"],
                         "https_ipv6_after": proxy["https_ipv6_after"], "udp": proxy["udp"],
                         "termination_events_before_stop": proxy["termination_events_before_stop"],
                         "evidence": "verification/product-windows-tun/native-mixed-debug06.json",
                         "churn_is_socks_handshake_only": True,
                         "churn_does_not_prove_bfp_open_success": True,
                         "ipv6_scope": "local IPv6 fake-IP restored to domain with IPv4 Los Angeles exit; not public IPv6 egress",
                         "singapore_used": False},
    "local_diagnostics": {"authenticated_udp_tcp_close_source": "PASS; source published before BusinessDone, first source preserved",
                          "native_mixed_session": "PASS; loopback only, retained healthy flow after TCP/UDP/fake-IP/refusal/cancel",
                          "native_mixed_test": "integrations/mihomo/source/adapter/outbound/bfp_tun_mixed_diagnostic_test.go",
                          "native_mixed_does_not_prove_tun_fixed": True},
    "client_final_state": "stopped", "acceptance_complete": False, "production_ready": False,
    "goal_status": "active"
}
RECORD.write_text(json.dumps(supplement, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"handoff": str(RECORD), "tun_fixed": False,
                  "cleanup_verified": supplement["windows_tun"]["final_cleanup_verified"],
                  "diagnostic_proxy_pass": proxy["pass"], "public_zips_unchanged": True}))
