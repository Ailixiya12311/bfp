"""Check the exact public Windows TUN client and its frozen native bindings."""
import hashlib
import json
import argparse
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--client-version", default="0.1.0-preview.4")
parser.add_argument("--native-version", default="0.1.0-preview.33")
parser.add_argument("--result-name", default="package-check-preview4.json")
args = parser.parse_args()
CLIENT = ROOT / ("dist/BFP-Client-Windows-" + args.client_version)
NATIVE = ROOT / ("dist/BFP-Mihomo-" + args.native_version)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(bundle, manifest_name):
    manifest = json.loads((bundle / manifest_name).read_text(encoding="utf-8-sig"))
    entries = {item["path"]: item for item in manifest["files"]}
    expected = set(entries) | {manifest_name}
    actual = {p.relative_to(bundle).as_posix() for p in bundle.rglob("*") if p.is_file()}
    assert actual == expected, "bundle file set mismatch"
    with zipfile.ZipFile(bundle.with_name(bundle.name + ".zip")) as archive:
        archived = {i.filename for i in archive.infolist() if not i.is_dir()}
        assert archived == expected, "archive file set mismatch"
        for path, entry in entries.items():
            data = (bundle / path).read_bytes()
            assert len(data) == entry["bytes"] and sha(data) == entry["sha256"], path
            assert archive.read(path) == data, path
        assert archive.read(manifest_name) == (bundle / manifest_name).read_bytes()
    private = [p for p in expected if set(Path(p).parts) & {"credentials", "runtime", "runs"}
               or Path(p).name in {"client.json", "server.json", "current.json", "lease.json"}]
    assert not private, "private state included"
    return manifest, len(expected)


native, native_count = verify(NATIVE, "release-manifest.json")
client, client_count = verify(CLIENT, "client-manifest.json")
assert client["native_version"] == native["version"] == args.native_version
scripts = ["desktop-client.ps1", "windows-client.ps1", "windows-context.ps1",
           "windows-lifecycle.ps1", "windows-system-proxy.ps1", "windows-proxy-watch.ps1",
           "windows-elevated-control.ps1"]
for script in scripts:
    source = (ROOT / "deploy" / script).read_bytes()
    assert source.startswith(b"\xef\xbb\xbf"), script
    assert (CLIENT / "deploy" / script).read_bytes() == source
    assert (CLIENT / "source/desktop/deploy" / script).read_bytes() == source
for path in ["start-native.ps1", "windows-tun-support.ps1", "windows-tun-cleanup.ps1",
             "bin/bfp-windows-amd64.exe", "bin/mihomo-bfp-windows-amd64.exe",
             "configs/native-proxy.yaml", "configs/native-tun.yaml"]:
    assert (CLIENT / "client" / path).read_bytes() == (NATIVE / path).read_bytes(), path
for script in ["start-native.ps1", "windows-tun-support.ps1", "windows-tun-cleanup.ps1"]:
    assert (NATIVE / script).read_bytes() == (ROOT / "integrations/mihomo/templates" / script).read_bytes()
assert (CLIENT / "docs/Windows全局TUN-v0.1.md").read_bytes() == (ROOT / "docs/Windows全局TUN-v0.1.md").read_bytes()
result = {"pass": True, "client_version": client["version"], "native_version": native["version"],
          "client_file_count": client_count, "native_file_count": native_count,
          "client_zip_sha256": sha(CLIENT.with_name(CLIENT.name + ".zip").read_bytes()),
          "native_zip_sha256": sha(NATIVE.with_name(NATIVE.name + ".zip").read_bytes()),
          "runtime_script_count": len(scripts), "credentials_in_public_packages": False,
          "host_tun_started": False, "scope": "File, archive, BOM and frozen payload bindings only"}
(Path(__file__).parent / args.result_name).write_text(json.dumps(result, indent=2), encoding="utf-8")
print(json.dumps(result))
