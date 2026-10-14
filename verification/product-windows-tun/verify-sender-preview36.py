"""One small HTTPS request through the upgraded Singapore BFP sender."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "deploy"))
import pilot

record = ROOT / "verification/product-windows-tun/sender-preview36-real.json"
if record.exists():
    raise pilot.LabError("preserve the existing sender result")
result = {"time_utc": pilot.utc(), "pass": False, "requests": 1,
          "scope": "one HTTPS request through owned Singapore SOCKS to Los Angeles egress",
          "bandwidth_test": False, "remote_config_changed": False}
try:
    with pilot.command_lock():
        state = pilot.load()
        if state["root_version"] != "0.1.0-preview.36":
            raise pilot.LabError("unexpected pilot version")
        hosts = pilot.load_hosts()
        with pilot.connect_remote(hosts, "sender", via_receiver=True) as remote:
            run = pilot.RemoteRun(remote, state["instance_id"])
            status = pilot.status_remote(run)
            if not status.get("running") or not status.get("owner_verified") or status.get("binary_sha256") != state["linux_sha256"]:
                raise pilot.LabError("owned sender binary was not verified")
            reply = remote.python(run._check() + '''
import subprocess,json
response=subprocess.run(['curl','--noproxy','','--proxy','socks5h://127.0.0.1:1080','--fail','--silent','--show-error','--max-time','15','https://www.cloudflare.com/cdn-cgi/trace'],capture_output=True,timeout=20)
body=response.stdout
address=next((line[3:] for line in body.decode('utf-8','replace').splitlines() if line.startswith('ip=')),None)
print(json.dumps({'curl_exit_code':response.returncode,'response_bytes':len(body),'exit_ip':address}))
''')
            result.update(reply, binary_sha256=status["binary_sha256"],
                          native_core_version=state["root_version"], access_route="via_receiver")
            result["pass"] = reply.get("curl_exit_code") == 0 and reply.get("exit_ip") == "192.0.2.10"
except Exception as error:
    result["error"] = pilot.SANITIZER.text(str(error))[:640]
finally:
    pilot.write_public_atomic(record, result)
print(json.dumps(result))
raise SystemExit(0 if result["pass"] else 1)
