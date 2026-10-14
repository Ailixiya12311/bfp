"""Build a labelled validation image without installing tools on the host."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lab"))
import remote

run_id = remote.new_run_id()
report = {"run_id": run_id, "base": "sha256:ded31c68586d2e49e760acc2e65a884b23d032e9bbbed0ae0c55abd3fcaf4452", "pass": False}
host = remote.load_hosts(inventory=pathlib.Path(r"C:\Users\developer\Desktop\cold\servers-unredacted.md"))["receiver"]
with remote.Remote(host) as conn:
    before = conn.snapshot()
    owned = remote.RemoteRun(conn, run_id)
    owned.create()
    try:
        owned.write("Dockerfile", ("FROM " + report["base"] + "\nLABEL bfp.run=" + run_id + " bfp.purpose=native-validation-tools\nRUN apt-get update && apt-get install -y --no-install-recommends iproute2 tcpdump iptables && rm -rf /var/lib/apt/lists/*\n").encode())
        print(json.dumps({"stage": "building_owned_tool_image", "run_id": run_id}), flush=True)
        report["build"] = conn.python(owned._check() + r'''
import subprocess
tag='bfp-validation-tools:'+rid
env=dict(os.environ,DOCKER_BUILDKIT='0')
result=subprocess.run(['docker','build','--force-rm','--pull=false','--network','default','--label','bfp.purpose=native-validation-tools','--label','bfp.run='+rid,'--label','bfp.base=ded31c68586d','-t',tag,str(p)],capture_output=True,text=True,env=env,timeout=240)
image=None
if result.returncode==0:
    inspect=subprocess.run(['docker','image','inspect',tag],capture_output=True,text=True,timeout=10)
    if inspect.returncode==0:
        data=json.loads(inspect.stdout)[0]
        image={'id':data['Id'],'tag':tag,'labels':data.get('Config',{}).get('Labels',{}),'layers':data.get('RootFS',{}).get('Layers',[])}
print(json.dumps({'exit_code':result.returncode,'log':result.stdout[-14000:]+result.stderr[-4096:],'image':image}))
''', timeout=270)
        report["pass"] = bool(report["build"].get("exit_code") == 0 and report["build"].get("image", {}).get("labels", {}).get("bfp.run") == run_id)
    except Exception as exc:
        report["error"] = type(exc).__name__ + ": " + remote.SANITIZER.text(str(exc))
    finally:
        report["cleanup"] = owned.cleanup()
    after = conn.snapshot()
report["snapshot_comparison"] = remote.compare_snapshots(before, after)
report["pass"] = bool(report["pass"] and report["cleanup"].get("directory_removed") and report["snapshot_comparison"].get("unchanged"))
path = ROOT / "verification/product-mihomo" / ("tool-image-" + run_id + ".json")
remote.write_public(path, report)
print(json.dumps({"pass": report["pass"], "artifact": str(path), "image": report.get("build", {}).get("image", {}).get("id"), "error": report.get("error")}), flush=True)
raise SystemExit(0 if report["pass"] else 1)
