"""Run one bounded next18 baseline WAN sample with the authorized inventory path."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lab"))
import remote
import wan

INVENTORY = Path(r"C:\Users\developer\Desktop\cold\servers-unredacted.md")
remote.INVENTORY = INVENTORY
wan.load_hosts = lambda: remote.load_hosts(inventory=INVENTORY)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--count", type=int, default=12)
    parser.add_argument("--size", type=int, default=1024)
    parser.add_argument("--interval", default="1s")
    parser.add_argument("--duration", default="20s")
    args = parser.parse_args()
    report, path = wan.run_wan(args.binary, args.count, args.size, args.interval, args.duration)
    print({"pass": report.get("pass"), "run_id": report.get("run_id"),
           "path": str(path),
           "scenarios": {name: value.get("pass") for name, value in report.get("scenarios", {}).items()},
           "random_probe": report.get("random_probe", {}).get("pass"),
           "error": report.get("error")}, flush=True)
    return 0 if report.get("pass") else 1


if __name__ == "__main__":
    raise SystemExit(main())

