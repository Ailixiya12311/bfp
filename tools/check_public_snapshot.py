"""Reject operator-specific network addresses and user paths in a Git snapshot.

Run this before publishing. Exact upstream Mihomo fixtures retain their public
examples; BFP additions and all first-party files are checked. This is a static
publication check, not a credential scanner or protocol acceptance test.
"""
import argparse
import html
import io
import ipaddress
import json
import pathlib
import re
import subprocess
import tarfile
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMMON_DNS_TEST_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "8.8.8.0/24", "8.8.4.0/24", "1.1.1.0/24",
    "2001:4860::/32", "2606:4700:4700::/48",
))
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(r"(?<![0-9A-Za-z_:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*(?:%[A-Za-z0-9_.-]+)?(?![0-9A-Za-z_:])")
USER_PATH = re.compile(r"(?i)(?:[A-Z]:[/\\]+Users[/\\]+|[/]home[/])([^/\\\s\"'`]+)")
GENERIC_USERS = {"developer", "user", "operator", "runner", "example", "test", "public"}


def is_first_party(name):
    prefix = "integrations/mihomo/source/"
    return not name.startswith(prefix) or pathlib.PurePosixPath(name).name.startswith("bfp")


def inspect(name, data):
    if not is_first_party(name) or b"\0" in data:
        return []
    text = data.decode("utf-8-sig", errors="replace")
    issues = []
    for number, line in enumerate(text.splitlines(), 1):
        # Also inspect common encodings used in commands and generated docs.
        line = html.unescape(urllib.parse.unquote(line))
        line = re.sub(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})",
                      lambda match: chr(int(match[1] or match[2], 16)), line)
        for pattern in (IPV4, IPV6):
            for match in pattern.finditer(line):
                # Normalize leading-zero IPv4 spelling as well as ordinary literals.
                try:
                    literal = match[0]
                    if pattern is IPV4:
                        literal = ".".join(str(int(part)) for part in literal.split("."))
                    value = ipaddress.ip_address(literal)
                except ValueError:
                    continue
                value = getattr(value, "ipv4_mapped", None) or value
                common_dns = any(value.version == network.version and value in network
                                 for network in COMMON_DNS_TEST_NETWORKS)
                if value.is_global and not value.is_reserved and not value.is_multicast and not common_dns:
                    issues.append({"path": name, "line": number, "type": "public_endpoint_literal"})
        for match in USER_PATH.finditer(line):
            if match[1].lower() not in GENERIC_USERS and not match[1].startswith(("$", "{", "<")):
                issues.append({"path": name, "line": number, "type": "personal_user_path"})
    return issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", help="scan the committed Git tree, e.g. HEAD")
    args = parser.parse_args()
    issues, count = [], 0
    if args.ref:
        archive = subprocess.check_output(["git", "archive", "--format=tar", args.ref], cwd=ROOT)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
            for entry in source:
                if entry.isfile():
                    count += 1
                    issues.extend(inspect(entry.name, source.extractfile(entry).read()))
    else:
        names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT)
        for name in sorted({entry.decode("utf8") for entry in names.split(b"\0") if entry}):
            count += 1
            issues.extend(inspect(name, (ROOT / name).read_bytes()))
    print(json.dumps({"files": count, "pass": not issues, "issues": issues}, ensure_ascii=True))
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
