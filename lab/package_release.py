"""Package a verified BFP revision from an explicit, credential-free allowlist.

Example (only after the named validation, race and WAN runs are complete)::

    python lab/package_release.py --revision v0.1-r5 \
        --race-manifest lab/runs/<race-run-id>/source-manifest.json \
        --wan-report lab/runs/<wan-run-id>/wan-result.json

This script performs no network access, subprocess execution, installation or
deployment. Raw race/WAN overall FAIL and socket-baseline differences are kept;
selected protocol gates may be accepted only with explicit supplemental review.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import zipfile
import zlib


WORKSPACE = Path(__file__).resolve().parents[1]
SOURCE_DIRS = (
    "protocol", "security", "scheduler", "classification", "obfuscation",
    "gateway", "session", "adapter", "cmd", "tests", "internal",
)
REVISION = re.compile(r"v[0-9]+\.[0-9]+-r[1-9][0-9]*\Z")
RUN_ID = re.compile(r"[a-f0-9]{32}\Z")
SHA256 = re.compile(r"[a-fA-F0-9]{64}\Z")
SCENARIOS = ("normal_udp", "udp_to_tcp", "initial_udp_blocked")
VERIFY_NAMES = (
    "validation.json", "binaries.json", "release-evidence.json", "fuzz-summary.json",
    "go-test-windows.jsonl",
    "go-vet.txt", "go-mod-verify.txt", "lab-test.txt",
    "ticket-runtime-fixed-10.jsonl", "ticket-adversarial-fixed-10.jsonl",
    "classification-test.txt",
    "unit.log", "ticket_repeat.log", "vet.log", "modules.log", "lab.log",
    "build_windows.log", "build_linux.log",
)
RACE_NAMES = (
    "source-manifest.json", "race-result.json", "race-log.json",
    "supplemental-baseline-review.json", "listener-review.json",
)
WAN_NAMES = (
    "wan-result.json", "supplemental-baseline-review.json",
    "udp-failure-analysis.json", "probe-correlation-analysis.json", "udp-operation-phase-analysis.json", "server-log.json", "fixture-log.json",
) + tuple(name + suffix for name in SCENARIOS
          for suffix in (".evidence.json", ".probe-log.json"))
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_INPUT_BYTES = 128 * 1024 * 1024
BLOCKED_COMPONENTS = {
    "credentials", "servers", "privateconfigs", "private-configs",
    "known_hosts", "vendor", "source", "__pycache__", ".git",
}
SENSITIVE_KEY = re.compile(
    r"password|passphrase|private(?:[_ -]?key)?$|secret|token|psk|admission|"
    r"credentials?|^ticket$|resume[_ -]?proof", re.I,
)
LABELED_SECRET = re.compile(
    r'(?i)("?(?:password|passphrase|private(?:[_ -]?key)?|'
    r'[a-z0-9_-]*secret|[a-z0-9_-]*token|psk|admission|ticket|credentials?)'
    r'"?\s*[:=]\s*)("[^"\n]*"|\S+)'
)
PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S,
)


class PackageError(RuntimeError):
    """A safe diagnostic which never includes input file contents."""


def require(condition, message):
    if not condition:
        raise PackageError(message)


def member_path(value):
    require(isinstance(value, str) and value, "empty/non-string archive path")
    require("\\" not in value and ":" not in value and "\0" not in value,
            "non-portable archive path")
    require(not value.startswith("/") and
            all(part not in ("", ".", "..") for part in value.split("/")),
            "absolute or traversal archive path")
    path = PurePosixPath(value)
    require(not path.is_absolute(), "absolute archive member")
    return path


def checked_file(root, path):
    """Reject linked/reparse inputs and enforce the workspace boundary."""
    path = Path(path)
    require(".." not in path.parts, "input traversal is not allowed")
    if not path.is_absolute():
        path = root / path
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise PackageError("input must be inside the BFP workspace") from None
    current = root
    for part in relative.parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError:
            raise PackageError("required input is missing or inaccessible") from None
        require(not stat.S_ISLNK(info.st_mode) and
                not getattr(info, "st_file_attributes", 0) &
                getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
                "linked/reparse input is not allowed")
    require(path.is_file(), "input must be a regular file")
    resolved = path.resolve()
    require(resolved.is_relative_to(root), "resolved input escaped workspace")
    return resolved


def read_bytes(root, path, limit=MAX_FILE_BYTES):
    path = checked_file(root, path)
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    require(len(data) <= limit, "input exceeded the package size bound")
    return data


def parse_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON keys in evidence")
            result[key] = value
        return result

    try:
        return json.loads(data.decode("utf-8-sig"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              PackageError("non-finite JSON number in evidence")))
    except (UnicodeError, json.JSONDecodeError):
        raise PackageError("invalid JSON evidence") from None


def read_json(root, path):
    return parse_json(read_bytes(root, path, MAX_JSON_BYTES))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True,
                       allow_nan=False) + "\n").encode("utf-8")


def sanitize(value, root):
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if SENSITIVE_KEY.search(key)
                      else sanitize(child, root)) for key, child in value.items()}
    if isinstance(value, list):
        return [sanitize(child, root) for child in value]
    if isinstance(value, str):
        value = value.replace(str(root), "[WORKSPACE]")
        value = value.replace(root.as_posix(), "[WORKSPACE]")
        value = PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", value)
        return LABELED_SECRET.sub(lambda m: m.group(1) + '"[REDACTED]"', value)
    return value


def public_json_bytes(root, path, lines=False):
    data = read_bytes(root, path, MAX_JSON_BYTES)
    if not lines:
        return json_bytes(sanitize(parse_json(data), root))
    output = []
    for line in data.splitlines():
        if line.strip():
            output.append(json.dumps(sanitize(parse_json(line), root),
                                     ensure_ascii=False, sort_keys=True,
                                     allow_nan=False))
    return ("\n".join(output) + "\n").encode("utf-8")


def public_text_bytes(root, path):
    try:
        text = read_bytes(root, path, MAX_JSON_BYTES).decode("utf-8-sig")
    except UnicodeError:
        raise PackageError("non-UTF8 public verification log") from None
    return sanitize(text, root).encode("utf-8")


def allowed_document(path):
    lower = [part.lower() for part in path.parts]
    if any(part in BLOCKED_COMPONENTS for part in lower):
        return False
    name = path.name.lower()
    if path.suffix.lower() != ".go" and (
            name.startswith(("credentials", "credential", "servers.", "servers-", "known_hosts")) or
            any(part.startswith(("credentials", "privateconfigs", "private-configs")) for part in lower)):
        return False
    return not any(term in name for term in (
        "known_hosts", "unredacted", "privateconfig", "private-config",
        "servers-unredacted",
    ))


def tree_files(root, directory, extensions):
    base = root / directory
    if not base.exists():
        return []
    require(base.is_dir(), "allowlisted input directory is not a directory")
    files = []
    for folder, directories, names in os.walk(base, followlinks=False):
        for name in list(directories):
            candidate = Path(folder) / name
            info = candidate.lstat()
            require(not stat.S_ISLNK(info.st_mode) and
                    not getattr(info, "st_file_attributes", 0) &
                    getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
                    "linked directory in allowlisted source tree")
            if name.lower() in BLOCKED_COMPONENTS:
                directories.remove(name)
        for name in names:
            path = Path(folder) / name
            if path.suffix.lower() in extensions and allowed_document(path.relative_to(root)):
                files.append(checked_file(root, path))
    return sorted(files)


def source_paths(root):
    files = [checked_file(root, name) for name in ("go.mod", "go.sum")]
    for directory in SOURCE_DIRS:
        files.extend(tree_files(root, directory, {".go"}))
    return {path.relative_to(root).as_posix(): path for path in files}


def validate_manifest(root, manifest):
    require(isinstance(manifest, list) and manifest, "race source manifest is empty")
    result = {}
    for row in manifest:
        require(isinstance(row, dict), "invalid source manifest row")
        path = member_path(row.get("path"))
        name = path.as_posix()
        require(name in ("go.mod", "go.sum") or
                path.parts[0] in SOURCE_DIRS and path.suffix == ".go",
                "race source manifest contains non-allowlisted input")
        require(name not in result and isinstance(row.get("bytes"), int) and
                not isinstance(row.get("bytes"), bool) and row["bytes"] >= 0 and
                isinstance(row.get("sha256"), str) and SHA256.fullmatch(row["sha256"]),
                "invalid or duplicate source manifest row")
        result[name] = {"path": name, "bytes": row["bytes"],
                        "sha256": row["sha256"].lower()}
    current = source_paths(root)
    require(set(result) == set(current), "current Go/module file set differs from race freeze")
    for name, path in current.items():
        data = read_bytes(root, path)
        require(len(data) == result[name]["bytes"] and
                digest(data) == result[name]["sha256"],
                "current Go/module bytes differ from race freeze")
    return result


def manifest_digest(manifest):
    return digest(json_bytes([manifest[name] for name in sorted(manifest)]))


def run_input(root, value, filename):
    path = checked_file(root, value)
    relative = path.relative_to(root)
    require(len(relative.parts) == 4 and relative.parts[:2] == ("lab", "runs") and
            RUN_ID.fullmatch(relative.parts[2]) and relative.name == filename,
            "evidence must name an exact allowlisted run file")
    return path, relative.parts[2]


def validate_local(root, revision, binaries):
    path = checked_file(root, f"verification/{revision}/validation.json")
    report = read_json(root, path)
    require(isinstance(report, dict) and
            report.get("version", report.get("revision")) == revision,
            "local validation revision does not match")
    require(report.get("local_validation_pass") is True or report.get("pass") is True or
            report.get("status") == "PASS", "local validation has no explicit PASS declaration")
    checks = report.get("checks")
    if isinstance(checks, dict):
        needed = {"unit", "ticket_repeat", "vet", "modules", "lab", "build_windows", "build_linux"}
        require(needed <= set(checks) and
                all(isinstance(checks[name], dict) and checks[name].get("pass") is True and
                    checks[name].get("exit_code") == 0 for name in needed),
                "local tests/vet/modules/lab/build gates are incomplete")
        require(report.get("source_unchanged") is True,
                "local validation does not establish unchanged build source")
    else:
        windows = report.get("windows")
        require(isinstance(windows, dict) and windows.get("vet_exit") == 0 and
                windows.get("mod_verify_exit") == 0 and
                isinstance(windows.get("packages_passed"), int) and windows["packages_passed"] > 0,
                "Windows tests/vet/module verification gates are incomplete")
    rows = report.get("binaries")
    require(isinstance(rows, list), "local binary hash records are missing")
    recorded = {}
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get("path"), str),
                "invalid local binary record")
        name = row["path"].replace("\\", "/").split("/")[-1]
        require(name in binaries and name not in recorded, "unexpected/duplicate local binary record")
        recorded[name] = row.get("sha256")
    require(set(recorded) == set(binaries) and
            all(recorded[name] == digest(data) for name, data in binaries.items()),
            "local validation binary hashes differ from selected artifacts")
    return path, report


def validate_local_source(report, manifest):
    rows = report.get("source_manifest")
    require(isinstance(rows, list) and rows, "local build source manifest is missing")
    recorded = {}
    for row in rows:
        require(isinstance(row, dict), "invalid local source manifest row")
        name = member_path(row.get("path")).as_posix()
        require(name in manifest and name not in recorded and
                row.get("sha256") == manifest[name]["sha256"],
                "local build source differs from race source")
        if "bytes" in row:
            require(row["bytes"] == manifest[name]["bytes"], "local build source size differs")
        recorded[name] = row["sha256"]
    require(set(recorded) == set(manifest), "local build source file set differs from race")


def baseline_gate(root, folder, report, kind):
    raw = report.get("pass")
    require(isinstance(raw, bool), "raw overall gate is missing")
    snapshots = report.get("snapshots")
    roles = {"receiver"} if kind == "race" else {"sender", "receiver"}
    require(isinstance(snapshots, dict) and set(snapshots) == roles and
            all(isinstance(value, dict) and isinstance(value.get("before"), dict) and
                isinstance(value.get("after"), dict) for value in snapshots.values()),
            "complete host before/after snapshots are missing")
    comparisons = {role: value.get("comparison") for role, value in snapshots.items()}
    require(len(comparisons) == (1 if kind == "race" else 2), "raw baseline comparisons missing")
    unchanged = {}
    for role, comparison in comparisons.items():
        require(isinstance(comparison, dict) and isinstance(comparison.get("unchanged"), bool),
                "raw baseline comparison is invalid")
        unchanged[role] = comparison["unchanged"]
        if not comparison["unchanged"]:
            changes = comparison.get("changes")
            require(isinstance(changes, dict) and changes and set(changes) <= {"listeners"},
                    "non-listener baseline differences cannot be waived")
    require(raw == all(unchanged.values()), "raw overall gate disagrees with selected gates/baseline")
    review_path = folder / "supplemental-baseline-review.json"
    review = None
    if not raw:
        review = read_json(root, review_path)
        require(isinstance(review, dict) and review.get("run_id") == folder.name,
                "supplemental baseline review run identity mismatch")
        require(review.get("kind") == kind and review.get("raw_original_pass") is False and
                review.get("binary_sha256") == report.get("binary_sha256", report.get("related_binary_sha256")) and
                review.get("code_checks_pass") is True and
                review.get("exact_owned_cleanup_complete") is True and
                review.get("supplemental_review_confirms_stable_services_and_config") is True,
                "supplemental stable-service review did not pass")
        hosts = review.get("host_baseline_reviews")
        require(isinstance(hosts, dict) and set(hosts) == roles and
                all(isinstance(value, dict) and
                    value.get("raw_baseline_unchanged") is unchanged[role] and
                    value.get("stable_tcp_fixed_udp_container_routes_firewall") is True and
                    value.get("full_before_after_snapshots_saved") is True
                    for role, value in hosts.items()),
                "supplemental review lacks complete stable-host gates")
    return {"raw_overall_pass": raw, "raw_socket_baseline_unchanged": unchanged,
            "supplemental_review_required": not raw,
            "supplemental_review": (review_path.relative_to(root).as_posix() if review else None),
            "raw_gate_limitation": ("Original all-socket equality and overall FAIL are retained. "
                                    "Supplemental stable-service review does not convert raw gates to PASS."
                                    if not raw else None)}


def validate_race(root, manifest_path, run_id, linux_hash):
    manifest_report = read_json(root, manifest_path)
    require(isinstance(manifest_report, dict), "invalid race manifest object")
    manifest = validate_manifest(root, manifest_report.get("files"))
    report_path = manifest_path.parent / "race-result.json"
    report = read_json(root, report_path)
    require(isinstance(report, dict) and report.get("run_id") == run_id,
            "race report run identity mismatch")
    require(report.get("related_binary_sha256") == linux_hash,
            "race associated binary hash does not match selected Linux artifact")
    require(validate_manifest(root, report.get("source_manifest")) == manifest,
            "race report and separate source manifest differ")
    execution, cleanup = report.get("execution"), report.get("cleanup")
    require(isinstance(execution, dict) and execution.get("exit_code") == 0 and
            execution.get("owned_container_removed") is True and
            isinstance(cleanup, dict) and cleanup.get("directory_removed") is True,
            "race execution or exact owned cleanup failed")
    gates = baseline_gate(root, manifest_path.parent, report, "race")
    gates.update(run_id=run_id, test_exit_code=0, owned_container_removed=True,
                 owned_directory_removed=True, frozen_source_matches=True,
                 source_files=len(manifest), source_manifest_sha256=manifest_digest(manifest))
    return manifest, gates


def validate_wan(root, path, run_id, linux_hash):
    report = read_json(root, path)
    require(isinstance(report, dict) and report.get("run_id") == run_id and
            report.get("binary_sha256") == linux_hash, "WAN run/binary identity mismatch")
    scenarios = report.get("scenarios")
    require(isinstance(scenarios, dict) and set(scenarios) == set(SCENARIOS) and
            all(isinstance(scenarios[name], dict) and scenarios[name].get("pass") is True
                for name in SCENARIOS), "WAN requires all three named scenarios PASS")
    probe = report.get("random_probe")
    require(isinstance(probe, dict) and probe.get("pass") is True and
            probe.get("no_application_response") is True and
            probe.get("no_target_side_effect") is True, "WAN unauthenticated random probe failed")
    cleanup = report.get("cleanup")
    require(isinstance(cleanup, dict) and set(cleanup) == {"sender", "receiver"} and
            all(isinstance(value, dict) and value.get("directory_removed") is True
                for value in cleanup.values()), "WAN exact owned cleanup is incomplete")
    staged = report.get("staged")
    require(isinstance(staged, dict) and set(staged) == {"sender", "receiver"} and
            all(isinstance(value, dict) and value.get("sha256") == linux_hash
                for value in staged.values()), "WAN host upload hashes differ from selected binary")
    lifecycle = report.get("ticket_lifecycle")
    require(isinstance(lifecycle, dict) and lifecycle.get("enabled") is True and
            all(scenarios[name].get("ticket_lifecycle_gate_met") is True
                for name in SCENARIOS), "release WAN must exercise ticket refresh in every scenario")
    gates = baseline_gate(root, path.parent, report, "wan")
    gates.update(run_id=run_id, binary_sha256=linux_hash,
                 scenario_pass={name: True for name in SCENARIOS},
                 random_probe_pass=True, exact_owned_cleanup_complete=True,
                 ticket_lifecycle_gate_pass=True)
    return gates


def validate_staged_public_records(root, payloads, race_path, wan_path, revision):
    """Fail if a raw gate or manifest would be altered by public serialization."""
    race_name = race_path.parent.relative_to(root).as_posix() + "/race-result.json"
    wan_name = wan_path.relative_to(root).as_posix()
    manifest_name = race_path.relative_to(root).as_posix()
    validation_name = "verification/" + revision + "/validation.json"
    for name in (race_name, wan_name, manifest_name, validation_name):
        require(name in payloads, "required staged public evidence is absent")
    race = parse_json(payloads[race_name][0])
    wan = parse_json(payloads[wan_name][0])
    original_race = read_json(root, race_name)
    original_wan = read_json(root, wan_name)
    for staged, original in ((race, original_race), (wan, original_wan)):
        require(staged.get("pass") is original.get("pass") and
                staged.get("snapshots") == sanitize(original.get("snapshots"), root),
                "raw overall or baseline evidence changed during sanitization")
    require(race.get("snapshot_comparison") == original_race.get("snapshot_comparison") and
            wan.get("scenarios") == sanitize(original_wan.get("scenarios"), root),
            "raw race baseline or WAN scenario gates changed in archive")
    require(parse_json(payloads[manifest_name][0]).get("files") ==
            read_json(root, manifest_name).get("files"), "staged race manifest was altered")


def collect_payloads(root, revision, manifest, binaries, validation, race_path, wan_path):
    selected = {}

    def add(path, public_json=False, json_lines=False, public_text=False, mode=0o644):
        path = checked_file(root, path)
        name = path.relative_to(root).as_posix()
        member_path(name)
        require(name not in selected, "duplicate allowlisted package input")
        data = (public_json_bytes(root, path, json_lines) if public_json or json_lines
                else public_text_bytes(root, path) if public_text else read_bytes(root, path))
        selected[name] = (data, mode)

    for name in sorted(manifest):
        add(name)
        data = selected[name][0]
        require(len(data) == manifest[name]["bytes"] and digest(data) == manifest[name]["sha256"],
                "packaged source stage differs from race freeze")
    for name in ("README.md", ".gitignore"):
        add(name)
    for directory in SOURCE_DIRS:
        for path in tree_files(root, directory, {".md"}):
            add(path)
    for directory in ("docs", "integrations"):
        for path in tree_files(root, directory, {".md", ".py"}):
            add(path)
    # Lab scripts/docs are top-level only: never discover arbitrary run files.
    for path in sorted((root / "lab").iterdir()):
        if path.is_file() and path.suffix.lower() in {".py", ".md"} and allowed_document(path):
            add(path)
    for relative in (
        "third_party/github.com/flynn/noise/LICENSE",
        "third_party/golang.org/x/crypto/LICENSE",
        "third_party/golang.org/x/crypto/PATENTS",
        "third_party/golang.org/x/sys/LICENSE",
        "third_party/golang.org/x/sys/PATENTS",
    ):
        add(relative)
    for name, data in binaries.items():
        add("bin/" + name, mode=0o755 if name.endswith("linux-amd64") else 0o644)
        require(selected["bin/" + name][0] == data, "binary changed during package staging")
    for name in VERIFY_NAMES:
        path = root / "verification" / revision / name
        if path.exists():
            add(path, public_json=path.suffix == ".json", json_lines=path.suffix == ".jsonl",
                public_text=path.suffix in {".txt", ".log"})
    # Explicit small regression evidence only; never traverse experiment trees.
    if int(revision.rsplit("-r", 1)[1]) >= 7:
        for name in ("README.md", "before-fix.log", "after-fix.log", "repeat-10.log"):
            path = root / "verification" / "experiments" / "r7-transport" / name
            if path.exists():
                add(path, public_text=True)
    for folder, names in ((race_path.parent, RACE_NAMES), (wan_path.parent, WAN_NAMES)):
        for name in names:
            path = folder / name
            if path.exists():
                add(path, public_json=True)
    require(validation.relative_to(root).as_posix() in selected, "validation missing from allowlist")
    require(sum(len(data) for data, _ in selected.values()) <= MAX_PACKAGE_INPUT_BYTES,
            "total allowlisted input exceeds package bound")
    return selected


def entry_record(name, data, mode):
    return {"path": name, "bytes": len(data), "sha256": digest(data),
            "crc32": f"{zlib.crc32(data) & 0xffffffff:08x}", "mode": f"{mode:04o}"}


def build_zip(path, prefix, payloads):
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9, allowZip64=False) as archive:
        for name in sorted(payloads):
            data, mode = payloads[name]
            arcname = member_path(prefix + "/" + name).as_posix()
            info = zipfile.ZipInfo(arcname, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compresslevel=9)
    with zipfile.ZipFile(path, "r") as archive:
        require(archive.testzip() is None, "ZIP CRC verification failed")
        require(len(archive.infolist()) == len(payloads), "ZIP entry count mismatch")
        require(len(set(archive.namelist())) == len(payloads), "duplicate ZIP members")
        for info in archive.infolist():
            member_path(info.filename)
            require(info.filename.startswith(prefix + "/"), "ZIP member escaped release prefix")
            name = info.filename[len(prefix) + 1:]
            require(name in payloads and archive.read(info) == payloads[name][0],
                    "ZIP member bytes differ from package manifest")


def package(root, revision, race_manifest, wan_report):
    require(REVISION.fullmatch(revision), "invalid revision")
    root = root.resolve()
    dist = root / "dist"
    prefix = "BFP-" + revision
    zip_path = dist / (prefix + ".zip")
    metadata_path = dist / (prefix + "-package.json")
    require(not zip_path.exists() and not metadata_path.exists(), "release output already exists; refusing overwrite")
    names = ("bfp-" + revision + "-linux-amd64", "bfp-" + revision + ".exe")
    binaries = {name: read_bytes(root, "bin/" + name) for name in names}
    require(binaries[names[0]].startswith(b"\x7fELF") and binaries[names[1]].startswith(b"MZ"),
            "selected release binaries are not ELF/Windows executable inputs")
    linux_hash = digest(binaries[names[0]])
    validation_path, local_report = validate_local(root, revision, binaries)
    race_path, race_id = run_input(root, race_manifest, "source-manifest.json")
    wan_path, wan_id = run_input(root, wan_report, "wan-result.json")
    manifest, race_gates = validate_race(root, race_path, race_id, linux_hash)
    validate_local_source(local_report, manifest)
    wan_gates = validate_wan(root, wan_path, wan_id, linux_hash)
    payloads = collect_payloads(root, revision, manifest, binaries, validation_path,
                                race_path, wan_path)
    validate_staged_public_records(root, payloads, race_path, wan_path, revision)
    limitations = [gate["raw_gate_limitation"] for gate in (race_gates, wan_gates)
                   if gate["raw_gate_limitation"]]
    metadata = {
        "schema_version": 1, "revision": revision,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "archive_prefix": prefix, "credentials_included": False,
        "selected_release_gates_pass": True,
        "gate_policy": {
            "local_explicit_pass_required": True, "race_exit_zero_required": True,
            "exact_owned_cleanup_required": True, "three_wan_scenarios_required": True,
            "wan_ticket_lifecycle_required": True,
            "raw_overall_pass_is_not_rewritten": True,
            "raw_baseline_equality_is_not_implied": True,
            "limitations": limitations,
        },
        "local_validation": {"record": validation_path.relative_to(root).as_posix(),
                             "input_sha256": digest(read_bytes(root, validation_path)),
                             "local_declared_pass": True},
        "linux_race": race_gates, "wan": wan_gates,
        "source_stages": {stage: manifest_digest(manifest)
                          for stage in ("local_build", "race_freeze", "preflight", "packaged", "prepublish")},
        "source_manifest": [manifest[name] for name in sorted(manifest)],
        "manifest_excludes_embedded_metadata_self": True,
        "files": [entry_record(name, data, mode) for name, (data, mode) in sorted(payloads.items())],
        "scope": "Experimental build; no independent security audit, native integration, or long-term reliability claim.",
    }
    payloads["package.json"] = (json_bytes(metadata), 0o644)
    # Re-read evidence gates as well as every source before publication. No
    # staging/vendor directory or mutable remote inventory is ever consulted.
    require(validate_manifest(root, read_json(root, race_path).get("files")) == manifest,
            "source changed before publication")
    require(validate_race(root, race_path, race_id, linux_hash)[1] == race_gates and
            validate_wan(root, wan_path, wan_id, linux_hash) == wan_gates,
            "evidence changed during staging")
    validate_local_source(validate_local(root, revision, binaries)[1], manifest)
    require(all(read_bytes(root, "bin/" + name) == data for name, data in binaries.items()),
            "release binary changed before publication")
    dist.mkdir(exist_ok=True)
    dist_info = dist.lstat()
    require(not stat.S_ISLNK(dist_info.st_mode) and
            not getattr(dist_info, "st_file_attributes", 0) &
            getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
            "linked distribution directory is not allowed")
    # Reserve both output names exclusively. Failure never overwrites an old
    # package; a partial new artifact may remain and must be inspected manually.
    with tempfile.TemporaryDirectory(prefix=".bfp-package-", dir=dist) as temporary:
        staged_zip = Path(temporary) / "release.zip"
        build_zip(staged_zip, prefix, payloads)
        require(validate_manifest(root, read_json(root, race_path).get("files")) == manifest,
                "source changed while writing archive")
        archive_data = staged_zip.read_bytes()
        final = dict(metadata)
        final["manifest_excludes_embedded_metadata_self"] = False
        final["embedded_metadata_sha256"] = digest(payloads["package.json"][0])
        final["files"] = [entry_record(name, data, mode) for name, (data, mode) in sorted(payloads.items())]
        final.update(path=zip_path.relative_to(root).as_posix(), bytes=len(archive_data),
                     sha256=digest(archive_data), entries=len(payloads), crc_pass=True,
                     all_manifest_hashes_match=True, frozen_source_matches=True)
        with zip_path.open("xb") as output:
            output.write(archive_data)
            output.flush()
            os.fsync(output.fileno())
        with metadata_path.open("xb") as output:
            output.write(json_bytes(final))
            output.flush()
            os.fsync(output.fileno())
    return {"revision": revision, "zip": zip_path.relative_to(root).as_posix(),
            "metadata": metadata_path.relative_to(root).as_posix(),
            "sha256": final["sha256"], "entries": final["entries"],
            "crc_pass": True, "frozen_source_matches": True,
            "raw_race_overall_pass": race_gates["raw_overall_pass"],
            "raw_wan_overall_pass": wan_gates["raw_overall_pass"],
            "raw_gate_limitations": limitations}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--race-manifest", required=True)
    parser.add_argument("--wan-report", required=True)
    args = parser.parse_args()
    try:
        report = package(WORKSPACE, args.revision, args.race_manifest, args.wan_report)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0
    except PackageError as error:
        print(json.dumps({"packaged": False, "error": str(error)}, ensure_ascii=False))
        return 1
    except (OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile) as error:
        # Arbitrary filesystem/JSON exceptions can include private paths or
        # content. Emit only their class; controlled diagnostics are above.
        print(json.dumps({"packaged": False, "error_type": type(error).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
