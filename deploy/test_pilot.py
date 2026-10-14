"""Offline pilot lifecycle checks; no real inventory, credentials, or SSH access."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location("bfp_pilot", pathlib.Path(__file__).with_name("pilot.py"))
pilot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pilot)


class PilotTests(unittest.TestCase):
    def test_prepare_uses_configured_receiver_for_both_carriers_and_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            package, native = root / "package", root / "native"
            package.mkdir()
            native.mkdir()
            (package / "release-manifest.json").write_text('{"version":"synthetic"}')
            payload = root / "payload"
            payload.write_bytes(b"synthetic offline payload")
            hosts = {role: types.SimpleNamespace(hostname=address) for role, address in
                     (("receiver", "203.0.113.40"), ("sender", "198.51.100.20"))}

            def keygen(argv, **_):
                private = pathlib.Path(argv[argv.index("-out") + 1])
                private.mkdir()
                (private / "server.json").write_text('{"credentials":{"allowed_clients":[]},"policy":{}}')
                (private / "client.json").write_text('{"credentials":{}}')
                return types.SimpleNamespace(returncode=0)

            with patch.object(pilot, "ROOT", root), patch.object(pilot, "CURRENT", root / "absent-current.json"), \
                 patch.object(pilot, "load_hosts", return_value=hosts), \
                 patch.object(pilot, "checked_file", return_value=payload), \
                 patch.object(pilot.subprocess, "run", side_effect=keygen) as run, \
                 patch.object(pilot, "save") as save, \
                 patch.dict(pilot.os.environ, {}, clear=True):
                result = pilot.prepare(package, native)
            argv = run.call_args.args[0]
            for flag in ("-server", "-tcp-server"):
                self.assertEqual(argv[argv.index(flag) + 1], "203.0.113.40:51880")
            state = save.call_args.args[0]
            self.assertEqual(state["public_endpoint"], "203.0.113.40:51880")
            self.assertEqual(state["expected_exit_ip"], "203.0.113.40")
            self.assertEqual(result["public_endpoint"], state["public_endpoint"])

    def test_status_and_stop_work_without_local_package(self):
        for action in ("status", "stop"):
            with self.subTest(action=action):
                state = {"instance_id": "a" * 32, "private_directory": "missing-private",
                         "root_package": "missing-package", "hosts": {"receiver": {"last_error": "old failure"}},
                         "events": []}
                run = MagicMock()
                run.cleanup.return_value = {"directory_removed": True}
                host = types.SimpleNamespace(hostname="receiver.test")
                with patch.object(pilot, "load", return_value=state), \
                     patch.object(pilot, "load_hosts", return_value={"receiver": host}), \
                     patch.object(pilot, "checked_file", side_effect=AssertionError("package must not be read")), \
                     patch.object(pilot, "connect_remote"), \
                     patch.object(pilot, "RemoteRun", return_value=run), \
                     patch.object(pilot, "status_remote", return_value={"exists": True, "running": True}), \
                     patch.object(pilot, "save"), redirect_stdout(io.StringIO()):
                    result = pilot.operate(action, ["receiver"])
                self.assertNotIn("error", result["roles"]["receiver"])
                self.assertNotIn("last_error", state["hosts"]["receiver"])
                self.assertEqual(run.cleanup.call_count, int(action == "stop"))

    def test_atomic_replace_failure_preserves_previous_record(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "state.json"
            target.write_text('{"old":true}', encoding="utf-8")
            with patch.object(pilot.os, "replace", side_effect=OSError("injected failure")):
                with self.assertRaises(OSError):
                    pilot.write_public_atomic(target, {"new": True})
            self.assertEqual(json.loads(target.read_text()), {"old": True})
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [target])

    def test_atomic_write_sanitizes_before_publishing(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "state.json"
            pilot.write_public_atomic(target, {"private_key": "synthetic-canary", "phase": "running"})
            self.assertEqual(json.loads(target.read_text()), {"private_key": "[REDACTED]", "phase": "running"})

    def test_command_lock_excludes_another_process_and_releases(self):
        source = (
            "import sys;sys.path.insert(0,sys.argv[1]);import pilot\n"
            "try:\n"
            " with pilot.command_lock(sys.argv[2]): print('acquired')\n"
            "except pilot.LabError:\n"
            " print('busy');sys.exit(23)\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            lock = pathlib.Path(directory) / "pilot.lock"
            argv = [sys.executable, "-c", source, str(pathlib.Path(__file__).parent), str(lock)]
            with pilot.command_lock(lock):
                busy = subprocess.run(argv, capture_output=True, text=True, timeout=15)
            acquired = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        self.assertEqual((busy.returncode, busy.stdout.strip()), (23, "busy"), busy.stderr)
        self.assertEqual((acquired.returncode, acquired.stdout.strip()), (0, "acquired"), acquired.stderr)

    def test_sender_tunnel_lifetime_and_destination(self):
        receiver_host = types.SimpleNamespace(hostname="receiver.test", port=2222)
        sender_host = types.SimpleNamespace(hostname="sender.test", port=22)
        receiver, sender, channel = MagicMock(), MagicMock(), MagicMock()
        receiver.__enter__.return_value = receiver
        receiver.client.get_transport.return_value.open_channel.return_value = channel
        with patch.object(pilot, "Remote", side_effect=[receiver, sender]):
            with pilot.connect_remote({"receiver": receiver_host, "sender": sender_host}, "sender", True) as remote:
                self.assertIs(remote, sender)
                sender.connect.assert_called_once_with(sock=channel)
                channel.close.assert_not_called()
                receiver.__exit__.assert_not_called()
        receiver.client.get_transport.return_value.open_channel.assert_called_once_with(
            "direct-tcpip", ("sender.test", 22), ("127.0.0.1", 0), timeout=10)
        sender.close.assert_called_once()
        channel.close.assert_called_once()
        receiver.__exit__.assert_called_once()

    def test_sender_tunnel_closes_when_inner_authentication_fails(self):
        receiver, sender, channel = MagicMock(), MagicMock(), MagicMock()
        receiver.__enter__.return_value = receiver
        receiver.client.get_transport.return_value.open_channel.return_value = channel
        sender.connect.side_effect = RuntimeError("synthetic authentication failure")
        hosts = {role: types.SimpleNamespace(hostname=role + ".test", port=22) for role in ("receiver", "sender")}
        with patch.object(pilot, "Remote", side_effect=[receiver, sender]):
            with self.assertRaises(RuntimeError):
                with pilot.connect_remote(hosts, "sender", True):
                    self.fail("failed connection must not be yielded")
        sender.close.assert_called_once()
        channel.close.assert_called_once()
        receiver.__exit__.assert_called_once()

    def remote_status(self, directory, role="receiver", fake_pathlib=None):
        def evaluate(source, **_):
            output = io.StringIO()
            with redirect_stdout(output):
                if fake_pathlib is None:
                    exec(source, {})
                else:
                    with patch.dict(sys.modules, {"pathlib": fake_pathlib}):
                        exec(source, {})
            return json.loads(output.getvalue())
        run = types.SimpleNamespace(directory=str(directory), _check=lambda: "import os\nrid='" + "a" * 32 + "'\n",
                                    remote=types.SimpleNamespace(host=types.SimpleNamespace(role=role), python=evaluate))
        return pilot.status_remote(run)

    def test_receiver_reports_only_latest_snapshot_including_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / "receiver.log"
            rows = [{"event": "stats", "sessions": [{"session_id": "old"}]},
                    {"event": "stats", "sessions": [{"session_id": "new", "carrier": "tcp"}]}]
            log.write_text("\n".join(map(json.dumps, rows)))
            result = self.remote_status(directory)
            self.assertEqual(result["sessions"], [{"session_id": "new", "carrier": "tcp"}])
            self.assertEqual(result["sessions_source"], "latest_server_stats")
            rows.append({"event": "stats", "sessions": []})
            log.write_text("\n".join(map(json.dumps, rows)))
            self.assertEqual(self.remote_status(directory)["sessions"], [])

    def test_sender_snapshot_is_explicitly_initial(self):
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / "sender.log").write_text(json.dumps(
                {"event": "socks_listening", "session": {"session_id": "initial", "carrier": "udp"}}))
            result = self.remote_status(directory, "sender")
        self.assertEqual(result["sessions_source"], "initial_connection")
        self.assertFalse(result["sessions_are_live"])

    def test_process_disappearance_during_status_is_stopped(self):
        class VanishedProc:
            def __init__(self, leaf=""):
                self.leaf = leaf

            def __truediv__(self, child):
                return VanishedProc(str(child))

            def exists(self):
                return True

            def read_text(self):
                return "123 (bfp) " + " ".join(["S"] + ["0"] * 18 + ["42"])

            def read_bytes(self):
                raise FileNotFoundError("process exited")

            def resolve(self):
                return "/synthetic/bfp"

        original_path = pathlib.Path
        fake_pathlib = types.SimpleNamespace(Path=lambda value: VanishedProc() if value == "/proc" else original_path(value))
        with tempfile.TemporaryDirectory() as directory:
            (original_path(directory) / "receiver.process.json").write_text(json.dumps(
                {"run_id": "a" * 32, "pid": 123, "starttime": "42", "command_sha256": "synthetic", "exe": "/synthetic/bfp"}))
            result = self.remote_status(directory, fake_pathlib=fake_pathlib)
        self.assertFalse(result["running"])


if __name__ == "__main__":
    unittest.main()
