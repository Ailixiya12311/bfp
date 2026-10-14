"""Local fault-injection tests for the run-owned binary staging helper.

No SSH or inventory is used. The fake endpoint executes the actual prefix and
commit Python supplied by bounded_staging in an isolated directory. Its SFTP
stream can persist part of a write before raising EOF, as a lost SSH reply can.
Run with: python -m unittest discover -s verification -p test_bounded_staging.py
"""
from __future__ import annotations

import contextlib
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import random
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lab"))
sys.path.insert(0, str(ROOT / "verification"))
import remote
import bounded_staging


class _Channel:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)


class _Stream:
    def __init__(self, endpoint, path, mode, action):
        self.endpoint = endpoint
        self.file = Path(path).open("r+b")
        self.action = action
        self.mode = mode
        self.pipeline = []
        self.pipelined = False
        self.pending = 0
        self.write_count = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.file.close()

    def set_pipelined(self, enabled):
        self.pipeline.append(enabled)
        self.pipelined = enabled

    def seek(self, offset):
        self.endpoint.seeks.append(offset)
        return self.file.seek(offset)

    def write(self, data):
        offset = self.file.tell()
        self.write_count += 1
        self.pending += 1
        accepted = len(data)
        failure = None
        if self.action and self.write_count == self.action[0]:
            accepted = min(self.action[1], len(data))
            failure = self.action[2]
        self.file.write(data[:accepted])
        self.file.flush()
        self.endpoint.writes.append({
            "connection": self.endpoint.connect_count,
            "offset": offset, "offered": len(data), "persisted": accepted,
            "pipelined": self.pipelined, "pending_requests": self.pending,
            "failure": type(failure).__name__ if failure else None,
        })
        if self.endpoint.after_write:
            self.endpoint.after_write()
        if failure:
            raise failure
        if not self.pipelined:
            self.endpoint.drains.append({"requests": self.pending, "offset": offset + len(data)})
            self.pending = 0


class _SFTP:
    def __init__(self, endpoint, action):
        self.endpoint = endpoint
        self.action = action
        self.channel = _Channel()
        self.closed = False
        self.streams = []

    def get_channel(self):
        return self.channel

    def open(self, path, mode):
        self.endpoint.opens.append((path, mode))
        stream = _Stream(self.endpoint, path, mode, self.action)
        self.streams.append(stream)
        return stream

    def close(self):
        self.closed = True


class _Endpoint:
    """A local adapter with the same remote.python exception contract."""

    def __init__(self, actions=()):
        self.host = types.SimpleNamespace(hostname="bounded-test.invalid", role="test")
        self.client = self
        self.actions = list(actions)
        self.connect_count = 0
        self.close_count = 0
        self.python_calls = []
        self.prefix_results = []
        self.sftps = []
        self.opens = []
        self.seeks = []
        self.writes = []
        self.drains = []
        self.before_commit = None
        self.commit_result_transform = None
        self.after_write = None
        self.on_open_sftp = None

    def connect(self):
        self.connect_count += 1
        return self

    def close(self):
        self.close_count += 1

    def open_sftp(self):
        if self.on_open_sftp:
            self.on_open_sftp()
        index = len(self.sftps)
        action = self.actions[index] if index < len(self.actions) else None
        sftp = _SFTP(self, action)
        self.sftps.append(sftp)
        return sftp

    def python(self, source, timeout=30):
        commit = "archive=p/'binary.gz.part';output=p/'bfp'" in source
        self.python_calls.append({"commit": commit, "timeout": timeout})
        if commit and self.before_commit:
            self.before_commit()
        stdout = io.StringIO()
        try:
            # Execute the helper's real scripts, including its real _check().
            with contextlib.redirect_stdout(stdout):
                exec(compile(source, "<local-bounded-staging-test>", "exec"), {})
        except Exception as error:
            # remote.Remote.python wraps a nonzero remote helper exit in LabError.
            raise remote.LabError(f"test: remote helper failed: {error}") from error
        try:
            result = json.loads(stdout.getvalue())
        except json.JSONDecodeError:
            raise remote.LabError("test: remote helper returned non-JSON output") from None
        if commit and self.commit_result_transform:
            result = self.commit_result_transform(result)
        if not commit:
            self.prefix_results.append(copy.deepcopy(result))
        return result


class _Timer:
    def __init__(self, interval, callback):
        self.interval = interval
        self.callback = callback
        self.daemon = False
        self.started = False
        self.cancelled = False

    def start(self):
        self.started = True

    def cancel(self):
        self.cancelled = True

    def fire(self):
        if not self.cancelled:
            self.callback()


class BoundedStagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bfp-bounded-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.directory = self.base / "owned"
        self.directory.mkdir()
        self.run_id = "a" * 32
        self.owner = {"run_id": self.run_id, "host": "bounded-test.invalid"}
        (self.directory / "owner.json").write_text(json.dumps(self.owner), encoding="utf-8")
        # Deterministic incompressible payload needs multiple actual chunks.
        self.data = b"\x7fELF" + random.Random(7119).randbytes(6 * bounded_staging.CHUNK + 317)
        self.source = self.base / "source-linux-elf"
        self.source.write_bytes(self.data)
        self.packed = gzip.compress(self.data, compresslevel=6, mtime=0)
        self.assertGreater(len(self.packed), 3 * bounded_staging.CHUNK)
        self.progress = []
        self.timers = []

        def make_timer(interval, callback):
            timer = _Timer(interval, callback)
            self.timers.append(timer)
            return timer

        timer_patch = mock.patch.object(bounded_staging.threading, "Timer", side_effect=make_timer)
        timer_patch.start()
        self.addCleanup(timer_patch.stop)

    def run_for(self, endpoint):
        # Keep the real ownership script and only replace its owned temp path.
        run = remote.RemoteRun(endpoint, self.run_id)
        run.directory = str(self.directory)
        return run

    def upload(self, endpoint):
        return bounded_staging.upload_binary(
            self.run_for(endpoint), self.source,
            progress=lambda value: self.progress.append(copy.deepcopy(value)),
        )

    def assert_no_retry_or_append(self, endpoint):
        self.assertEqual(endpoint.connect_count, 0)
        self.assertEqual(endpoint.close_count, 0)
        self.assertEqual(endpoint.opens, [])
        self.assertEqual(endpoint.writes, [])
        self.assertEqual(len(endpoint.python_calls), 1)
        self.assertEqual(len(self.progress[-1]["attempts"]), 1)
        self.assertFalse(self.progress[-1]["pass"])
        self.assertFalse((self.directory / "bfp").exists())

    def test_partial_chunk_eof_resumes_only_exact_verified_prefix(self):
        initial = 1739
        persisted_before_eof = 8191
        archive = self.directory / "binary.gz.part"
        archive.write_bytes(self.packed[:initial])
        endpoint = _Endpoint(actions=[(1, persisted_before_eof, EOFError("lost reply"))])
        report = self.upload(endpoint)
        recovered = initial + persisted_before_eof

        self.assertTrue(report["pass"])
        self.assertEqual(len(report["attempts"]), 2)
        self.assertEqual(endpoint.connect_count, 1)
        self.assertEqual(endpoint.close_count, 1)
        self.assertEqual(endpoint.seeks, [initial, recovered])
        self.assertEqual([item["bytes"] for item in endpoint.prefix_results], [initial, recovered])
        for item in endpoint.prefix_results:
            self.assertEqual(item["sha256"], hashlib.sha256(self.packed[:item["bytes"]]).hexdigest())
        self.assertEqual(report["attempts"][0]["verified_start_offset"], initial)
        self.assertNotIn("acknowledged_offset", report["attempts"][0])
        self.assertEqual(report["attempts"][0]["error_type"], "EOFError")
        self.assertEqual(report["attempts"][1]["verified_start_offset"], recovered)
        self.assertTrue(report["attempts"][1]["management_reconnected"])
        self.assertEqual(report["attempts"][1]["acknowledged_offset"], len(self.packed))
        self.assertEqual(endpoint.writes[1]["offset"], recovered)
        self.assertEqual(archive.read_bytes(), self.packed)
        self.assertEqual((self.directory / "bfp").read_bytes(), self.data)
        self.assertEqual(report["committed"]["bytes"], len(self.data))
        self.assertEqual(report["committed"]["sha256"], hashlib.sha256(self.data).hexdigest())
        self.assertEqual(report["committed"]["compressed_sha256"], hashlib.sha256(self.packed).hexdigest())
        self.assertEqual(json.loads((self.directory / "owner.json").read_text()), self.owner)
        self.assertTrue(all(sftp.closed for sftp in endpoint.sftps))
        self.assertTrue(all(write["pending_requests"] <= 4 for write in endpoint.writes))
        self.assertTrue(all(drain["requests"] <= 4 for drain in endpoint.drains))
        self.assertTrue(all(timer.started and timer.daemon and timer.cancelled for timer in self.timers))
        self.assertTrue(all(item["offered"] <= bounded_staging.CHUNK for item in endpoint.writes))

    def test_empty_archive_is_created_and_committed_with_real_scripts(self):
        endpoint = _Endpoint()
        report = self.upload(endpoint)
        self.assertTrue(report["pass"])
        self.assertEqual(endpoint.seeks, [0])
        self.assertEqual(len(report["attempts"]), 1)
        self.assertEqual(endpoint.connect_count, 0)
        self.assertEqual((self.directory / "binary.gz.part").read_bytes(), self.packed)
        self.assertEqual((self.directory / "bfp").read_bytes(), self.data)
        self.assertEqual([item["commit"] for item in endpoint.python_calls], [False, True])

    def test_at_most_four_requests_and_batch_ack_after_last_nonpipelined_write(self):
        self.assertEqual(bounded_staging.BATCH_CHUNKS, 4)
        endpoint = _Endpoint()
        report = self.upload(endpoint)
        self.assertTrue(report["pass"])
        self.assertEqual(report["max_outstanding_chunks"], 4)
        self.assertEqual([item["pipelined"] for item in endpoint.writes],
                         [True, True, True, False, True, True, False])
        self.assertEqual([item["pending_requests"] for item in endpoint.writes], [1, 2, 3, 4, 1, 2, 3])
        self.assertEqual(endpoint.drains, [
            {"requests": 4, "offset": 4 * bounded_staging.CHUNK},
            {"requests": 3, "offset": len(self.packed)},
        ])
        self.assertEqual(report["attempts"][0]["acknowledged_offset"], endpoint.drains[-1]["offset"])

    def test_eof_during_first_batch_drain_does_not_claim_queued_chunks_acked(self):
        partial = 8191
        endpoint = _Endpoint(actions=[(4, partial, EOFError("lost drain reply"))])
        report = self.upload(endpoint)
        recovered = 3 * bounded_staging.CHUNK + partial
        self.assertTrue(report["pass"])
        self.assertEqual(endpoint.seeks, [0, recovered])
        self.assertNotIn("acknowledged_offset", report["attempts"][0])
        self.assertEqual(endpoint.writes[3]["pending_requests"], 4)
        self.assertFalse(endpoint.writes[3]["pipelined"])
        self.assertEqual(report["attempts"][1]["verified_start_offset"], recovered)
        self.assertEqual((self.directory / "bfp").read_bytes(), self.data)

    def test_later_batch_failure_retains_only_previous_drained_ack_offset(self):
        endpoint = _Endpoint(actions=[(6, 211, EOFError("lost pipelined reply"))])
        report = self.upload(endpoint)
        recovered = 5 * bounded_staging.CHUNK + 211
        self.assertTrue(report["pass"])
        self.assertEqual(report["attempts"][0]["acknowledged_offset"], 4 * bounded_staging.CHUNK)
        self.assertEqual(report["attempts"][1]["verified_start_offset"], recovered)
        self.assertEqual(endpoint.seeks, [0, recovered])
        self.assertEqual((self.directory / "bfp").read_bytes(), self.data)

    def test_corrupt_prefix_rejected_before_append_without_reconnection(self):
        archive = self.directory / "binary.gz.part"
        corrupted = bytearray(self.packed[:2891])
        corrupted[-1] ^= 1
        archive.write_bytes(corrupted)
        endpoint = _Endpoint()
        with self.assertRaisesRegex(remote.LabError, "partial upload prefix mismatch"):
            self.upload(endpoint)
        self.assert_no_retry_or_append(endpoint)
        self.assertEqual(archive.read_bytes(), bytes(corrupted))

    def test_oversize_prefix_rejected_before_append_without_reconnection(self):
        archive = self.directory / "binary.gz.part"
        oversized = self.packed + b"x"
        archive.write_bytes(oversized)
        endpoint = _Endpoint()
        with self.assertRaisesRegex(remote.LabError, "invalid owned upload prefix"):
            self.upload(endpoint)
        self.assert_no_retry_or_append(endpoint)
        self.assertEqual(archive.read_bytes(), oversized)

    def test_symlink_prefix_rejected_before_append_without_reconnection(self):
        target = self.base / "outside-owned-prefix"
        target.write_bytes(self.packed[:257])
        archive = self.directory / "binary.gz.part"
        try:
            archive.symlink_to(target)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"local platform does not allow file symlinks: {error}")
        endpoint = _Endpoint()
        with self.assertRaisesRegex(remote.LabError, "invalid owned upload prefix"):
            self.upload(endpoint)
        self.assert_no_retry_or_append(endpoint)
        self.assertTrue(archive.is_symlink())
        self.assertEqual(target.read_bytes(), self.packed[:257])

    def test_nonregular_prefix_rejected_before_append(self):
        (self.directory / "binary.gz.part").mkdir()
        endpoint = _Endpoint()
        with self.assertRaisesRegex(remote.LabError, "invalid owned upload prefix"):
            self.upload(endpoint)
        self.assert_no_retry_or_append(endpoint)

    def test_owner_mismatch_rejected_before_creating_prefix_without_retry(self):
        (self.directory / "owner.json").write_text(json.dumps({**self.owner, "run_id": "b" * 32}))
        endpoint = _Endpoint()
        with self.assertRaisesRegex(remote.LabError, "run owner mismatch"):
            self.upload(endpoint)
        self.assert_no_retry_or_append(endpoint)
        self.assertFalse((self.directory / "binary.gz.part").exists())

    def test_repeated_partial_eof_has_exactly_three_attempts(self):
        self.assertEqual(bounded_staging.MAX_CONNECTIONS, 3)
        endpoint = _Endpoint(actions=[(1, 113, EOFError("lost reply"))] * 4)
        with self.assertRaisesRegex(remote.LabError, "bounded management upload attempts exhausted"):
            self.upload(endpoint)
        report = self.progress[-1]
        self.assertFalse(report["pass"])
        self.assertEqual(len(report["attempts"]), 3)
        self.assertEqual(endpoint.connect_count, 2)
        self.assertEqual(endpoint.close_count, 2)
        self.assertEqual(len(endpoint.sftps), 3)
        self.assertEqual(endpoint.seeks, [0, 113, 226])
        self.assertEqual([item["bytes"] for item in endpoint.prefix_results], [0, 113, 226])
        self.assertEqual((self.directory / "binary.gz.part").read_bytes(), self.packed[:339])
        self.assertTrue(all(item["error_type"] == "EOFError" for item in report["attempts"]))
        self.assertTrue(all(sftp.closed for sftp in endpoint.sftps))
        self.assertFalse((self.directory / "bfp").exists())
        self.assertFalse(any(item["commit"] for item in endpoint.python_calls))

    def test_changed_prefix_after_disconnect_is_not_appended_again(self):
        endpoint = _Endpoint(actions=[(1, 4097, EOFError("lost reply"))])
        original_connect = endpoint.connect

        def corrupt_on_reconnect():
            original_connect()
            archive = self.directory / "binary.gz.part"
            damaged = bytearray(archive.read_bytes())
            damaged[0] ^= 1
            archive.write_bytes(damaged)
            return endpoint

        endpoint.connect = corrupt_on_reconnect
        with self.assertRaisesRegex(remote.LabError, "partial upload prefix mismatch"):
            self.upload(endpoint)
        self.assertEqual(endpoint.connect_count, 1)
        self.assertEqual(len(endpoint.sftps), 1)
        self.assertEqual(len(endpoint.writes), 1)
        self.assertEqual(len(self.progress[-1]["attempts"]), 2)
        self.assertEqual(self.progress[-1]["attempts"][1]["error_type"], "LabError")
        self.assertFalse((self.directory / "bfp").exists())

    def test_compressed_hash_error_at_commit_does_not_retry(self):
        endpoint = _Endpoint()

        def corrupt_completed_archive():
            archive = self.directory / "binary.gz.part"
            damaged = bytearray(archive.read_bytes())
            damaged[-1] ^= 1
            archive.write_bytes(damaged)

        endpoint.before_commit = corrupt_completed_archive
        with self.assertRaisesRegex(remote.LabError, "compressed upload proof mismatch"):
            self.upload(endpoint)
        self.assertEqual(endpoint.connect_count, 0)
        self.assertEqual(len(endpoint.sftps), 1)
        self.assertEqual(len(self.progress[-1]["attempts"]), 1)
        self.assertFalse(self.progress[-1]["pass"])
        self.assertFalse((self.directory / "bfp").exists())

    def test_mismatched_commit_result_is_terminal_without_retry(self):
        endpoint = _Endpoint()
        endpoint.commit_result_transform = lambda result: {**result, "sha256": "0" * 64}
        with self.assertRaisesRegex(remote.LabError, "remote ELF proof mismatch"):
            self.upload(endpoint)
        self.assertEqual(endpoint.connect_count, 0)
        self.assertEqual(len(endpoint.sftps), 1)
        self.assertFalse(self.progress[-1]["pass"])
        # Local adapter really committed the original bytes before the bad reply.
        self.assertEqual((self.directory / "bfp").read_bytes(), self.data)

    def test_fixed_deadline_is_not_extended_by_partial_writes_or_reconnect(self):
        now = [50.0]
        endpoint = _Endpoint()
        endpoint.after_write = lambda: now.__setitem__(0, 50.0 + bounded_staging.TRANSFER_SECONDS + 1)
        with mock.patch.object(bounded_staging.time, "monotonic", side_effect=lambda: now[0]):
            with self.assertRaisesRegex(remote.LabError, "fixed upload deadline exceeded"):
                self.upload(endpoint)
        self.assertEqual(endpoint.connect_count, 0)
        self.assertEqual(len(endpoint.writes), 1)
        self.assertEqual(len(self.progress[-1]["attempts"]), 1)
        self.assertFalse((self.directory / "bfp").exists())

    def test_reconnect_timer_uses_remaining_original_deadline(self):
        now = [50.0]
        endpoint = _Endpoint(actions=[(1, 113, EOFError("lost reply"))] * 3)
        endpoint.after_write = lambda: now.__setitem__(0, now[0] + 30)
        with mock.patch.object(bounded_staging.time, "monotonic", side_effect=lambda: now[0]):
            with self.assertRaisesRegex(remote.LabError, "bounded management upload attempts exhausted"):
                self.upload(endpoint)
        self.assertEqual([timer.interval for timer in self.timers], [180.0, 150.0, 120.0])
        self.assertTrue(all(timer.started and timer.daemon and timer.cancelled for timer in self.timers))

    def test_deadline_timer_closes_only_this_endpoint_during_sftp_initialization(self):
        now = [50.0]
        endpoint = _Endpoint()

        def stalled_open():
            now[0] += bounded_staging.TRANSFER_SECONDS
            self.timers[-1].fire()
            raise EOFError("subsystem interrupted at original deadline")

        endpoint.on_open_sftp = stalled_open
        with mock.patch.object(bounded_staging.time, "monotonic", side_effect=lambda: now[0]):
            with self.assertRaisesRegex(EOFError, "subsystem interrupted"):
                self.upload(endpoint)
        self.assertEqual(endpoint.connect_count, 0)
        self.assertEqual(endpoint.close_count, 1)
        self.assertEqual(endpoint.opens, [])
        self.assertEqual(len(self.progress[-1]["attempts"]), 1)
        self.assertTrue(self.timers[0].cancelled)
        self.assertFalse((self.directory / "bfp").exists())

    def test_deadline_reached_after_final_write_must_prevent_commit(self):
        now = [50.0]
        endpoint = _Endpoint()

        def final_write_consumes_deadline():
            if endpoint.writes[-1]["offset"] + endpoint.writes[-1]["persisted"] == len(self.packed):
                now[0] = 50.0 + bounded_staging.TRANSFER_SECONDS

        endpoint.after_write = final_write_consumes_deadline
        with mock.patch.object(bounded_staging.time, "monotonic", side_effect=lambda: now[0]):
            with self.assertRaisesRegex(remote.LabError, "fixed upload deadline exceeded"):
                self.upload(endpoint)
        self.assertFalse(any(item["commit"] for item in endpoint.python_calls))
        self.assertFalse((self.directory / "bfp").exists())

    def test_deadline_reached_after_commit_must_not_publish_success(self):
        now = [50.0]
        endpoint = _Endpoint()

        def commit_returns_at_original_deadline(result):
            # The real commit script has already checked and created the ELF.
            # Advance only the clock; do not alter its authentic hash result.
            now[0] = 50.0 + bounded_staging.TRANSFER_SECONDS
            return result

        endpoint.commit_result_transform = commit_returns_at_original_deadline
        with mock.patch.object(bounded_staging.time, "monotonic", side_effect=lambda: now[0]):
            with self.assertRaisesRegex(remote.LabError, "fixed upload deadline exceeded during commit"):
                self.upload(endpoint)
        self.assertEqual([item["commit"] for item in endpoint.python_calls], [False, True])
        self.assertEqual((self.directory / "bfp").read_bytes(), self.data)
        self.assertEqual(endpoint.connect_count, 0)
        self.assertEqual(len(self.progress[-1]["attempts"]), 1)
        self.assertFalse(self.progress[-1]["pass"])
        self.assertFalse(self.progress[-1]["attempts"][0]["success"])
        self.assertEqual(self.progress[-1]["attempts"][0]["error_type"], "LabError")
        self.assertNotIn("committed", self.progress[-1])
        self.assertEqual(self.progress[-1]["elapsed_seconds"], bounded_staging.TRANSFER_SECONDS)
        self.assertTrue(all(timer.cancelled for timer in self.timers))


if __name__ == "__main__":
    unittest.main()
