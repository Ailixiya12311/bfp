"""Six focused, filesystem-free capture-parser checks."""
import contextlib
import importlib.util
import io
import json
import pathlib
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("capture_attempt05", pathlib.Path(__file__).with_name("capture-attempt05.py"))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


def control(path, stamp, success=None):
    return {"path": path, "created_utc": stamp, "reply": {"success": success}}


class CaptureParserTests(unittest.TestCase):
    def test_legacy_new_and_private_fields(self):
        legacy = capture.parse_bfp_event('time="2026-10-13T04:06:50.861839300-07:00" level=warning msg="[BFP] event=bfp_session_business_ended source=context_end_without_cancel"', 89)
        self.assertEqual(legacy["source"], "context_end_without_cancel")
        self.assertEqual(legacy["line"], 89)
        self.assertIsNone(legacy["owner"])
        line = '[BFP] event=bfp_session_business_ended outbound=2 owner=3 source=parent_context_end@tunnel.go:613 business_ended=true control_ended=false close_intent=false local_close=true domain=secret.invalid key=secret'
        event = capture.parse_bfp_event(line)
        self.assertEqual((event["outbound"], event["owner"]), (2, 3))
        self.assertEqual([event[key] for key in capture.BOOL_FIELDS], [True, False, False, True])
        self.assertNotIn("secret", json.dumps(event))
        self.assertIsNone(capture.parse_bfp_event('time="2026-10-13T11:00:00Z" level=info msg="[TCP] destination=secret.invalid event=bfp_session_business_ended"'))
        invalid = capture.parse_bfp_event('[BFP] event=bfp_session_business_ended outbound=18446744073709551616 owner=2 owner=3 source=C:/private.go:4 business_ended=1 local_close=false local_close=true')
        self.assertEqual(invalid["source"], "unknown")
        self.assertTrue(all(invalid[key] is None for key in ("outbound", "owner", "business_ended", "local_close")))
        self.assertEqual(capture.parse_bfp_event('[BFP] event=bfp_outbound_started outbound=0 owner=18446744073709551615')["owner"], 2**64 - 1)
        raw = capture.parse_bfp_event('[BFP] event=bfp_session_business_ended source=raw_business_stop@session.go:812 business_ended=true control_ended=false close_intent=false local_close=false')
        self.assertEqual(raw["source"], "raw_business_stop@session.go:812")
        self.assertFalse(raw["source_records_exact_cause"])
        self.assertEqual(capture.parse_bfp_event('[BFP] event=bfp_session_business_ended source=raw_business_stop@C:/secret.go:4')["source"], "unknown")

    def test_multiple_controls_and_approximate_boundary(self):
        controls = {"check": [control("check2", "2026-10-13T11:00:03Z"), control("check1", "2026-10-13T11:00:01Z")],
                    "stop": [control("stop2", "2026-10-13T11:00:05Z"), control("stop1", "2026-10-13T11:00:02Z")]}
        lines = [
            'time="2026-10-13T04:00:01.999999999-07:00" level=warning msg="[BFP] event=bfp_session_business_ended source=unknown"',
            'time="2026-10-13T11:00:02Z" level=warning msg="[BFP] event=bfp_session_business_ended source=unknown"',
            'time="2026-10-13T11:00:04Z" level=warning msg="[BFP] event=bfp_session_business_ended source=unknown"']
        events = [capture.parse_bfp_event(line, i) for i, line in enumerate(lines, 1)]
        audit = capture.make_audit({}, list(reversed(events)), controls, [])
        self.assertEqual([event["before_stop"] for event in audit["termination_events"]], [True, False, False])
        self.assertEqual([entry["path"] for entry in audit["control_logs"]["stop"]], ["stop1", "stop2"])
        self.assertEqual(audit["controls"]["check"]["path"], "check1")
        self.assertEqual(audit["unexpected_termination_count_before_stop"], 1)
        self.assertIn("not exact stop invocation or completion", audit["stop_boundary"]["definition"])
        unknown = capture.make_audit({}, events, {"stop": [control("stop", None)]}, [])
        self.assertIsNone(unknown["unexpected_termination_count_before_stop"])
        self.assertEqual(unknown["unclassified_termination_count"], 3)
        self.assertIsNone(capture.parsed_time("2026-10-13T11:00:00"))
        self.assertEqual(capture.parsed_time("2026-10-13T11:00:01.123456789Z").microsecond, 123456)

    def test_https_actual_evidence_and_no_double_counting(self):
        cases = [
            (1, [True], [True], True), (2, [True], [True], None),
            (2, [True, None], [True, True], None), (2, [True, False], [], False),
            (None, [True, True], [], None), (2, [], [True, True], True),
            (1, ["true"], [True], None), (1, [False], [], False),
            (1, [], [None], None), (1, [True, True], [], None),
            (True, [True], [], None), (0, [], [], None)]
        for requested, flags, scenarios, expected in cases:
            with self.subTest(requested=requested, flags=flags, scenarios=scenarios):
                result = {"requested_https_checks": requested, "pass": False,
                          "scenarios": [{"ready": True, "pass": True, "https": {"success": flag}} for flag in scenarios]}
                controls = {"check": [control(str(i), "2026-10-13T11:00:00Z", flag) for i, flag in enumerate(flags)]}
                self.assertIs(capture.coverage(result, controls)["https_pass"], expected)
        duplicate = control("same-path", "2026-10-13T11:00:00Z", True)
        self.assertIsNone(capture.coverage({"requested_https_checks": 2}, {"check": [duplicate, duplicate]})["https_pass"])

    def test_force_flags_are_independent_of_cleanup(self):
        for launcher, supervisor, expected in ((True, True, True), (True, False, False),
                                               (False, False, False), (True, None, None),
                                               ("false", True, None), (None, None, None)):
            with self.subTest(launcher=launcher, supervisor=supervisor):
                result = {"scenarios": [{"name": "supervisor_and_launcher_force_termination",
                          "verified_chain": {"launcher_terminated": launcher, "supervisor_terminated": supervisor},
                          "child_exited": False, "cleanup": {"pass": False}, "pass": False}]}
                evidence = capture.coverage(result, {})
                self.assertIs(evidence["force_termination_executed"], expected)
                self.assertIs(evidence["force_termination_evidence"][0]["child_exited"], False)
        self.assertIs(capture.coverage({"scenarios": []}, {})["force_termination_executed"], False)
        self.assertIsNone(capture.coverage({"scenarios": [{"name": "supervisor_and_launcher_force_termination", "verified_chain": None}]}, {})["force_termination_executed"])

    def test_demo_dry_run_has_no_filesystem_operations(self):
        output = io.StringIO()
        with mock.patch.object(pathlib.Path, "open") as opened, \
             mock.patch.object(pathlib.Path, "read_text") as read_text, \
             mock.patch.object(pathlib.Path, "read_bytes") as read_bytes, \
             mock.patch.object(pathlib.Path, "mkdir") as mkdir, \
             mock.patch.object(capture.shutil, "copyfileobj") as copied, \
             contextlib.redirect_stdout(output):
            self.assertEqual(capture.main(["--dry-run", "--demo"]), 0)
        for operation in (opened, read_text, read_bytes, mkdir, copied):
            operation.assert_not_called()
        audit = json.loads(output.getvalue())
        self.assertEqual([(event["outbound"], event["owner"]) for event in audit["instance_events"]], [(1, 1), (1, 1), (2, 2)])
        self.assertIsNone(audit["https_pass"])

    def test_existing_outputs_refused_before_copy_or_read(self):
        with mock.patch.object(pathlib.Path, "exists", return_value=True), \
             mock.patch.object(pathlib.Path, "read_text") as read_text, \
             mock.patch.object(capture.shutil, "copyfileobj") as copied:
            with self.assertRaisesRegex(RuntimeError, "preserve existing"):
                capture.main(["--attempt", "6"])
        read_text.assert_not_called()
        copied.assert_not_called()
        fresh, existing = mock.Mock(), mock.Mock()
        fresh.exists.return_value = False
        fresh.is_symlink.return_value = False
        existing.exists.return_value = True
        with self.assertRaisesRegex(RuntimeError, "preserve existing"):
            capture.preflight_outputs(fresh, [fresh, existing])


if __name__ == "__main__":
    unittest.main(verbosity=2)
