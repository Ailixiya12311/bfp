import pathlib
import os
import tempfile
import unittest
from unittest.mock import patch

from remote import (
    Sanitizer,
    LabError,
    owned_dir,
    file_name,
    compare_snapshots,
    _find_inventory,
    _find_server_workspace,
    load_hosts,
)


class RemoteSafetyTests(unittest.TestCase):
    def test_unconfigured_endpoints_fail_before_inventory_access(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(LabError, "BFP_RECEIVER_HOST"):
                load_hosts(pathlib.Path("missing-private-inventory.md"))

    def test_configured_endpoints_match_only_selected_inventory_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            inventory = root / "inventory.md"
            inventory.write_text(
                "| receiver | 192.0.2.10:2222 | operator | receiver-canary |\n"
                "| sender | 198.51.100.20 | operator | sender-canary |\n"
                "| other | 203.0.113.30 | other | unrelated-canary |\n", encoding="utf-8")
            with patch.dict(os.environ, {
                "BFP_RECEIVER_HOST": "192.0.2.10", "BFP_RECEIVER_SSH_PORT": "2222",
                "BFP_SENDER_HOST": "198.51.100.20", "BFP_INVENTORY_PATH": str(inventory),
                "BFP_RECEIVER_KNOWN_HOSTS": str(root / "receiver-pins"),
            }, clear=True):
                hosts = load_hosts()
            self.assertEqual((hosts["receiver"].hostname, hosts["receiver"].port), ("192.0.2.10", 2222))
            self.assertEqual(hosts["receiver"].pin_file, root / "receiver-pins")
            self.assertEqual(hosts["sender"].port, 22)
            self.assertEqual(set(hosts), {"receiver", "sender"})

    def test_invalid_configured_port_fails_before_inventory_access(self):
        for port in ("0", "65536", "not-a-port"):
            with self.subTest(port=port), patch.dict(os.environ, {
                "BFP_RECEIVER_HOST": "192.0.2.10", "BFP_RECEIVER_SSH_PORT": port,
                "BFP_SENDER_HOST": "198.51.100.20",
            }, clear=True):
                with self.assertRaisesRegex(LabError, "BFP_RECEIVER_SSH_PORT"):
                    load_hosts(pathlib.Path("missing-private-inventory.md"))

    def test_workspace_resolution_uses_pinned_layout_and_inventory_fallback(self):
        with tempfile.TemporaryDirectory() as root:
            desktop = pathlib.Path(root)
            preferred = desktop / "renamed-workspace"
            (preferred / "latency-plan-24").mkdir(parents=True)
            self.assertEqual(_find_server_workspace(desktop), preferred)
            inventory = preferred / "服务器清单.md"
            inventory.write_text("placeholder", encoding="utf-8")
            self.assertEqual(_find_inventory(preferred), inventory)

    def test_workspace_resolution_prefers_named_workspace_when_multiple_candidates_exist(self):
        with tempfile.TemporaryDirectory() as root:
            desktop = pathlib.Path(root)
            preferred = desktop / "服务器整理及优化"
            (preferred / "latency-plan-24").mkdir(parents=True)
            other = desktop / "other-workspace"
            (other / "latency-plan-24").mkdir(parents=True)
            self.assertEqual(_find_server_workspace(desktop), preferred)

    def test_inventory_resolution_prefers_unredacted_sibling_over_summary_table(self):
        with tempfile.TemporaryDirectory() as root:
            desktop = pathlib.Path(root)
            workspace = desktop / "server-notes"
            workspace.mkdir()
            summary = workspace / "服务器清单.md"
            summary.write_text("summary", encoding="utf-8")
            cold = desktop / "cold"
            cold.mkdir()
            unredacted = cold / "servers-unredacted.md"
            unredacted.write_text("unredacted", encoding="utf-8")
            self.assertEqual(_find_inventory(workspace), unredacted)

    def test_inventory_environment_override_is_explicit(self):
        with tempfile.TemporaryDirectory() as root:
            workspace = pathlib.Path(root) / "server-notes"
            workspace.mkdir()
            override = workspace / "operator-inventory.md"
            override.write_text("override", encoding="utf-8")
            previous = os.environ.get("BFP_INVENTORY_PATH")
            os.environ["BFP_INVENTORY_PATH"] = str(override)
            try:
                self.assertEqual(_find_inventory(workspace), override)
            finally:
                if previous is None:
                    os.environ.pop("BFP_INVENTORY_PATH", None)
                else:
                    os.environ["BFP_INVENTORY_PATH"] = previous

    def test_exact_run_directory(self):
        self.assertEqual(owned_dir('a'*32), '/tmp/bfp-lab-'+'a'*32)
        for value in ('../root', '', 'a'*31, 'A'*32, 'a'*32+'/..'):
            with self.assertRaises(LabError):
                owned_dir(value)

    def test_artifact_path_cannot_escape(self):
        self.assertEqual(file_name('server.config.json'), 'server.config.json')
        for value in ('../config', '/tmp/other', 'a/b', '.', '..', 'a\x00b'):
            with self.assertRaises(LabError):
                file_name(value)

    def test_all_registered_secrets_are_redacted_in_errors_and_logs(self):
        cleaner=Sanitizer()
        cleaner.add('ssh-password-value')
        cleaner.config({'nested':{'private_key':'private-key-value','resume_secret':'resume-value','admit_key':'admit-value'},'array':[{'token':'token-value'}]})
        text='ssh-password-value private-key-value resume-value admit-value token-value'
        result=cleaner.text(text)
        for value in text.split():
            self.assertNotIn(value,result)
        self.assertEqual(result.count('[REDACTED]'),5)
        unknown=cleaner.text('password=unexpected-secret token="another-secret" private="private-material" admission="admission-material"')
        self.assertNotIn('unexpected-secret',unknown)
        self.assertNotIn('another-secret',unknown)
        self.assertNotIn('private-material',unknown)
        self.assertNotIn('admission-material',unknown)
        obj=cleaner.obj({'password':'never-written','logs':['resume-value'],'pid':123})
        self.assertEqual(obj,{'password':'[REDACTED]','logs':['[REDACTED]'],'pid':123})
        stats = cleaner.obj({'udp_cwnd_admission_denied': 7, 'udp_pacer_tokens': 4800, 'udp_feedback_tokens': 2400})
        self.assertEqual(stats, {'udp_cwnd_admission_denied': 7, 'udp_pacer_tokens': 4800, 'udp_feedback_tokens': 2400})
        secrets = cleaner.obj({'admission': 'private-admission', 'resume_secret': 'private-resume', 'client_key': 'private-key'})
        self.assertEqual(secrets, {'admission': '[REDACTED]', 'resume_secret': '[REDACTED]', 'client_key': '[REDACTED]'})

    def test_snapshot_comparison_detects_services_and_config_not_load(self):
        before={'snapshot':{'listeners':['tcp LISTEN 0 100 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1))'], 'containers':[{'ID':'a','Names':'existing','Image':'image','State':'running','Ports':'443','Status':'Up 2 days'}], 'memory':{'MemAvailable_KiB':123},'firewall':{'configuration_sha256':'aaa'}}}
        after={'snapshot':{'listeners':['tcp LISTEN 0 100 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=2))'], 'containers':[{'ID':'a','Names':'existing','Image':'image','State':'running','Ports':'443','Status':'Up 3 days'}], 'memory':{'MemAvailable_KiB':120},'firewall':{'configuration_sha256':'aaa'}}}
        self.assertTrue(compare_snapshots(before,after)['unchanged'])
        after['snapshot']['firewall']['configuration_sha256']='bbb'
        self.assertIn('firewall',compare_snapshots(before,after)['changes'])
        after['snapshot']['containers'][0]['State']='exited'
        self.assertIn('containers',compare_snapshots(before,after)['changes'])


if __name__=='__main__':
    unittest.main()
