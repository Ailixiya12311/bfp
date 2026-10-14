import json
import pathlib
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import race
from remote import LabError


class RacePreparationTests(unittest.TestCase):
    def test_collects_new_packages_and_all_platforms_but_not_nested_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            paths=('go.mod','main.go','clientconfig/config.go',
                   'future_product/product_windows.go','future_product/product_linux.go',
                   'future_product/product_test.go','future_product/credentials.json',
                   'integrations/go.mod','integrations/native.go',
                   'session/nested/go.mod','session/nested/other.go',
                   '.staging/protocol/frame.go','dist/source/main.go',
                   'lab/runs/source/main.go','verification/old/main.go',
                   'third_party/dependency/dependency.go','vendor/dependency.go')
            for relative in paths:
                path=root/relative
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text('fixture\n')
            collected=[path.relative_to(root).as_posix()
                       for path in race.collect_module_source(root)]
            self.assertEqual(collected,['clientconfig/config.go',
                'future_product/product_linux.go','future_product/product_test.go',
                'future_product/product_windows.go','go.mod','main.go'])

    def test_invalid_related_hash_rejected_before_freezing(self):
        with mock.patch.object(race,'freeze_source') as freeze:
            for value in ('a'*65,'a'*63,'z'*64,'../secret'):
                with self.assertRaises(LabError):race.execute(value)
            freeze.assert_not_called()

    def test_freeze_uses_run_copy_offline_and_excludes_secret_configs(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            workspace=root/'workspace'
            output=root/'run'
            workspace.mkdir();output.mkdir()
            (workspace/'go.mod').write_text('module example\n\ngo 1.27.0\n')
            (workspace/'go.sum').write_text('test dependency fixture\n')
            (workspace/'protocol').mkdir()
            (workspace/'protocol'/'frame.go').write_text('package protocol\n')
            (workspace/'protocol'/'secret.json').write_text('DO-NOT-COPY')
            (workspace/'classification').mkdir()
            (workspace/'classification'/'rules.go').write_text('package classification\n')
            (workspace/'internal'/'securefile').mkdir(parents=True)
            (workspace/'internal'/'securefile'/'file.go').write_text('package securefile\n')
            original=(workspace/'go.mod').read_bytes()
            def fake_vendor(command,**kwargs):
                self.assertEqual(command,['go','mod','vendor'])
                self.assertEqual(kwargs['cwd'],output/'source')
                self.assertEqual(kwargs['env']['GOPROXY'],'off')
                self.assertEqual(kwargs['env']['GOTOOLCHAIN'],'local')
                vendor=kwargs['cwd']/'vendor'
                vendor.mkdir();(vendor/'modules.txt').write_text('mock vendor tree\n')
                return SimpleNamespace(returncode=0,stderr='')
            with mock.patch.object(race,'WORKSPACE',workspace),mock.patch.object(race.subprocess,'run',side_effect=fake_vendor):
                archive,manifest,vendor_hash=race.freeze_source(output)
            self.assertEqual((workspace/'go.mod').read_bytes(),original)
            self.assertFalse((workspace/'vendor').exists())
            self.assertEqual([row['path'] for row in manifest],['classification/rules.go','go.mod','go.sum','internal/securefile/file.go','protocol/frame.go'])
            with tarfile.open(archive) as tar:
                names=tar.getnames()
            self.assertIn('source/protocol/frame.go',names)
            self.assertIn('source/internal/securefile/file.go',names)
            self.assertIn('source/classification/rules.go',names)
            self.assertIn('source/vendor/modules.txt',names)
            self.assertNotIn('source/protocol/secret.json',names)
            report=json.loads((output/'source-manifest.json').read_text())
            self.assertEqual(report['vendor_tree_sha256'],vendor_hash)
            self.assertEqual(len(vendor_hash),64)


if __name__=='__main__':unittest.main()
