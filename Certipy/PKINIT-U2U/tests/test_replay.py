"""Runner contract tests; engine simulation here is NOT detector validation."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

class RunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = None
        if (ROOT/'replay.py').exists():
            spec = importlib.util.spec_from_file_location('replay', ROOT/'replay.py')
            cls.runner = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.runner)

    def setUp(self):
        self.assertIsNotNone(self.runner, 'portable replay.py must exist')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def test_packaged_bindings(self):
        config = self.runner.load_package(ROOT)
        self.assertEqual(len(config['cases']), 8)
        self.assertEqual(len(config['event_cases']), 31)
        self.assertEqual(config['detector_sha256'], '79a4c0304656b9df0b9cdfd2a906b072ba52b70f1018b884d2502e1a39c4ecbc')
        self.assertEqual(config['cases'][-1]['classification'], 'derived_partial_view_expected_false_negative')

    def test_detector_mutation_rejected(self):
        dest = self.work/'package'
        shutil.copytree(ROOT, dest)
        with (dest/'Zeek script/pkinit-u2u.zeek').open('ab') as f: f.write(b'\n')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.runner.load_package(dest)

    def test_capture_mutation_rejected(self):
        dest = self.work/'package'
        shutil.copytree(ROOT, dest)
        with (dest/'pcap/positive-pkinit-u2u.pcap').open('ab') as f: f.write(b'bad')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.runner.load_package(dest)

    def test_fixture_mutation_rejected(self):
        dest = self.work/'package'
        shutil.copytree(ROOT, dest)
        with (dest/'Zeek script/event-regressions.zeek').open('ab') as f: f.write(b'\n')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.runner.load_package(dest)

    def test_traversal_rejected(self):
        with self.assertRaises(ValueError): self.runner.package_path(ROOT, '../outside')
        with self.assertRaises(ValueError): self.runner.package_path(ROOT, '/outside')

    def test_missing_logs_are_valid_zero(self):
        row = self.runner.read_result(self.work, 0, 0, '', '')
        self.assertTrue(row['passed'])
        self.assertEqual(row['observed'], 0)
        self.assertEqual(row['notices'], 0)

    def test_requires_exact_log_and_notice_counts(self):
        (self.work/'pkinit_u2u.log').write_text('{}\n')
        self.assertFalse(self.runner.read_result(self.work, 1, 0, '', '')['passed'])
        (self.work/'notice.log').write_text(json.dumps({'note':'PKINIT_U2U::Self_Targeted_Ticket'})+'\n')
        self.assertTrue(self.runner.read_result(self.work, 1, 0, '', '')['passed'])
        with (self.work/'pkinit_u2u.log').open('a') as f: f.write('{}\n')
        self.assertFalse(self.runner.read_result(self.work, 1, 0, '', '')['passed'])

    def test_engine_stderr_stdout_reporter_error_and_nonzero_fail(self):
        for code,out,err in [(1,'',''),(0,'unexpected',''),(0,'','warning')]:
            self.assertFalse(self.runner.read_result(self.work,0,code,out,err)['passed'])
        (self.work/'reporter.log').write_text('{"level":"ERROR"}\n')
        self.assertFalse(self.runner.read_result(self.work,0,0,'','')['passed'])

    def test_corrupt_log_rejected(self):
        (self.work/'pkinit_u2u.log').write_text('not-json\n')
        with self.assertRaises(ValueError): self.runner.read_result(self.work,0,0,'','')

    def test_zeek_argv_and_constructed_case_option(self):
        config = self.runner.load_package(ROOT)
        case = config['event_cases'][0]
        engine = '/path with spaces/zeek'
        with patch.object(self.runner.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')) as run:
            row = self.runner.run_case(ROOT,config,case,self.work,engine,True)
        args = run.call_args.args[0]
        self.assertEqual(args[0],engine)
        self.assertEqual(args[1],'-Cr')
        self.assertIn(str(ROOT/'Zeek script/event-regressions.zeek'),args)
        self.assertIn('PKINIT_U2U::regression_case='+case['case'],args)
        self.assertNotIn('shell',run.call_args.kwargs)
        self.assertEqual(row['classification'],'constructed_event_regression')
        self.assertEqual(row['pcap_sha256'],config['cases'][0]['sha256'])

    def test_cli_help_standalone(self):
        r=subprocess.run([sys.executable,'-I',str(ROOT/'replay.py'),'--help'],capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('--zeek',r.stdout)
        self.assertIn('--events',r.stdout)

    def test_cli_missing_engine_fails_without_fake_success(self):
        out=self.work/'results'
        r=subprocess.run([sys.executable,'-I',str(ROOT/'replay.py'),'--zeek',str(self.work/'absent'),'--output',str(out)],capture_output=True,text=True)
        self.assertNotEqual(r.returncode,0)
        self.assertFalse((out/'receipt.json').exists())

    def test_cli_refuses_existing_output(self):
        r=subprocess.run([sys.executable,'-I',str(ROOT/'replay.py'),'--output',str(self.work)],capture_output=True,text=True)
        self.assertNotEqual(r.returncode,0)
        self.assertIn('exist',r.stderr.lower())

class PackageIntegrityTests(unittest.TestCase):
    def test_exact_public_allowlist(self):
        expected = {'README.md', 'PACKET-GUIDE.md', 'DETECTOR-GUIDE.md', 'cases.json',
                    'validation.json', 'SHA256SUMS', 'replay.py', 'tests/test_replay.py',
                    'Zeek script/pkinit-u2u.zeek', 'Zeek script/event-regressions.zeek'}
        config = json.loads((ROOT/'cases.json').read_text())
        expected.update(case['pcap'] for case in config['cases'])
        self.assertEqual({str(p.relative_to(ROOT)) for p in ROOT.rglob('*') if p.is_file()}, expected)

    def test_manifest_binds_every_public_file(self):
        import hashlib
        manifest = ROOT/'SHA256SUMS'
        self.assertTrue(manifest.exists(), 'SHA256SUMS must exist')
        members = {}
        for line in manifest.read_text().splitlines():
            digest, name = line.split('  ', 1)
            self.assertNotIn(name, members)
            self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(), digest)
            members[name] = digest
        self.assertEqual(set(members), {str(p.relative_to(ROOT)) for p in ROOT.rglob('*') if p.is_file() and p != manifest})

    def test_sanitized_execution_binds_current_inputs(self):
        import hashlib
        validation = ROOT/'validation.json'
        self.assertTrue(validation.exists(), 'Sanitized actual execution must exist')
        receipt = json.loads(validation.read_text())
        self.assertTrue(receipt['passed'])
        self.assertEqual(len(receipt['cases']), 39)
        for path, key in [('replay.py', 'runner_sha256'), ('cases.json', 'cases_manifest_sha256'),
                          ('Zeek script/pkinit-u2u.zeek', 'detector_sha256'),
                          ('Zeek script/event-regressions.zeek', 'event_fixture_sha256')]:
            self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(), receipt[key])
        for row in receipt['cases']:
            self.assertTrue(row['passed'])
            self.assertEqual(row['expected'], row['observed'])
            self.assertEqual(row['expected'], row['notices'])
        public = validation.read_text()
        for forbidden in ['sensor_root', '/srv/', '/home/', '/mnt/', 'reporter_errors', 'tgt_sha256']:
            self.assertNotIn(forbidden, public)


if __name__ == '__main__': unittest.main()
