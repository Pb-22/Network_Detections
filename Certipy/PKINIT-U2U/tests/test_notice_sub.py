"""Actual offline Zeek output regression; requires Zeek 9.0.0."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NoticeAccountTests(unittest.TestCase):
    def test_positive_notice_sub_contains_only_account(self):
        engine = os.environ.get('ZEEK_BIN') or shutil.which('zeek')
        if not engine:
            self.skipTest('Set ZEEK_BIN to run the real Zeek output regression')
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            result = subprocess.run([
                engine, '-Cr', str(ROOT / 'pcap/positive-pkinit-u2u.pcap'),
                str(ROOT / 'Zeek script/pkinit-u2u.zeek'), 'LogAscii::use_json=T',
            ], cwd=work, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, '')
            self.assertEqual(result.stderr, '')
            findings = [json.loads(line) for line in (work / 'pkinit_u2u.log').read_text().splitlines()]
            notices = [json.loads(line) for line in (work / 'notice.log').read_text().splitlines()
                       if json.loads(line).get('note') == 'PKINIT_U2U::Self_Targeted_Ticket']
            self.assertEqual(len(findings), 1)
            self.assertEqual(len(notices), 1)
            account = findings[0]['principal'] + '@' + findings[0]['realm']
            self.assertEqual(notices[0]['sub'], account)
            self.assertEqual(notices[0]['msg'],
                             'PKINIT followed by linked self-targeted U2U ticket issuance for ' + account)


if __name__ == '__main__':
    unittest.main()
