"""Standard-library regression tests for the synthetic fixture harness."""
import importlib.util
import pathlib
import struct
import subprocess
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent


class HarnessTests(unittest.TestCase):
    def test_cli_help(self):
        for name in ('generate_fixtures.py', 'run-tests.py'):
            result = subprocess.run([sys.executable, str(HERE / name), '--help'],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('--output', result.stdout)

    def test_model_and_wire(self):
        spec = importlib.util.spec_from_file_location('fixtures', HERE / 'generate_fixtures.py')
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cases = module.cases()
        self.assertEqual(len(cases), 28)
        self.assertEqual(len({c['id'] for c in cases}), 28)
        self.assertEqual(sum(bool(c['notice']) for c in cases), 9)
        for arch, magic in [('x86', 0x10b), ('x64', 0x20b), ('arm64', 0x20b)]:
            model = module.pe_model(arch)
            self.assertEqual(len(model), 1024)
            self.assertEqual(model[:2], b'MZ')
            self.assertEqual(model[128:132], b'PE\0\0')
            self.assertEqual(struct.unpack_from('<H', model, 152)[0], magic)
            self.assertEqual(model[512:], bytes(512))  # no section code
        wire = module.pcap(cases[0])
        self.assertEqual(wire, module.pcap(cases[0]))
        offset, flags = 24, []
        while offset < len(wire):
            _, _, length, original = struct.unpack_from('<IIII', wire, offset)
            self.assertEqual(length, original)
            packet = wire[offset + 16:offset + 16 + length]
            ip, tcp = packet[14:34], packet[34:]
            self.assertEqual(module.checksum(ip), 0)
            pseudo = ip[12:20] + b'\0\x06' + struct.pack('!H', len(tcp))
            self.assertEqual(module.checksum(pseudo + tcp), 0)
            flags.append(tcp[13])
            offset += 16 + length
        self.assertEqual(flags[:3], [2, 18, 16])
        self.assertEqual(sum(bool(f & 1) for f in flags), 2)
        self.assertEqual(offset, len(wire))


if __name__ == '__main__':
    unittest.main()
