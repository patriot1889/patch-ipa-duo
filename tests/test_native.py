"""Native artifact compatibility and integrity without a host compiler."""
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from ipaduo import native, macho
from ipaduo.bundles import read_plist
from ipaduo.cli import patch_command
from ipaduo.errors import Problem
from test_pipeline import executable, make_ipa, read_ipa
from test_macho import fat


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_old_minimum_uses_compatible_prebuilt(self):
        source, output = self.root / 'source.ipa', self.root / 'out.ipa'
        make_ipa(source, executable(minimum=14 << 16), {'MinimumOSVersion': '14.0'})
        with patch('ipaduo.native.build', side_effect=AssertionError('Must use compatible bundle')), redirect_stdout(io.StringIO()):
            patch_command(['patch', str(source), '--output', str(output), '--bars', 'top'])
        info = plistlib.loads(read_ipa(output)['Payload/Test.app/Info.plist'])
        self.assertEqual(info['MinimumOSVersion'], '14.0')

    def test_older_than_prebuilt_falls_back_to_exact_target(self):
        executable_path = self.root / 'Fixture'
        executable_path.write_bytes(executable(minimum=11 << 16))
        output = self.root / 'library.dylib'
        with patch('ipaduo.native.build', side_effect=Problem('build fallback reached')) as builder:
            with self.assertRaisesRegex(Problem, 'build fallback reached'):
                native.obtain(executable_path, native.ROOT / 'native/IPAPatcherBars.m', native.BAR_LOAD,
                              ['PATCH_TOP=1'], 'bars/top', output, self.root)
        self.assertEqual(builder.call_args.args[3], [('arm64', 11 << 16)])
        self.assertFalse(output.exists())

    def test_fat_executable_gets_both_library_architectures(self):
        source, output = self.root / 'source.ipa', self.root / 'out.ipa'
        make_ipa(source, fat([executable(subtype=2), executable()]))
        with patch('ipaduo.native.build', side_effect=AssertionError('Must use bundle')), redirect_stdout(io.StringIO()):
            patch_command(['patch', str(source), '--output', str(output), '--bars', 'side'])
        result = read_ipa(output)
        exe, lib = self.root / 'exe', self.root / 'lib'
        exe.write_bytes(result['Payload/Test.app/Fixture'])
        lib.write_bytes(result['Payload/Test.app/Frameworks/IPAPatcherBars.dylib'])
        native.validate_library(lib, exe, native.BAR_LOAD)
        self.assertEqual(macho.architectures(lib, file_type=6), ['arm64', 'arm64e'])
        self.assertTrue(all(r.sdk == (27 << 16 | 1 << 8) for r in macho.sdk_records(exe)))

    def test_corrupt_and_stale_bundles_fail_without_build(self):
        executable_path = self.root / 'Fixture'
        executable_path.write_bytes(executable())
        with tempfile.TemporaryDirectory() as temp:
            prebuilt = Path(temp)
            original = json.loads((native.PREBUILT / 'manifest.json').read_text())
            item = original['libraries']['bars/top']
            item['file'] = 'test.dylib'
            (prebuilt / 'test.dylib').write_bytes(b'corrupted')
            (prebuilt / 'manifest.json').write_text(json.dumps(original))
            with patch.object(native, 'PREBUILT', prebuilt), patch('ipaduo.native.build', side_effect=AssertionError('Do not fall back')):
                with self.assertRaisesRegex(Problem, 'checksum mismatch'):
                    native.obtain(executable_path, native.ROOT / 'native/IPAPatcherBars.m', native.BAR_LOAD,
                                  ['PATCH_TOP=1'], 'bars/top', self.root / 'out', self.root)
                item['sourceHash'] = 'old'
                (prebuilt / 'manifest.json').write_text(json.dumps(original))
                with self.assertRaisesRegex(Problem, 'stale'):
                    native.obtain(executable_path, native.ROOT / 'native/IPAPatcherBars.m', native.BAR_LOAD,
                                  ['PATCH_TOP=1'], 'bars/top', self.root / 'out', self.root)

    def test_source_hash_survives_windows_line_endings(self):
        source = self.root / 'source.m'
        source.write_bytes(b'line1\nline2\n')
        before = native.fingerprint(source, 'library', [])
        source.write_bytes(b'line1\r\nline2\r\n')
        self.assertEqual(before, native.fingerprint(source, 'library', []))

    def test_malformed_xml_is_a_clean_failure(self):
        source = self.root / 'Info.plist'
        source.write_bytes(b'<plist><dict>')
        with self.assertRaisesRegex(Problem, 'Invalid Info.plist'):
            read_plist(source)

    def test_adapter_transform_entry_point(self):
        # Reuse adapter-owned fixture generators; this launches the actual adapter
        # subprocess and exercises temporary-file replacement on the current OS.
        package = native.ROOT / 'adapters/com.allenheath.SQU.MixPad'
        spec = importlib.util.spec_from_file_location('sq_fixtures', package / 'test_executable.py')
        fixtures = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixtures)
        data, entitlements = fixtures.fixture()
        exe = self.root / 'executable'
        exe.write_bytes(data)
        request = self.root / 'request.json'
        request.write_text(json.dumps({'schemaVersion': 1, 'executable': str(exe),
                                       'injectedLibraries': [fixtures.PATCH.DISCOVERY_LIBRARY]}))
        result = subprocess.run([sys.executable, str(package / 'patch-executable.py'), str(request)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = {key: value for key, value in entitlements.items() if key != fixtures.MULTICAST}
        self.assertEqual(plistlib.loads(fixtures.blobs(exe.read_bytes())[5][8:]), expected)


if __name__ == '__main__':
    unittest.main()
