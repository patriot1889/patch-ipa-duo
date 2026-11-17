"""Portable integration fixtures: patch results, preservation and failure paths."""
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from ipaduo.cli import main, patch_command, parse, ROOT
from ipaduo.errors import Problem
from ipaduo import macho, native


def executable(sdk=18 << 16, minimum=15 << 16, subtype=0, encrypted=False, padding=True):
    section_offset = 4096 if padding else 208
    segment = struct.pack('<II16sQQQQIIII', 0x19, 152, b'__TEXT', 0x100000000, 8192, 0, 8192, 7, 5, 1, 0)
    section = struct.pack('<16s16sQQIIIIIIII', b'__text', b'__TEXT', 0x100000000 + section_offset,
                          32, section_offset, 2, 0, 0, 0x80000400, 0, 0, 0)
    commands = segment + section + struct.pack('<6I', 0x32, 24, 2, minimum, sdk, 0)
    if encrypted:
        commands += struct.pack('<6I', 0x2c, 24, 0, 0, 1, 0)
    result = bytearray(struct.pack('<8I', 0xfeedfacf, 0x100000c, subtype, 2, 3 if encrypted else 2, len(commands), 0, 0) + commands)
    result.extend(b'\0' * (8192 - len(result)))
    result[section_offset:section_offset + 32] = b'\x17' * 32
    return bytes(result)


def make_ipa(path, binary=None, changes=None, extra=None):
    info = {'CFBundleIdentifier': 'com.example.fixture', 'CFBundleExecutable': 'Fixture', 'CFBundlePackageType': 'APPL',
            'CFBundleSupportedPlatforms': ['iPhoneOS'], 'CFBundleVersion': '1', 'CFBundleShortVersionString': '1.0',
            'MinimumOSVersion': '15.0', 'UIDeviceFamily': [2], 'DTSDKName': 'iphoneos18.0',
            'UIApplicationSceneManifest': {'UISceneConfigurations': {'UIWindowSceneSessionRoleApplication': [{'UISceneConfigurationName': 'Default'}]}}}
    info.update(changes or {})
    entries = {'Payload/Test.app/Info.plist': plistlib.dumps(info), 'Payload/Test.app/Fixture': binary or executable(),
               'Payload/Test.app/resource.txt': b'untouched resource',
               'Payload/Test.app/_CodeSignature/CodeResources': b'original stale signature',
               'Payload/Test.app/embedded.mobileprovision': b'original profile', 'iTunesArtwork': b'allowed artwork'}
    entries.update(extra or {})
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, allowZip64=False) as archive:
        for name, data in entries.items():
            item = zipfile.ZipInfo(name)
            item.create_system = 3
            item.external_attr = (0o100755 if name.endswith('/Fixture') else 0o100644) << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(item, data)
    return entries


def read_ipa(path):
    with zipfile.ZipFile(path) as archive:
        return {item.filename: archive.read(item) for item in archive.infolist() if not item.is_dir()}


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / 'original with spaces.ipa'
        self.output = self.root / 'output with spaces.ipa'
        self.original = make_ipa(self.input)
        self.digest = hashlib.sha256(self.input.read_bytes()).digest()

    def run_patch(self, *options, source=None, output=None):
        with redirect_stdout(io.StringIO()):
            patch_command(['patch', str(source or self.input), '--output', str(output or self.output), *options])

    def test_generic_patch_preserves_resources_and_input(self):
        self.run_patch('--enable-iphone')
        result = read_ipa(self.output)
        info = plistlib.loads(result['Payload/Test.app/Info.plist'])
        self.assertEqual(info['UIDeviceFamily'], [1, 2])
        self.assertEqual(info['DTSDKName'], 'iphoneos27.1')
        self.assertEqual(info['DTPlatformVersion'], '27.1')
        self.assertNotIn('iTunesArtwork', result)
        for name, data in self.original.items():
            if name not in ('iTunesArtwork', 'Payload/Test.app/Info.plist', 'Payload/Test.app/Fixture'):
                self.assertEqual(result[name], data)
        before, after = self.original['Payload/Test.app/Fixture'], bytearray(result['Payload/Test.app/Fixture'])
        # Exactly the SDK word changes for metadata-only patching.
        offset = 32 + 152 + 16
        after[offset:offset+4] = before[offset:offset+4]
        self.assertEqual(bytes(after), before)
        self.assertEqual(self.digest, hashlib.sha256(self.input.read_bytes()).digest())
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(archive.getinfo('Payload/Test.app/Fixture').external_attr >> 16 & 0o777, 0o755)
            self.assertEqual(archive.getinfo('Payload/Test.app/resource.txt').external_attr >> 16 & 0o777, 0o644)

    def test_reserved_side_and_newer_sdk(self):
        make_ipa(self.input, executable(sdk=28 << 16))
        self.run_patch()
        self.assertEqual(plistlib.loads(read_ipa(self.output)['Payload/Test.app/Info.plist'])['DTSDKName'], 'iphoneos28.0')
        self.output.unlink()
        self.run_patch('--display', 'reserved-side', '--bars', 'side')
        self.assertEqual(plistlib.loads(read_ipa(self.output)['Payload/Test.app/Info.plist'])['DTSDKName'], 'iphoneos27.0')

    def test_native_hooks_without_build_tools(self):
        for mode in ('top', 'side'):
            with self.subTest(mode=mode), patch('ipaduo.native.build', side_effect=AssertionError('Must use prebuilt')):
                self.run_patch('--bars', mode)
                result = read_ipa(self.output)
                library_path = 'Payload/Test.app/Frameworks/IPAPatcherBars.dylib'
                self.assertIn(library_path, result)
                self.assertIn(native.BAR_LOAD.encode() + b'\0', result['Payload/Test.app/Fixture'])
                binary = self.root / 'fixture'
                binary.write_bytes(result['Payload/Test.app/Fixture'])
                self.assertEqual(macho.sdk_records(binary)[0].minimum, 15 << 16)
                library = self.root / 'library'
                library.write_bytes(result[library_path])
                native.validate_library(library, binary, native.BAR_LOAD)
                self.output.unlink()

    def test_failures_leave_no_output(self):
        for label, binary, changes in [
            ('encrypted', executable(encrypted=True), {}),
            ('minimum', executable(minimum=28 << 16), {}),
            ('plist minimum', executable(), {'MinimumOSVersion': '28.0'}),
            ('bad families', executable(), {'UIDeviceFamily': [True]}),
            ('missing scenes', executable(), {'UIApplicationSceneManifest': {}}),
            ('unsupported adapter', executable(), {'CFBundleIdentifier': 'com.plexapp.plex'}),
        ]:
            with self.subTest(case=label):
                make_ipa(self.input, binary, changes)
                with self.assertRaises(Problem):
                    self.run_patch()
                self.assertFalse(self.output.exists())
        make_ipa(self.input, executable(padding=False))
        with self.assertRaises(Problem):
            self.run_patch('--bars', 'top')
        self.assertFalse(self.output.exists())

    def test_existing_output_and_publication_race(self):
        self.output.write_bytes(b'preserve')
        with self.assertRaises(Problem):
            self.run_patch()
        self.assertEqual(self.output.read_bytes(), b'preserve')
        self.output.unlink()
        original_link = __import__('os').link
        def racing_link(source, output):
            self.output.write_bytes(b'other writer')
            return original_link(source, output)
        with patch('ipaduo.cli.os.link', side_effect=racing_link), self.assertRaises(Problem):
            self.run_patch()
        self.assertEqual(self.output.read_bytes(), b'other writer')

    def test_existing_hook_rejected(self):
        self.run_patch('--bars', 'top')
        second = self.root / 'second.ipa'
        for options in (['--bars', 'side'], ['--display', 'reserved-side']):
            with self.assertRaises(Problem):
                self.run_patch(*options, source=self.output, output=second)
            self.assertFalse(second.exists())

    def test_plex_and_forced_adapter(self):
        make_ipa(self.input, changes={'CFBundleIdentifier': 'com.plexapp.plex', 'CFBundleShortVersionString': '2026.22.0', 'CFBundleVersion': '2211'})
        self.run_patch()
        info = plistlib.loads(read_ipa(self.output)['Payload/Test.app/Info.plist'])
        self.assertIn('_airplay._tcp', info['NSBonjourServices'])
        self.output.unlink()
        make_ipa(self.input, changes={'CFBundleShortVersionString': '2026.22.0', 'CFBundleVersion': '2211'})
        self.run_patch('--adapter', 'com.plexapp.plex')
        info = plistlib.loads(read_ipa(self.output)['Payload/Test.app/Info.plist'])
        self.assertEqual(info['CFBundleIdentifier'], 'com.example.fixture')
        self.assertIn('_airplay._tcp', info['NSBonjourServices'])

    def test_cli_rejects_bad_options(self):
        for args in (['inspect', 'a', '--bars', 'top'], ['patch', 'a'],
                     ['patch', 'a', '--output', 'b', '--bars', 'top', '--bars', 'side'],
                     ['patch', 'a', '--output', 'b', '--adapter', '../escape'],
                     ['patch', 'a', '--output', 'b', '--display', 'reserved-side', '--bars', 'top']):
            with self.subTest(args=args), self.assertRaises(Problem):
                parse(args)
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(['patch', str(self.root / 'missing.ipa'), '--output', str(self.output)]), 1)

    def test_script_from_other_directory(self):
        result = subprocess.run([sys.executable, str(ROOT / 'patch-ipa-duo.py'), 'inspect', str(self.input)],
                                cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Adapter: generic', result.stdout)


if __name__ == '__main__':
    unittest.main()
