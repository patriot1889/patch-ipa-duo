#!/usr/bin/env python3
"""Build and run deterministic discovery tests; never sends network traffic."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ADAPTER = Path(__file__).resolve().parent


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


class DiscoveryTests(unittest.TestCase):
    def test_native_without_network(self):
        with tempfile.TemporaryDirectory(prefix="sq-discovery-native-") as temporary:
            binary = str(Path(temporary) / "tests")
            run("xcrun", "clang", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", str(ADAPTER / "discovery-tests.m"),
                "-o", binary)
            output = run(binary)
            self.assertRegex(output, r"PASS: \d+ deterministic discovery assertions; no network syscalls")

    def test_device_library_slices(self):
        with tempfile.TemporaryDirectory(prefix="sq-discovery-device-") as temporary:
            for architecture in ("arm64", "arm64e"):
                with self.subTest(architecture=architecture):
                    library = str(Path(temporary) / f"{architecture}.dylib")
                    install_name = "@executable_path/Frameworks/SQFind.dylib"
                    run("xcrun", "--sdk", "iphoneos", "clang",
                        "-target", f"{architecture}-apple-ios15.0", "-dynamiclib",
                        "-Wall", "-Wextra", "-Werror", "-Wl,-adhoc_codesign",
                        "-install_name", install_name,
                        str(ADAPTER / "discovery.m"), "-o", library)
                    run("codesign", "--verify", "--strict", library)
                    symbols = run("xcrun", "nm", "-g", library)
                    self.assertRegex(symbols, r"(?m)^\w+ T _sq_find$")
                    self.assertRegex(symbols, r"(?m)^\s+U _sendmsg$")
                    metadata = run("xcrun", "otool", "-l", library)
                    self.assertIn(install_name, metadata)
                    self.assertRegex(metadata, r"platform 2\s+minos 15\.0")


if __name__ == "__main__":
    unittest.main()
