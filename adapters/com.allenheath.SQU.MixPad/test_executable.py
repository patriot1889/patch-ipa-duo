#!/usr/bin/env python3
"""Adapter-local regression fixtures for import/entitlement transformations."""
import hashlib
import importlib.util
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("sq_executable", Path(__file__).with_name("patch-executable.py"))
PATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PATCH)
MULTICAST = "com.apple.developer.networking.multicast"


def tlv(tag, payload):
    size = len(payload)
    length = bytes([size]) if size < 128 else bytes([0x82]) + struct.pack(">H", size) if size > 255 else bytes([0x81, size])
    return bytes([tag]) + length + payload


def der_value(value):
    if isinstance(value, bool):
        return tlv(1, b"\xff" if value else b"\0")
    if isinstance(value, str):
        return tlv(12, value.encode())
    if isinstance(value, list):
        return tlv(0x30, b"".join(der_value(item) for item in value))
    if isinstance(value, dict):
        return tlv(0xB0, b"".join(tlv(0x30, tlv(12, key.encode()) + der_value(item)) for key, item in sorted(value.items())))
    raise AssertionError("Unsupported fixture value")


def der_dictionary(values):
    entries = b"".join(tlv(0x30, tlv(12, key.encode()) + der_value(value)) for key, value in sorted(values.items()))
    return tlv(0x70, b"\2\1\1" + tlv(0xB0, entries))


def signature(entitlements, der=None):
    xml = plistlib.dumps(entitlements)
    blobs = [(5, struct.pack(">II", 0xFADE7171, len(xml) + 8) + xml)]
    der = der_dictionary(entitlements) if der is None else der
    blobs.append((7, struct.pack(">II", 0xFADE7172, len(der) + 8) + der))
    for slot, algorithm, width, type_ in ((0, hashlib.sha1, 20, 1), (0x1000, hashlib.sha256, 32, 2)):
        offset = 44 + 7 * width
        cd = bytearray(b"\x55" * (offset + width))
        struct.pack_into(">9I", cd, 0, 0xFADE0C02, len(cd), 0x20001, 2, offset, 0, 7, 1, 512)
        cd[36:40] = bytes([width, type_, 0, 12])
        for special, blob in blobs:
            start = offset - special * width
            cd[start:start + width] = algorithm(blob).digest()
        blobs.append((slot, cd))
    blobs.append((2, struct.pack(">II", 0xFADE0C01, 12) + b"test"))
    result = bytearray(12 + 8 * len(blobs))
    for index, (slot, blob) in enumerate(blobs):
        result.extend(b"\0" * (-len(result) % 8))
        struct.pack_into(">II", result, 12 + index * 8, slot, len(result))
        result.extend(blob)
    struct.pack_into(">III", result, 0, 0xFADE0CC0, len(result), len(blobs))
    result.extend(b"\0" * (4096 - len(result)))
    assert len(result) == 4096
    return result


def dylib(name):
    name = name.encode() + b"\0"
    size = (24 + len(name) + 7) & ~7
    return struct.pack("<6I", 0xC, size, 24, 0, 0, 0) + name + b"\0" * (size - 24 - len(name))


def fixture(format_=1, der=None):
    entitlements = {"application-identifier": "TEAM.com.example.fixture", "com.apple.developer.team-identifier": "TEAM",
                    MULTICAST: True, "keychain-access-groups": ["TEAM.group1", "TEAM.group2"]}
    width = {1: 4, 2: 8, 3: 16}[format_]
    record = struct.pack("<Qq", 1 | (1 << 16), -42) if format_ == 3 else struct.pack("<I", 1 | (1 << 8)) + (struct.pack("<i", -42) if format_ == 2 else b"")
    fixups = struct.pack("<7I", 0, 28, 32, 32 + width, 1, format_, 0) + b"\0" * 4 + record + b"_sendmsg\0"
    commands = dylib(PATCH.ORIGINAL_LIBRARY) + dylib(PATCH.DISCOVERY_LIBRARY)
    commands += struct.pack("<4I", 0x80000034, 16, 512, len(fixups))
    commands += struct.pack("<4I", 0x1D, 16, 1024, 4096)
    result = bytearray(struct.pack("<8I", 0xFEEDFACF, 0x100000C, 0, 2, 4, len(commands), 0, 0) + commands)
    result.extend(b"\0" * (512 - len(result)))
    result.extend(fixups)
    result.extend(b"\0" * (1024 - len(result)))
    result.extend(signature(entitlements, der))
    return result, entitlements


def blobs(data):
    start, count = 1024, struct.unpack_from(">I", data, 1032)[0]
    result = {}
    for index in range(count):
        slot, offset = struct.unpack_from(">II", data, start + 12 + index * 8)
        size = struct.unpack_from(">I", data, start + offset + 4)[0]
        result[slot] = data[start + offset:start + offset + size]
    return result


class ExecutableTests(unittest.TestCase):
    def test_only_root_entitlement_is_removed(self):
        values = {MULTICAST: True, "com.example.nested": {MULTICAST: True}}
        source, _ = fixture()
        source[1024:] = signature(values)
        result = PATCH.transform(source)
        expected = {"com.example.nested": {MULTICAST: True}}
        result_blobs = blobs(result)
        self.assertEqual(plistlib.loads(result_blobs[5][8:]), expected)
        self.assertEqual(result_blobs[7][8:], der_dictionary(expected))

    def test_codesign_readback_and_ad_hoc_verification(self):
        with tempfile.TemporaryDirectory(prefix="sq-entitlements-") as temporary:
            root = Path(temporary)
            executable = root / "fixture"
            source = root / "main.c"
            source.write_text("int main(void) { return 0; }\n")
            entitlements = root / "entitlements.plist"
            entitlements.write_bytes(plistlib.dumps({MULTICAST: True, "com.example.preserve": True}))
            subprocess.run(["/usr/bin/xcrun", "clang", str(source), "-o", str(executable)], check=True, capture_output=True)
            subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--generate-entitlement-der", "--entitlements", str(entitlements), str(executable)], check=True, capture_output=True)
            data = bytearray(executable.read_bytes())
            PATCH.strip_entitlements(data, PATCH.commands(data))
            executable.write_bytes(data)
            result = subprocess.run(["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(executable)], check=True, capture_output=True)
            self.assertEqual(plistlib.loads(result.stdout), {"com.example.preserve": True})
            subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(executable)], check=True, capture_output=True)

    def test_import_formats_entitlements_and_unchanged_bytes(self):
        for format_ in (1, 2, 3):
            with self.subTest(format=format_):
                source, entitlements = fixture(format_)
                result = PATCH.transform(source)
                self.assertEqual(len(result), len(source))
                width = 8 if format_ == 3 else 4
                name = 512 + 32 + {1: 4, 2: 8, 3: 16}[format_]
                word = int.from_bytes(result[544:544 + width], "little")
                before = int.from_bytes(source[544:544 + width], "little")
                mask = 0xFFFF if format_ == 3 else 255
                self.assertEqual(word & mask, 2)
                self.assertEqual(word & ~mask, before & ~mask)
                self.assertEqual(result[name:name + 9], b"_sq_find\0")
                new, old = blobs(result), blobs(source)
                self.assertEqual(plistlib.loads(new[5][8:]), {key: value for key, value in entitlements.items() if key != MULTICAST})
                self.assertEqual(new[7][8:], der_dictionary({key: value for key, value in entitlements.items() if key != MULTICAST}))
                self.assertEqual(new[2], old[2])
                self.assertNotIn(MULTICAST.encode(), result[1024:])
                for slot, algorithm, size in ((0, hashlib.sha1, 20), (0x1000, hashlib.sha256, 32)):
                    changed = bytearray(new[slot])
                    hash_offset = struct.unpack_from(">I", changed, 16)[0]
                    for special in (5, 7):
                        offset = hash_offset - special * size
                        self.assertEqual(changed[offset:offset + size], algorithm(new[special]).digest())
                        changed[offset:offset + size] = old[slot][offset:offset + size]
                    self.assertEqual(changed, old[slot])
                result[544:544 + width] = source[544:544 + width]
                result[name:name + 8] = source[name:name + 8]
                result[1024:] = source[1024:]
                self.assertEqual(result, source)

    def test_fat_slices(self):
        first, _ = fixture(1)
        second, _ = fixture(3)
        struct.pack_into("<I", second, 8, 2)
        data = bytearray(struct.pack(">12I", 0xCAFEBABE, 2, 0x100000C, 0, 4096, len(first), 12, 0x100000C, 2, 16384, len(second), 12))
        data.extend(b"\0" * (4096 - len(data)))
        data.extend(first)
        data.extend(b"\0" * (16384 - len(data)))
        data.extend(second)
        result = PATCH.transform(data)
        self.assertEqual(len(result), len(data))
        self.assertEqual(result[:4096], data[:4096])
        self.assertNotIn(MULTICAST.encode(), result)
        self.assertEqual(result.count(b"_sq_find\0"), 2)

    def test_safe_rejection(self):
        source, _ = fixture()
        for description, mutate in (
            ("compressed symbols", lambda data: struct.pack_into("<I", data, 536, 1)),
            ("wrong source ordinal", lambda data: struct.pack_into("<I", data, 544, 3)),
            ("bad import format", lambda data: struct.pack_into("<I", data, 532, 99)),
            ("missing import name", lambda data: data.__setitem__(slice(548, 556), b"_unknown")),
            ("truncated signature bounds", lambda data: struct.pack_into("<I", data, 1028, 999999)),
        ):
            with self.subTest(description=description):
                changed = bytearray(source)
                mutate(changed)
                before = bytes(changed)
                with self.assertRaises(ValueError):
                    PATCH.transform(changed)
                self.assertEqual(changed, before)
        with self.assertRaises(ValueError):
            PATCH.transform(PATCH.transform(source))

    def test_xml_der_disagreement_and_malformed_der(self):
        source, entitlements = fixture()
        without = {key: value for key, value in entitlements.items() if key != MULTICAST}
        for der in (der_dictionary(without), b"\x70\x80", b"\x71\0"):
            with self.subTest(der=der):
                source, _ = fixture(der=der)
                with self.assertRaises(ValueError):
                    PATCH.transform(source)


if __name__ == "__main__":
    unittest.main()
