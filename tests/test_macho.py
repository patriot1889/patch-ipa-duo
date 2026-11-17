import struct
import tempfile
import unittest
from pathlib import Path

from ipaduo.errors import Problem
from ipaduo import macho


LOAD_PATH = "@executable_path/Frameworks/Hook.dylib"


def command(kind, *words):
    return struct.pack("<" + "I" * (2 + len(words)), kind, 8 + 4 * len(words), *words)


def dylib_command(kind, name):
    encoded = name.encode() + b"\0"
    size = (24 + len(encoded) + 7) & ~7
    return struct.pack("<6I", kind, size, 24, 0, 0, 0) + encoded.ljust(size - 24, b"\0")


def segment(section_offset=0x1000, section_size=16, section_type=0):
    head = struct.pack("<II16sQQQQiiII", 0x19, 152, b"__TEXT".ljust(16, b"\0"),
                       0, 0x2000, 0, 0x1200, 7, 5, 1, 0)
    sec = struct.pack("<16s16sQQIIIIIIII", b"__text".ljust(16, b"\0"),
                      b"__TEXT".ljust(16, b"\0"), 0, section_size, section_offset,
                      2, 0, 0, section_type, 0, 0, 0)
    return head + sec


def thin(arch="arm64", file_type=2, *, platform=2, minimum=15 << 16,
         sdk=18 << 16, extra=(), section_offset=0x1000, legacy=False):
    subtype = 2 if arch == "arm64e" else 0
    build = (command(0x25, minimum, sdk) if legacy else
             command(0x32, platform, minimum, sdk, 0))
    commands = [build, segment(section_offset=section_offset), *extra]
    table = b"".join(commands)
    header = struct.pack("<8I", 0xFEEDFACF, macho.ARM64, subtype, file_type,
                         len(commands), len(table), 0, 0)
    return (header + table).ljust(0x1200, b"\0")


def fat(parts, *, fat64=False, little=False, offsets=None):
    width = 32 if fat64 else 20
    if offsets is None:
        offsets = [0x2000 + index * 0x2000 for index in range(len(parts))]
    endian = "<" if little else ">"
    magic = 0xCAFEBABF if fat64 else 0xCAFEBABE
    data = bytearray(struct.pack(endian + "2I", magic, len(parts)))
    for part, offset in zip(parts, offsets):
        cpu, subtype = struct.unpack_from("<2I", part, 4)
        if fat64:
            data.extend(struct.pack(endian + "2I2Q2I", cpu, subtype, offset, len(part), 14, 0))
        else:
            data.extend(struct.pack(endian + "5I", cpu, subtype, offset, len(part), 14))
    for part, offset in sorted(zip(parts, offsets), key=lambda x: x[1]):
        data.extend(b"\0" * max(0, offset - len(data)))
        data.extend(part)
    return bytes(data)


class MachOTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, data, name="binary"):
        path = self.root / name
        path.write_bytes(data)
        return path

    def assert_problem(self, diagnostic, action):
        with self.assertRaisesRegex(Problem, diagnostic):
            action()

    def test_thin_sdk_and_injection(self):
        path = self.write(thin())
        self.assertEqual(macho.architectures(path), ["arm64"])
        self.assertEqual(macho.slices(path), [macho.Slice(0, 0x1200)])
        self.assertEqual(macho.sdk_records(path), [macho.SDKRecord(48, 18 << 16, 15 << 16)])
        self.assertEqual(macho.version((27 << 16) | (1 << 8) | 2), "27.1.2")
        plan = macho.injection_plan(path, [LOAD_PATH])
        self.assertEqual(plan, [macho.Injection(0, 32 + 24 + 152, 2, 176)])
        macho.patch_sdk(path, 27 << 16)
        self.assertEqual(macho.sdk_records(path)[0].sdk, 27 << 16)
        macho.inject(path, plan, [LOAD_PATH])
        self.assertEqual(struct.unpack_from("<2I", path.read_bytes(), 16), (3, 176 + 64))
        self.assert_problem("already injected", lambda: macho.injection_plan(path, [LOAD_PATH]))

    def test_fat_formats_and_patch_both_slices(self):
        for fat64, little in ((False, False), (False, True), (True, False), (True, True)):
            with self.subTest(fat64=fat64, little=little):
                path = self.write(fat([thin("arm64e"), thin()], fat64=fat64, little=little))
                self.assertEqual(macho.architectures(path), ["arm64", "arm64e"])
                self.assertEqual([r.offset for r in macho.sdk_records(path)], [0x2000 + 48, 0x4000 + 48])
                macho.patch_sdk(path, 28 << 16)
                self.assertEqual([r.sdk for r in macho.sdk_records(path)], [28 << 16, 28 << 16])

    def test_rejects_invalid_macho(self):
        invalid = [
            (thin(platform=7), "not built for iOS device"),
            (thin(extra=[command(0x2C, 0, 0, 1, 0)]), "encrypted"),
            (thin(extra=[command(0x24, 0, 0)]), "not built for iOS device"),
            (thin(extra=[command(0x32, 2, 0, 0, 0)]), "exactly one SDK"),
            (thin(extra=[struct.pack("<2I", 0x99, 7)]), "load command size"),
            (fat([thin(), thin()], offsets=[0x2000, 0x3000]), "overlapping"),
            (fat([thin(), thin()]), "duplicate architecture"),
            (fat([thin()], fat64=True)[:-1], "out-of-bounds"),
        ]
        for data, diagnostic in invalid:
            with self.subTest(diagnostic=diagnostic):
                path = self.write(data)
                self.assert_problem(diagnostic, lambda: macho.sdk_records(path))

    def test_injection_rejects_unsafe_padding_and_duplicate_paths(self):
        path = self.write(thin(section_offset=32 + 24 + 152))
        self.assert_problem("Insufficient", lambda: macho.injection_plan(path, [LOAD_PATH]))
        data = bytearray(thin())
        data[32 + 24 + 152] = 1
        path.write_bytes(data)
        self.assert_problem("Insufficient", lambda: macho.injection_plan(path, [LOAD_PATH]))
        self.assert_problem("unique", lambda: macho.injection_plan(path, [LOAD_PATH, LOAD_PATH]))

    def test_injection_plan_detects_modified_file(self):
        path = self.write(thin())
        plan = macho.injection_plan(path, [LOAD_PATH])
        data = bytearray(path.read_bytes())
        data[32 + 24 + 152] = 1
        path.write_bytes(data)
        self.assert_problem("Insufficient", lambda: macho.inject(path, plan, [LOAD_PATH]))

    def test_prebuilt_dylib_selection_and_validation(self):
        dylibs = [thin("arm64e", file_type=6, extra=[dylib_command(0xD, LOAD_PATH)]),
                  thin("arm64", file_type=6, extra=[dylib_command(0xD, LOAD_PATH)])]
        source = self.write(fat(dylibs), "prebuilt")
        output = self.root / "selected"
        macho.select_architectures(source, output, ["arm64", "arm64e"])
        self.assertEqual(macho.architectures(output, file_type=6), ["arm64", "arm64e"])
        exe = self.write(fat([thin("arm64e"), thin()]), "exe")
        macho.validate_dylib(output, exe, LOAD_PATH)
        self.assert_problem("install name", lambda: macho.validate_dylib(output, exe, "other"))
        single = self.root / "single"
        macho.select_architectures(source, single, ["arm64"])
        self.assertEqual(macho.architectures(single, file_type=6), ["arm64"])
        self.assert_problem("architectures", lambda: macho.validate_dylib(single, exe, LOAD_PATH))

    def test_prebuilt_minimum_must_not_exceed_executable(self):
        dylib = self.write(thin(file_type=6, minimum=16 << 16,
                                extra=[dylib_command(0xD, LOAD_PATH)]), "prebuilt")
        exe = self.write(thin(minimum=15 << 16), "exe")
        self.assert_problem("deployment target", lambda: macho.validate_dylib(dylib, exe, LOAD_PATH))


if __name__ == "__main__":
    unittest.main()
