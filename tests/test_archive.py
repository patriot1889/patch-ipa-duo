import io
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from ipaduo.archive import Archive, safe_component, write_archive
from ipaduo.errors import Problem


def fixture(path: Path, entries: list[tuple[str, bytes, int]], *, compression=zipfile.ZIP_STORED) -> None:
    with zipfile.ZipFile(path, "w", allowZip64=False) as archive:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            # ZipInfo normalizes backslashes on Windows. Hostile fixtures must
            # retain their literal names in both local and central ZIP records.
            info.filename = name
            info.create_system = 3
            info.compress_type = compression
            info.external_attr = mode << 16
            archive.writestr(info, data)


class ArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ipa = self.root / "input.ipa"

    def basic(self, *, compression=zipfile.ZIP_STORED) -> None:
        fixture(self.ipa, [
            ("Payload/", b"", stat.S_IFDIR | 0o755),
            ("Payload/Example.app/", b"", stat.S_IFDIR | 0o755),
            ("Payload/Example.app/Exec", b"executable", stat.S_IFREG | 0o755),
            ("Payload/Example.app/Info.plist", b"plist", stat.S_IFREG | 0o644),
            ("iTunesArtwork", b"artwork", stat.S_IFREG | 0o644),
        ], compression=compression)

    def test_extract_and_validate_artwork_and_modes(self) -> None:
        self.basic(compression=zipfile.ZIP_DEFLATED)
        destination = self.root / "unpacked"
        destination.mkdir()
        with Archive(self.ipa) as archive:
            dirs, files, app = archive.validate_layout()
            self.assertEqual(app, "Payload/Example.app")
            self.assertIn("Payload/Example.app/Exec", files)
            self.assertIn("Payload", dirs)
            archive.validate_all()
            archive.extract(destination)
        self.assertEqual((destination / "Payload/Example.app/Exec").read_bytes(), b"executable")
        self.assertFalse((destination / "iTunesArtwork").exists())
        if os.name != "nt":  # Windows lacks Unix execute permission bits; ZIP attrs are tested below.
            self.assertEqual((destination / "Payload/Example.app/Exec").stat().st_mode & 0o777, 0o755)
            self.assertEqual((destination / "Payload/Example.app/Info.plist").stat().st_mode & 0o777, 0o644)

    def test_writer_sets_portable_unix_modes(self) -> None:
        source = self.root / "tree"
        app = source / "Payload/Example.app"
        app.mkdir(parents=True)
        (app / "Exec").write_bytes(b"executable")
        (app / "Info.plist").write_bytes(b"plist")
        (source / "adapter-transform-request.json").write_text("private work data")
        output = self.root / "output.ipa"
        write_archive(source, output, {"Payload/Example.app/Exec"})
        with Archive(output) as archive:
            archive.validate_all()
            self.assertEqual({entry.path for entry in archive.entries if entry.executable and not entry.directory},
                             {"Payload/Example.app/Exec"})
        with zipfile.ZipFile(output) as zipped:
            modes = {info.filename: info.external_attr >> 16 for info in zipped.infolist()}
            self.assertEqual(modes["Payload/Example.app/Exec"], stat.S_IFREG | 0o755)
            self.assertEqual(modes["Payload/Example.app/Info.plist"], stat.S_IFREG | 0o644)
            self.assertEqual(modes["Payload/Example.app/"], stat.S_IFDIR | 0o755)
            self.assertNotIn("adapter-transform-request.json", modes)

    def test_bad_crc_is_rejected_during_validation(self) -> None:
        self.basic()
        data = bytearray(self.ipa.read_bytes())
        position = data.index(b"executable")
        data[position] ^= 1
        self.ipa.write_bytes(data)
        with Archive(self.ipa) as archive, self.assertRaisesRegex(Problem, "checksum"):
            archive.validate_all()

    def test_streaming_descriptor_is_accepted(self) -> None:
        class NonSeekable(io.BytesIO):
            def seekable(self) -> bool:
                return False

            def seek(self, *args: object) -> None:
                raise OSError("not seekable")

        buffer = NonSeekable()
        with zipfile.ZipFile(buffer, "w", allowZip64=False) as archive:
            archive.writestr("Payload/Example.app/Info.plist", b"plist", compress_type=zipfile.ZIP_DEFLATED)
        self.ipa.write_bytes(buffer.getvalue())
        with Archive(self.ipa) as archive:
            self.assertEqual(len(archive.entries), 1)
            archive.validate_all()

    def test_local_name_disagreement_is_rejected(self) -> None:
        self.basic()
        data = bytearray(self.ipa.read_bytes())
        position = data.index(b"Payload/Example.app/Exec")
        data[position + len("Payload/Example.app/")] = ord("Z")
        self.ipa.write_bytes(data)
        with self.assertRaisesRegex(Problem, "conflicting local"):
            with Archive(self.ipa):
                pass

    def test_unexplained_prefix_is_rejected(self) -> None:
        self.basic()
        self.ipa.write_bytes(b"garbage" + self.ipa.read_bytes())
        with self.assertRaises(Problem):
            with Archive(self.ipa):
                pass

    def test_unsupported_extra_field_is_rejected(self) -> None:
        self.basic()
        data = bytearray(self.ipa.read_bytes())
        central = data.index(b"PK\x01\x02")
        name_length = struct.unpack_from("<H", data, central + 28)[0]
        struct.pack_into("<H", data, central + 30, 4)
        insertion = central + 46 + name_length
        data[insertion:insertion] = b"\x01\x00\x00\x00"
        eocd = data.rindex(b"PK\x05\x06")
        struct.pack_into("<I", data, eocd + 12,
                         struct.unpack_from("<I", data, eocd + 12)[0] + 4)
        self.ipa.write_bytes(data)
        with self.assertRaisesRegex(Problem, "Unsupported ZIP extra"):
            with Archive(self.ipa):
                pass

    def test_symlink_entry_is_rejected(self) -> None:
        fixture(self.ipa, [("Payload/Example.app/link", b"target", stat.S_IFLNK | 0o777)])
        with self.assertRaisesRegex(Problem, "link"):
            with Archive(self.ipa):
                pass

    def test_case_and_normalization_collision_are_rejected(self) -> None:
        for first, second in (("File", "file"), ("caf\u00e9", "cafe\u0301")):
            with self.subTest(first=first):
                fixture(self.ipa, [(f"Payload/Example.app/{name}", b"x", stat.S_IFREG | 0o644)
                                   for name in (first, second)])
                with Archive(self.ipa) as archive, self.assertRaisesRegex(Problem, "collision"):
                    archive.validate_layout()

    def test_unsafe_windows_names_and_traversal_are_rejected(self) -> None:
        for name in ("../escape", "CON.txt", "trailing.", "a\\b", "a:b", "a?b", "COM¹", "CONIN$", "CON .txt", "a\u0085b"):
            with self.subTest(name=name):
                fixture(self.ipa, [(f"Payload/Example.app/{name}", b"x", stat.S_IFREG | 0o644)])
                with self.assertRaisesRegex(Problem, "unsafe path"):
                    with Archive(self.ipa):
                        pass
        self.assertFalse(safe_component("NUL.txt"))
        self.assertTrue(safe_component("Info.plist"))

    def test_fixture_preserves_backslashes_with_windows_zip_normalization(self) -> None:
        name = "Payload/Example.app/a\\b"
        with patch("zipfile.os.sep", "\\"):
            fixture(self.ipa, [(name, b"x", stat.S_IFREG | 0o644)])
        # Check raw bytes: a ZipFile reader may normalize the name as well.
        self.assertEqual(self.ipa.read_bytes().count(name.encode("utf-8")), 2)
        with self.assertRaisesRegex(Problem, "unsafe path"):
            with Archive(self.ipa):
                pass

    def test_layout_rejects_extra_root(self) -> None:
        fixture(self.ipa, [("Payload/Example.app/Info.plist", b"x", stat.S_IFREG | 0o644),
                           ("other", b"x", stat.S_IFREG | 0o644)])
        with Archive(self.ipa) as archive, self.assertRaisesRegex(Problem, "Expected only"):
            archive.validate_layout()

    def test_writer_rejects_source_symlink(self) -> None:
        source = self.root / "tree"
        app = source / "Payload/Example.app"
        app.mkdir(parents=True)
        try:
            (app / "link").symlink_to(self.ipa)
        except OSError as error:
            if os.name == "nt":
                self.skipTest(f"Host does not permit symlink creation: {error}")
            raise
        with self.assertRaisesRegex(Problem, "link or special"):
            write_archive(source, self.root / "output.ipa", set())


if __name__ == "__main__":
    unittest.main()
