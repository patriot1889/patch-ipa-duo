"""Strict, portable IPA ZIP reading and writing.

The ZIP directory is parsed directly because zipfile deliberately accepts several
ambiguous layouts that are unsuitable for extracting an untrusted IPA.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
import struct
import unicodedata
import zlib

from .errors import Problem


_CHUNK = 128 * 1024
_MAX_ENTRY = 2 * 1024**3
_MAX_TOTAL = 8 * 1024**3
_MAX_CENTRAL = 32 * 1024**2
_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _safe_component(name: str) -> bool:
    if not name or name in (".", "..") or name[-1] in " .":
        return False
    if any(unicodedata.category(c) == "Cc" or c in '<>:"/\\|?*' for c in name):
        return False
    if name.split(".", 1)[0].rstrip(" ").upper() in _WINDOWS_RESERVED:
        return False
    return True


def safe_component(name: str) -> bool:
    """Return whether one IPA path component is portable and non-special."""
    return _safe_component(name)


def _safe_path(path: str) -> None:
    parts = path.split("/")
    if len(parts) > 40 or not all(_safe_component(part) for part in parts):
        raise Problem(f"IPA ZIP contains an unsafe path: {path!r}.")


def _extras(data: bytes, unix_mode: int) -> None:
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise Problem("Malformed ZIP extra field.")
        kind, length = struct.unpack_from("<HH", data, offset)
        offset += 4
        if length > len(data) - offset:
            raise Problem("Malformed ZIP extra field length.")
        value = data[offset : offset + length]
        valid = kind in (0x5455, 0x7875)
        valid |= kind == 0x5855 and length in (8, 12)
        valid |= kind == 0x7855 and length in (0, 4)
        valid |= kind == 0x5A53 and length == 2 and _u16(value, 0) == unix_mode
        if not valid:
            raise Problem(f"Unsupported ZIP extra field 0x{kind:x}.")
        offset += length


@dataclass(frozen=True)
class Entry:
    path: str
    directory: bool
    executable: bool
    method: int
    crc: int
    compressed: int
    expanded: int
    local: int
    data_offset: int
    record_end: int


class Archive:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        try:
            initial = self.path.lstat()
            if not stat.S_ISREG(initial.st_mode) or getattr(initial, "st_file_attributes", 0) & 0x400:
                raise Problem(f"Expected a regular file at {self.path.name}.")
            self._fd = os.open(self.path, flags)
            info = os.fstat(self._fd)
            if not stat.S_ISREG(info.st_mode):
                raise Problem(f"Expected a regular file at {self.path.name}.")
            self._size = info.st_size
            self.entries = self._parse()
        except BaseException:
            if hasattr(self, "_fd"):
                os.close(self._fd)
                del self._fd
            raise

    def __enter__(self) -> Archive:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if hasattr(self, "_fd"):
            os.close(self._fd)
            del self._fd

    def _read(self, offset: int, count: int) -> bytes:
        if offset < 0 or count < 0 or offset > self._size or count > self._size - offset:
            raise Problem("A ZIP record points outside its file.")
        os.lseek(self._fd, offset, os.SEEK_SET)
        data = bytearray()
        while len(data) < count:
            chunk = os.read(self._fd, count - len(data))
            if not chunk:
                break
            data.extend(chunk)
        data = bytes(data)
        if len(data) != count:
            raise Problem("An input file was truncated while reading it.")
        return data

    def _parse(self) -> list[Entry]:
        tail_start = max(0, self._size - 65557)
        tail = self._read(tail_start, self._size - tail_start)
        if len(tail) < 22:
            raise Problem("Input is too small to be an IPA ZIP archive.")
        eocd = next((i for i in range(len(tail) - 22, -1, -1)
                     if _u32(tail, i) == 0x06054B50 and i + 22 + _u16(tail, i + 20) == len(tail)), None)
        if eocd is None:
            raise Problem("IPA ZIP end record is missing.")
        count = _u16(tail, eocd + 10)
        central_size = _u32(tail, eocd + 12)
        central_offset = _u32(tail, eocd + 16)
        if (_u16(tail, eocd + 4) or _u16(tail, eocd + 6)
                or _u16(tail, eocd + 8) != count or not 0 < count < 65535
                or central_size > _MAX_CENTRAL
                or central_offset + central_size != tail_start + eocd):
            raise Problem("Unsupported split, ZIP64, empty, or oversized ZIP directory.")
        central = self._read(central_offset, central_size)
        entries: list[Entry] = []
        offset = total = 0
        for _ in range(count):
            if central_size - offset < 46 or _u32(central, offset) != 0x02014B50:
                raise Problem("Malformed ZIP central directory.")
            flags, method = struct.unpack_from("<HH", central, offset + 8)
            if flags & ~0x080E or method not in (0, 8) or (method == 0 and flags & 0x0006):
                raise Problem("Encrypted ZIP entries and unsupported ZIP methods or flags are outside IPA scope.")
            crc, compressed, expanded = struct.unpack_from("<III", central, offset + 16)
            name_length, extra_length, comment_length = struct.unpack_from("<HHH", central, offset + 28)
            local = _u32(central, offset + 42)
            name_start = offset + 46
            name_end = name_start + name_length
            if (_u16(central, offset + 34) != 0 or not 0 < name_length <= 1024
                    or name_end + extra_length + comment_length > central_size
                    or local >= central_offset or compressed == 0xFFFFFFFF or expanded > _MAX_ENTRY):
                raise Problem("Invalid or oversized IPA ZIP entry.")
            total += expanded
            if total > _MAX_TOTAL:
                raise Problem("IPA expands beyond the 8 GiB safety limit.")
            name = central[name_start:name_end]
            try:
                raw_path = name.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise Problem("IPA ZIP contains a filename outside UTF-8.") from exc
            directory = raw_path.endswith("/")
            path = raw_path[:-1] if directory else raw_path
            _safe_path(path)
            attributes = _u32(central, offset + 38)
            unix_mode = attributes >> 16
            kind = unix_mode & 0o170000
            if (kind not in (0, stat.S_IFDIR if directory else stat.S_IFREG)
                    or attributes & 0x08 or (attributes & 0x10 and not directory)
                    or (directory and expanded != 0)
                    or (method == 0 and compressed != expanded)):
                raise Problem("IPA ZIP contains a link, special file, or inconsistent file type.")
            _extras(central[name_end : name_end + extra_length], unix_mode)
            header = self._read(local, 30)
            local_name_length, local_extra_length = struct.unpack_from("<HH", header, 26)
            data_offset = local + 30 + name_length + local_extra_length
            if (_u32(header, 0) != 0x04034B50 or _u16(header, 6) != flags
                    or _u16(header, 8) != method or local_name_length != name_length
                    or data_offset + compressed > central_offset):
                raise Problem("ZIP local header disagrees with the central directory.")
            fields = self._read(local + 30, name_length + local_extra_length)
            if fields[:name_length] != name:
                raise Problem("ZIP entry has conflicting local and central filenames.")
            _extras(fields[name_length:], unix_mode)
            record_end = data_offset + compressed
            if not flags & 0x08:
                if (_u32(header, 14), _u32(header, 18), _u32(header, 22)) != (crc, compressed, expanded):
                    raise Problem("ZIP local size or checksum disagrees with the central directory.")
            else:
                if (_u32(header, 14) not in (0, crc) or _u32(header, 18) not in (0, compressed)
                        or _u32(header, 22) not in (0, expanded) or central_offset - record_end < 12):
                    raise Problem("Invalid ZIP streaming metadata.")
                descriptor = self._read(record_end, min(16, central_offset - record_end))
                start = 4 if (len(descriptor) == 16 and _u32(descriptor, 0) == 0x08074B50
                              and _u32(descriptor, 4) == crc) else 0
                if (_u32(descriptor, start), _u32(descriptor, start + 4), _u32(descriptor, start + 8)) != (crc, compressed, expanded):
                    raise Problem("ZIP data descriptor disagrees with the central directory.")
                record_end += start + 12
            entries.append(Entry(path, directory, bool(unix_mode & 0o111), method, crc,
                                 compressed, expanded, local, data_offset, record_end))
            offset = name_end + extra_length + comment_length
        next_local = 0
        for entry in sorted(entries, key=lambda item: item.local):
            if entry.local != next_local:
                raise Problem("IPA ZIP contains overlapping entries or unexplained archive data.")
            next_local = entry.record_end
        if offset != central_size or next_local != central_offset:
            raise Problem("IPA ZIP contains unexplained archive data.")
        return entries

    def validate_layout(self) -> tuple[set[str], set[str], str]:
        artwork = [entry for entry in self.entries if entry.path == "iTunesArtwork" and not entry.directory]
        if len(artwork) > 1:
            raise Problem("Duplicate iTunesArtwork archive entry.")
        spellings: dict[str, str] = {}
        dirs: set[str] = set()
        files: set[str] = set()
        explicit: set[str] = set()
        for entry in self.entries:
            if entry.path == "iTunesArtwork" and not entry.directory:
                continue
            if entry.path in explicit:
                raise Problem(f"Duplicate or normalization-equivalent ZIP path: {entry.path}.")
            explicit.add(entry.path)
            parts = entry.path.split("/")
            for i in range(len(parts)):
                path = "/".join(parts[: i + 1])
                folded = unicodedata.normalize("NFC", path).casefold()
                previous = spellings.get(folded)
                if previous is not None and previous != path:
                    raise Problem(f"Case or normalization collision in IPA ZIP: {path}.")
                spellings[folded] = path
                if i < len(parts) - 1 or entry.directory:
                    dirs.add(path)
                    if len(dirs) > 100_000:
                        raise Problem("IPA contains too many directories.")
                else:
                    files.add(path)
        if not files.isdisjoint(dirs):
            raise Problem("A ZIP file path is also a directory or has child entries.")
        apps = {path for path in dirs if path.startswith("Payload/")
                and len(path.split("/")) == 2 and path.endswith(".app")}
        if (len(apps) != 1 or any(path != "Payload" and path not in apps
                                  and not any(path.startswith(app + "/") for app in apps) for path in dirs)
                or any(not any(path.startswith(app + "/") for app in apps) for path in files)):
            raise Problem("Expected only Payload/<one iOS app>.app and its contents in the IPA.")
        return dirs, files, next(iter(apps))

    def _consume(self, entry: Entry, output: object | None = None) -> None:
        written = checksum = 0

        def write(data: bytes) -> None:
            nonlocal written, checksum
            if len(data) > entry.expanded - written:
                raise Problem(f"ZIP entry expands beyond its declared size: {entry.path}.")
            checksum = zlib.crc32(data, checksum)
            if output is not None:
                output.write(data)  # type: ignore[union-attr]
            written += len(data)

        remaining = entry.compressed
        if entry.method == 0:
            while remaining:
                count = min(_CHUNK, remaining)
                write(self._read(entry.data_offset + entry.compressed - remaining, count))
                remaining -= count
        else:
            stream = zlib.decompressobj(-zlib.MAX_WBITS)
            while remaining and not stream.eof:
                count = min(_CHUNK, remaining)
                data = self._read(entry.data_offset + entry.compressed - remaining, count)
                remaining -= count
                while data:
                    try:
                        write(stream.decompress(data, _CHUNK))
                    except zlib.error as exc:
                        raise Problem(f"Invalid deflate stream: {entry.path}.") from exc
                    if stream.eof:
                        if stream.unused_data or stream.unconsumed_tail or remaining:
                            raise Problem(f"ZIP entry has bytes after its deflate stream: {entry.path}.")
                        break
                    data = stream.unconsumed_tail
            if not stream.eof:
                raise Problem(f"Incomplete deflate stream: {entry.path}.")
        if written != entry.expanded or checksum != entry.crc:
            raise Problem(f"ZIP entry failed its size or checksum check: {entry.path}.")

    def validate_all(self) -> None:
        self.validate_layout()
        for entry in self.entries:
            self._consume(entry)

    def extract(self, root: Path | str) -> None:
        dirs, _, _ = self.validate_layout()
        root = Path(root)
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or any(root.iterdir()):
            raise Problem("IPA extraction requires an empty regular directory.")
        for directory in sorted(dirs, key=lambda path: (path.count("/"), path)):
            (root / directory).mkdir(mode=0o755)
            os.chmod(root / directory, 0o755)
        for entry in self.entries:
            if entry.directory or entry.path == "iTunesArtwork":
                self._consume(entry)
                continue
            path = root / entry.path
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            with os.fdopen(os.open(path, flags, 0o600), "wb") as output:
                self._consume(entry, output)
            os.chmod(path, 0o755 if entry.executable else 0o644)


def write_archive(root: Path | str, output: Path | str, executable_paths: set[str]) -> None:
    """Write a fresh IPA using fixed Unix modes and no ZIP64 records."""
    root, output = Path(root), Path(output)
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise Problem("IPA source must be a regular directory.")
    if output.resolve().is_relative_to(root.resolve()):
        raise Problem("IPA output must be outside its source directory.")
    paths: list[tuple[str, Path, bool, int]] = []

    def scan(directory: Path, relative: str = "") -> None:
        for child in sorted(directory.iterdir(), key=lambda path: path.name):
            name = f"{relative}/{child.name}" if relative else child.name
            _safe_path(name)
            info = child.lstat()
            if stat.S_ISDIR(info.st_mode):
                paths.append((name, child, True, 0))
                scan(child, name)
            elif stat.S_ISREG(info.st_mode):
                if info.st_size > _MAX_ENTRY:
                    raise Problem(f"IPA source file exceeds 2 GiB: {name}.")
                paths.append((name, child, False, info.st_size))
            else:
                raise Problem(f"IPA source contains a link or special file: {name}.")

    payload = root / "Payload"
    if not stat.S_ISDIR(payload.lstat().st_mode):
        raise Problem("IPA source is missing its Payload directory.")
    paths.append(("Payload", payload, True, 0))
    scan(payload, "Payload")
    names = {name for name, _, directory, _ in paths if not directory}
    if not executable_paths <= names:
        raise Problem("Executable path set names a missing file.")
    if sum(size for _, _, _, size in paths) > _MAX_TOTAL:
        raise Problem("IPA expands beyond the 8 GiB safety limit.")
    # Write ZIP32 directly: zipfile's conservative 2 GiB ZIP64 threshold
    # rejects legal ZIP32 archives that the reader and original tool support.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    if len(paths) >= 65535:
        raise Problem("Too many IPA ZIP entries for ZIP32.")
    central = bytearray()
    with os.fdopen(os.open(output, flags, 0o600), "wb") as stream:
        for name, source, directory, expected_size in paths:
            encoded = (name + "/" if directory else name).encode("utf-8")
            if len(encoded) > 1024:
                raise Problem(f"IPA source path is too long: {name}.")
            method = 0 if directory else 8
            local = stream.tell()
            if local >= 0xffffffff:
                raise Problem("IPA output exceeds the ZIP32 offset limit.")
            # UTF-8 names; sizes are patched after streaming into a seekable file.
            stream.write(struct.pack("<I5H3I2H", 0x04034b50, 20, 0x800, method, 0, 33,
                                     0, 0, 0, len(encoded), 0))
            stream.write(encoded)
            start = stream.tell()
            checksum = expanded = 0
            if not directory:
                compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
                fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
                with os.fdopen(fd, "rb") as input_file:
                    current = os.fstat(input_file.fileno())
                    if not stat.S_ISREG(current.st_mode) or current.st_size != expected_size:
                        raise Problem(f"IPA source changed while archiving: {name}.")
                    while True:
                        chunk = input_file.read(_CHUNK)
                        if not chunk:
                            break
                        expanded += len(chunk)
                        if expanded > expected_size:
                            raise Problem(f"IPA source grew while archiving: {name}.")
                        checksum = zlib.crc32(chunk, checksum)
                        stream.write(compressor.compress(chunk))
                    stream.write(compressor.flush())
                if expanded != expected_size:
                    raise Problem(f"IPA source shrank while archiving: {name}.")
            end = stream.tell()
            compressed = end - start
            if compressed >= 0xffffffff or expanded >= 0xffffffff:
                raise Problem("IPA output requires unsupported ZIP64 sizes.")
            stream.seek(local + 14)
            stream.write(struct.pack("<3I", checksum, compressed, expanded))
            stream.seek(end)
            mode = stat.S_IFDIR | 0o755 if directory else stat.S_IFREG | (0o755 if name in executable_paths else 0o644)
            attrs = mode << 16 | (0x10 if directory else 0)
            central.extend(struct.pack("<I6H3I5H2I", 0x02014b50, 3 << 8 | 20, 20, 0x800, method, 0, 33,
                                       checksum, compressed, expanded, len(encoded), 0, 0, 0, 0, attrs, local))
            central.extend(encoded)
            if len(central) > _MAX_CENTRAL:
                raise Problem("IPA output central directory exceeds the safety limit.")
        central_offset = stream.tell()
        if central_offset >= 0xffffffff:
            raise Problem("IPA output requires unsupported ZIP64 offsets.")
        stream.write(central)
        stream.write(struct.pack("<I4H2IH", 0x06054b50, 0, 0, len(paths), len(paths), len(central), central_offset, 0))
