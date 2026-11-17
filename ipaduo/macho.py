"""Strict, device-only Mach-O inspection and in-place patching.

Offsets in the public records are absolute file offsets.  All integers in Mach-O
headers and load commands are little endian; universal headers support both
endian orders and both 32 and 64 bit architecture tables.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct

from .errors import Problem


ARM64 = 0x0100000C
FAT_MAGICS = {0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA}
DYLIB_COMMANDS = {0xC, 0x18, 0x80000018, 0x8000001F, 0x80000023}


@dataclass(frozen=True)
class Slice:
    offset: int
    size: int


@dataclass(frozen=True)
class SDKRecord:
    offset: int
    sdk: int
    minimum: int


@dataclass(frozen=True)
class Injection:
    header: int
    offset: int
    count: int
    size: int


@dataclass(frozen=True)
class _ParsedSlice:
    region: Slice
    architecture: str
    cpu: int
    subtype: int
    count: int
    commands: bytes


def _u32(data: bytes, offset: int, endian: str = "<") -> int:
    return struct.unpack_from(endian + "I", data, offset)[0]


def _u64(data: bytes, offset: int, endian: str = "<") -> int:
    return struct.unpack_from(endian + "Q", data, offset)[0]


def _read(handle, offset: int, count: int, total: int) -> bytes:
    if offset < 0 or count < 0 or offset > total or count > total - offset:
        raise Problem("Mach-O read is outside the file.")
    handle.seek(offset)
    data = handle.read(count)
    if len(data) != count:
        raise Problem("Truncated Mach-O file.")
    return data


def _table(handle, total: int) -> list[tuple[Slice, int | None, int | None]]:
    magic = int.from_bytes(_read(handle, 0, 4, total), "big")
    if magic not in FAT_MAGICS:
        return [(Slice(0, total), None, None)]
    endian = "<" if magic in (0xBEBAFECA, 0xBFBAFECA) else ">"
    fat64 = magic in (0xCAFEBABF, 0xBFBAFECA)
    width = 32 if fat64 else 20
    count = _u32(_read(handle, 4, 4, total), 0, endian)
    if not 1 <= count <= 16:
        raise Problem("Invalid universal Mach-O architecture count.")
    table_end = 8 + count * width
    table = _read(handle, 8, count * width, total)
    regions = []
    for index in range(count):
        base = index * width
        cpu = _u32(table, base, endian)
        subtype = _u32(table, base + 4, endian)
        offset = _u64(table, base + 8, endian) if fat64 else _u32(table, base + 8, endian)
        size = _u64(table, base + 16, endian) if fat64 else _u32(table, base + 12, endian)
        if offset < table_end or offset > total or size > total - offset:
            raise Problem("Universal Mach-O contains an out-of-bounds slice.")
        regions.append((Slice(offset, size), cpu, subtype))
    return regions


def _commands(parsed: _ParsedSlice):
    data = parsed.commands
    offset = 0
    for _ in range(parsed.count):
        # _parse has validated all command lengths and the final table offset.
        kind = _u32(data, offset)
        length = _u32(data, offset + 4)
        yield offset, kind, length
        offset += length


def _parse(path: Path, file_type: int) -> list[_ParsedSlice]:
    try:
        with Path(path).open("rb") as handle:
            handle.seek(0, 2)
            total = handle.tell()
            regions = _table(handle, total)
            parsed = []
            seen = set()
            previous_end = 0
            for region, fat_cpu, fat_subtype in sorted(regions, key=lambda item: item[0].offset):
                if region.offset < previous_end or region.size < 32:
                    raise Problem("Universal Mach-O contains an overlapping or truncated slice.")
                previous_end = region.offset + region.size
                header = _read(handle, region.offset, 32, total)
                cpu = _u32(header, 4)
                subtype = _u32(header, 8)
                if (_u32(header, 0) != 0xFEEDFACF or
                        fat_cpu is not None and fat_cpu != cpu or
                        fat_subtype is not None and fat_subtype != subtype or
                        _u32(header, 12) != file_type):
                    raise Problem("Expected a 64-bit Mach-O executable or dynamic library of the declared type.")
                base_subtype = subtype & 0xFFFFFF
                if cpu != ARM64 or base_subtype not in (0, 2):
                    raise Problem("Mach-O has an unsupported architecture for iOS device.")
                architecture = "arm64e" if base_subtype == 2 else "arm64"
                if architecture in seen:
                    raise Problem("Mach-O contains duplicate architecture slices.")
                seen.add(architecture)
                count, size = _u32(header, 16), _u32(header, 20)
                if count == 0 or count > 8192 or size > min(region.size - 32, 16 * 1024 * 1024):
                    raise Problem("Invalid Mach-O load command table.")
                commands = _read(handle, region.offset + 32, size, total)
                position = 0
                has_platform = False
                for _ in range(count):
                    if size - position < 8:
                        raise Problem("Truncated Mach-O load command.")
                    kind, length = _u32(commands, position), _u32(commands, position + 4)
                    if length < 8 or length > size - position or length % 8:
                        raise Problem("Invalid Mach-O load command size.")
                    if kind == 0x32:
                        if length < 24 or _u32(commands, position + 8) != 2:
                            raise Problem("Mach-O was not built for iOS device.")
                        has_platform = True
                    elif kind == 0x25:
                        if length < 16:
                            raise Problem("Mach-O was not built for iOS device.")
                        has_platform = True
                    elif kind in (0x24, 0x2F, 0x30):
                        raise Problem("Mach-O was not built for iOS device.")
                    elif kind in (0x21, 0x2C):
                        if length < 20 or _u32(commands, position + 16) != 0:
                            raise Problem("Mach-O is encrypted or has invalid encryption metadata.")
                    position += length
                if position != size or not has_platform:
                    raise Problem("Mach-O does not declare the iOS device platform.")
                parsed.append(_ParsedSlice(region, architecture, cpu, subtype, count, commands))
            return parsed
    except OSError as exc:
        raise Problem(f"Cannot read Mach-O file: {exc}") from exc


def architectures(path: Path, file_type: int = 2) -> list[str]:
    return sorted(item.architecture for item in _parse(path, file_type))


def slices(path: Path, file_type: int = 2) -> list[Slice]:
    """Return validated slice regions in file order."""
    return [item.region for item in _parse(path, file_type)]


def sdk_records(path: Path, file_type: int = 2) -> list[SDKRecord]:
    records = []
    for item in _parse(path, file_type):
        found = []
        for offset, kind, _ in _commands(item):
            if kind in (0x32, 0x25):
                field = offset + (16 if kind == 0x32 else 12)
                found.append(SDKRecord(item.region.offset + 32 + field,
                                       _u32(item.commands, field), _u32(item.commands, field - 4)))
        if len(found) != 1:
            raise Problem("Each executable slice must declare exactly one SDK version.")
        records.extend(found)
    return records


def version(value: int) -> str:
    major, minor, patch = value >> 16, (value >> 8) & 255, value & 255
    return f"{major}.{minor}" if patch == 0 else f"{major}.{minor}.{patch}"


def _library_bytes(libraries: list[str]) -> bytes:
    if not libraries or len(set(libraries)) != len(libraries):
        raise Problem("Injection requires unique library paths.")
    result = bytearray()
    for library in libraries:
        if not library or "\x00" in library:
            raise Problem("Invalid injected library path.")
        name = library.encode("utf-8") + b"\x00"
        size = (24 + len(name) + 7) & ~7
        if size > 0xFFFFFFFF:
            raise Problem("Injected library path is too long.")
        result.extend(struct.pack("<6I", 0xC, size, 24, 0, 0x10000, 0x10000))
        result.extend(name)
        result.extend(b"\x00" * (size - 24 - len(name)))
    return bytes(result)


def injection_plan(path: Path, libraries: list[str]) -> list[Injection]:
    load = _library_bytes(libraries)
    plan = []
    try:
        with Path(path).open("rb") as handle:
            handle.seek(0, 2)
            total = handle.tell()
            for item in _parse(path, 2):
                region = item.region
                commands = item.commands
                boundary = region.size
                has_sections = False
                for offset, kind, length in _commands(item):
                    if kind in DYLIB_COMMANDS:
                        if length < 24:
                            raise Problem("Malformed dylib load command.")
                        name_offset = _u32(commands, offset + 8)
                        if name_offset < 24 or name_offset >= length:
                            raise Problem("Invalid dylib load-command name.")
                        name = commands[offset + name_offset:offset + length].split(b"\x00", 1)
                        if len(name) != 2:
                            raise Problem("Unterminated dylib load-command name.")
                        if name[0].decode("utf-8", errors="replace") in libraries:
                            raise Problem("A requested library is already injected. Use the original IPA to patch again.")
                    if kind == 0x19:
                        if length < 72:
                            raise Problem("Truncated segment command.")
                        file_offset, file_size = _u64(commands, offset + 40), _u64(commands, offset + 48)
                        if file_offset > region.size or file_size > region.size - file_offset:
                            raise Problem("Segment points outside its Mach-O slice.")
                        if file_offset > 0 and file_size > 0:
                            boundary = min(boundary, file_offset)
                        section_count = _u32(commands, offset + 64)
                        if section_count > (length - 72) // 80:
                            raise Problem("Invalid segment section table.")
                        for index in range(section_count):
                            section = offset + 72 + index * 80
                            section_type = _u32(commands, section + 64) & 255
                            section_size = _u64(commands, section + 40)
                            section_offset = _u32(commands, section + 48)
                            if section_size and section_type not in (1, 12, 18):
                                if section_offset > region.size or section_size > region.size - section_offset:
                                    raise Problem("Section points outside its Mach-O slice.")
                                has_sections = True
                                boundary = min(boundary, section_offset)
                end = 32 + len(commands)
                if (not has_sections or boundary < end or len(load) > boundary - end or
                        any(_read(handle, region.offset + end, len(load), total))):
                    raise Problem("Insufficient Mach-O load-command space for injected libraries; zeroed header padding before a file-backed section is required.")
                plan.append(Injection(region.offset, region.offset + end, item.count, len(commands)))
    except OSError as exc:
        raise Problem(f"Cannot read Mach-O file: {exc}") from exc
    return plan


def inject(path: Path, plan: list[Injection], libraries: list[str]) -> None:
    load = _library_bytes(libraries)
    if plan != injection_plan(path, libraries):
        raise Problem("Mach-O injection plan no longer matches the executable.")
    try:
        with Path(path).open("r+b") as handle:
            for item in plan:
                if item.count + len(libraries) > 0xFFFFFFFF or item.size + len(load) > 0xFFFFFFFF:
                    raise Problem("Injected Mach-O load command table is too large.")
                handle.seek(item.offset)
                handle.write(load)
                handle.seek(item.header + 16)
                handle.write(struct.pack("<2I", item.count + len(libraries), item.size + len(load)))
    except OSError as exc:
        raise Problem(f"Cannot inject Mach-O library: {exc}") from exc


def patch_sdk(path: Path, sdk: int) -> None:
    if not isinstance(sdk, int) or not 0 <= sdk <= 0xFFFFFFFF:
        raise Problem("Invalid Mach-O SDK version.")
    records = sdk_records(path)
    try:
        with Path(path).open("r+b") as handle:
            for record in records:
                handle.seek(record.offset)
                handle.write(struct.pack("<I", sdk))
    except OSError as exc:
        raise Problem(f"Cannot update Mach-O SDK version: {exc}") from exc


def _dylib_id(path: Path) -> str:
    result = []
    for item in _parse(path, 6):
        names = []
        for offset, kind, length in _commands(item):
            if kind == 0xD:
                if length < 24:
                    raise Problem("Malformed dylib install-name command.")
                name_offset = _u32(item.commands, offset + 8)
                if name_offset < 24 or name_offset >= length:
                    raise Problem("Invalid dylib install name.")
                name = item.commands[offset + name_offset:offset + length].split(b"\x00", 1)
                if len(name) != 2:
                    raise Problem("Unterminated dylib install name.")
                try:
                    names.append(name[0].decode("utf-8", errors="strict"))
                except UnicodeError as exc:
                    raise Problem("Invalid UTF-8 dylib install name.") from exc
        if len(names) != 1:
            raise Problem("Each dylib slice must declare exactly one install name.")
        result.append(names[0])
    if len(set(result)) != 1:
        raise Problem("Dylib slices declare different install names.")
    return result[0]


def validate_dylib(path: Path, executable: Path, install_name: str) -> None:
    """Validate a ready-to-inject dylib against an executable after SDK patching."""
    if _dylib_id(path) != install_name:
        raise Problem("Injected library install name does not match its requested load path.")
    dylib_arch = architectures(path, file_type=6)
    exe_arch = architectures(executable)
    if dylib_arch != exe_arch:
        raise Problem("Injected-library architectures do not match the executable.")
    dylib_versions = dict(zip((item.architecture for item in _parse(path, 6)), sdk_records(path, file_type=6)))
    exe_versions = dict(zip((item.architecture for item in _parse(executable, 2)), sdk_records(executable)))
    for arch in exe_arch:
        if dylib_versions[arch].minimum > exe_versions[arch].minimum:
            raise Problem("Injected library deployment target exceeds the executable's minimum OS.")


def select_architectures(source: Path, output: Path, wanted: list[str]) -> None:
    """Copy selected dylib slices into a thin or fat Mach-O without external tools."""
    if not wanted or len(set(wanted)) != len(wanted) or any(a not in ("arm64", "arm64e") for a in wanted):
        raise Problem("Requested dylib architectures are invalid or duplicated.")
    parsed = _parse(source, 6)
    available = {item.architecture: item for item in parsed}
    if any(arch not in available for arch in wanted):
        raise Problem("Prebuilt dylib is missing a required architecture.")
    selected = [available[arch] for arch in wanted]
    try:
        with Path(source).open("rb") as src, Path(output).open("xb") as dst:
            if len(selected) == 1:
                src.seek(selected[0].region.offset)
                _copy_exact(src, dst, selected[0].region.size)
            else:
                # 16 KiB alignment matches ordinary arm64 universal binaries.
                offset = 8 + len(selected) * 20
                entries = []
                for item in selected:
                    offset = (offset + 16383) & ~16383
                    if offset > 0xFFFFFFFF or item.region.size > 0xFFFFFFFF:
                        raise Problem("Selected dylib is too large for a universal Mach-O.")
                    entries.append((item.cpu, item.subtype, offset, item.region.size, 14))
                    offset += item.region.size
                dst.write(struct.pack(">2I", 0xCAFEBABE, len(selected)))
                for entry in entries:
                    dst.write(struct.pack(">5I", *entry))
                for item, entry in zip(selected, entries):
                    dst.write(b"\x00" * (entry[2] - dst.tell()))
                    src.seek(item.region.offset)
                    _copy_exact(src, dst, item.region.size)
    except OSError as exc:
        raise Problem(f"Cannot select dylib architectures: {exc}") from exc
    architectures(output, file_type=6)


def _copy_exact(src, dst, count: int) -> None:
    remaining = count
    while remaining:
        chunk = src.read(min(remaining, 1024 * 1024))
        if not chunk:
            raise Problem("Prebuilt dylib was truncated while copying slices.")
        dst.write(chunk)
        remaining -= len(chunk)
