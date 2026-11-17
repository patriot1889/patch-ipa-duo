#!/usr/bin/env python3
"""SQ-specific chained-import redirect and multicast-entitlement removal.

The generic patcher invokes this adapter-owned transform with a JSON request.
All edits are in place within existing allocations; final device signing is
still required because code pages and CMS signature hashes are stale.
"""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import struct
import sys
import tempfile

ORIGINAL_SYMBOL = b"_sendmsg"
REPLACEMENT_SYMBOL = b"_sq_find"
ORIGINAL_LIBRARY = "/usr/lib/libSystem.B.dylib"
DISCOVERY_LIBRARY = "@executable_path/Frameworks/SQFind.dylib"
MULTICAST = "com.apple.developer.networking.multicast"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def u32(data, offset):
    require(0 <= offset <= len(data) - 4, "Truncated integer")
    return struct.unpack_from("<I", data, offset)[0]


def be32(data, offset):
    require(0 <= offset <= len(data) - 4, "Truncated signature integer")
    return struct.unpack_from(">I", data, offset)[0]


def slices(data):
    require(len(data) >= 4, "Truncated Mach-O")
    magic = bytes(data[:4])
    if magic == b"\xcf\xfa\xed\xfe":
        return [(0, len(data))]
    require(magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"), "Unsupported Mach-O magic")
    endian = ">" if magic[:2] == b"\xca\xfe" else "<"
    fat64 = magic in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
    count = struct.unpack_from(endian + "I", data, 4)[0]
    require(1 <= count <= 16, "Invalid fat architecture count")
    width = 32 if fat64 else 20
    require(8 + count * width <= len(data), "Truncated fat table")
    result = []
    previous_end = 8 + count * width
    for index in range(count):
        offset, size = struct.unpack_from(endian + ("QQ" if fat64 else "II"), data, 8 + index * width + 8)
        require(size >= 32 and offset >= 8 + count * width and offset + size <= len(data), "Invalid fat slice bounds")
        result.append((offset, size))
    for offset, size in sorted(result):
        require(offset >= previous_end, "Overlapping fat slices")
        previous_end = offset + size
    return result


def commands(data):
    require(len(data) >= 32 and u32(data, 0) == 0xFEEDFACF and u32(data, 12) == 2, "Expected 64-bit executable")
    require(u32(data, 4) == 0x0100000C and (u32(data, 8) & 0xFFFFFF) in (0, 2), "Expected arm64/arm64e")
    count, size = u32(data, 16), u32(data, 20)
    require(0 < count <= 8192 and size <= len(data) - 32, "Invalid load-command table")
    cursor = 32
    result = []
    for _ in range(count):
        kind, length = u32(data, cursor), u32(data, cursor + 4)
        require(length >= 8 and length % 8 == 0 and cursor + length <= 32 + size, "Invalid load command")
        if kind in (0x21, 0x2C):
            require(length >= 20 and u32(data, cursor + 16) == 0, "Encrypted executable")
        result.append((kind, cursor, length))
        cursor += length
    require(cursor == 32 + size, "Load-command table size mismatch")
    return result


def cstring(data, start, end):
    require(0 <= start < end <= len(data), "Invalid string bounds")
    terminator = data.find(b"\0", start, end)
    require(terminator >= 0, "Unterminated string")
    return bytes(data[start:terminator])


def redirect_import(data, load_commands):
    libraries = []
    fixups = []
    for kind, offset, length in load_commands:
        if kind in (0xC, 0x80000018, 0x18, 0x8000001F, 0x80000023, 0x20):
            require(length >= 24, "Truncated dylib load command")
            name = u32(data, offset + 8)
            require(24 <= name < length, "Invalid dylib name offset")
            libraries.append(cstring(data, offset + name, offset + length).decode("utf-8"))
        if kind == 0x80000034:
            require(length == 16, "Invalid chained-fixups command")
            fixups.append((u32(data, offset + 8), u32(data, offset + 12)))
    require(libraries.count(DISCOVERY_LIBRARY) == 1 and libraries.count(ORIGINAL_LIBRARY) == 1, "Expected original system library and injected discovery library")
    require(len(fixups) == 1, "Expected exactly one chained-fixups payload")
    base, size = fixups[0]
    require(size >= 28 and base + size <= len(data), "Invalid chained-fixups bounds")
    header = struct.unpack_from("<7I", data, base)
    version, starts, imports, symbols, count, format_, symbol_format = header
    require(version == 0 and symbol_format == 0, "Unsupported chained-fixups version or compressed symbols")
    width = {1: 4, 2: 8, 3: 16}.get(format_)
    require(width is not None and 0 < count <= 1000000, "Unsupported chained imports format/count")
    require(28 <= starts <= imports and imports + count * width <= symbols < size, "Invalid chained imports/symbol bounds")
    source_ordinal = libraries.index(ORIGINAL_LIBRARY) + 1
    target_ordinal = libraries.index(DISCOVERY_LIBRARY) + 1
    require(target_ordinal < (32768 if format_ == 3 else 128), "Discovery library ordinal is not representable")
    records = []
    for index in range(count):
        offset = base + imports + index * width
        if format_ == 3:
            word = struct.unpack_from("<Q", data, offset)[0]
            name_offset, ordinal = word >> 32, word & 0xFFFF
            require((word >> 17) & 0x7FFF == 0, "Invalid reserved chained import bits")
        else:
            word = u32(data, offset)
            name_offset, ordinal = word >> 9, word & 255
        name_start = base + symbols + name_offset
        name = cstring(data, name_start, base + size)
        records.append((offset, word, name_start, name, ordinal))
    selected = [record for record in records if record[3] == ORIGINAL_SYMBOL]
    require(len(selected) == 1 and selected[0][4] == source_ordinal, "Expected one original sendmsg import from libSystem")
    offset, word, name_start, name, _ = selected[0]
    require(sum(record[2] == name_start for record in records) == 1, "sendmsg symbol storage is shared")
    require(all(record[0] == offset or record[2] + len(record[3]) + 1 <= name_start or record[2] >= name_start + len(name) + 1 for record in records), "sendmsg symbol overlaps another import name")
    require(not any(record[3] == REPLACEMENT_SYMBOL for record in records), "Discovery import was already redirected")
    require(len(ORIGINAL_SYMBOL) == len(REPLACEMENT_SYMBOL), "Replacement must fit existing symbol allocation")
    if format_ == 3:
        struct.pack_into("<Q", data, offset, (word & ~0xFFFF) | target_ordinal)
    else:
        struct.pack_into("<I", data, offset, (word & ~255) | target_ordinal)
    data[name_start:name_start + len(name)] = REPLACEMENT_SYMBOL
    return [(offset, 8 if format_ == 3 else 4), (name_start, len(name))]


def der_tlv(data, offset=0):
    require(offset + 2 <= len(data), "Truncated DER entitlement")
    tag, first = data[offset:offset + 2]
    require(tag & 31 != 31, "Unsupported DER tag")
    cursor = offset + 2
    if first & 128:
        width = first & 127
        require(1 <= width <= 4 and cursor + width <= len(data), "Invalid DER length")
        require(data[cursor] != 0, "Noncanonical DER length")
        length = int.from_bytes(data[cursor:cursor + width], "big")
        require(length >= 128, "Noncanonical DER long length")
        cursor += width
    else:
        length = first
    require(cursor + length <= len(data), "DER value exceeds its allocation")
    return tag, cursor, cursor + length


def der_encode(tag, payload):
    length = len(payload)
    if length < 128:
        header = bytes([length])
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([128 | len(encoded)]) + encoded
    return bytes([tag]) + header + payload


def strip_der(payload, expected_present):
    tag, start, end = der_tlv(payload)
    require(tag == 0x70 and end == len(payload), "Unsupported DER entitlement root")
    version_tag, version_start, version_end = der_tlv(payload, start)
    require(version_tag == 2 and payload[version_start:version_end] == b"\1", "Unsupported DER entitlement version")
    tag, entries_start, entries_end = der_tlv(payload, version_end)
    require(tag == 0xB0 and entries_end == end, "Unsupported DER entitlement dictionary")
    cursor = entries_start
    kept = bytearray()
    names = set()
    found = False
    while cursor < entries_end:
        entry = cursor
        tag, content, entry_end = der_tlv(payload, cursor)
        require(tag == 0x30 and entry_end <= entries_end, "Invalid DER dictionary entry")
        key_tag, key_start, key_end = der_tlv(payload, content)
        require(key_tag == 0x0C and key_end < entry_end, "Invalid DER entitlement key")
        key = payload[key_start:key_end].decode("utf-8")
        require(key not in names, "Duplicate DER entitlement key")
        names.add(key)
        _, _, value_end = der_tlv(payload, key_end)
        require(value_end == entry_end, "Invalid DER entitlement value")
        if key == MULTICAST:
            found = True
        else:
            kept.extend(payload[entry:entry_end])
        cursor = entry_end
    require(found == expected_present, "XML/DER multicast entitlement presence disagrees")
    return der_encode(0x70, payload[start:version_end] + der_encode(0xB0, kept))


def strip_entitlements(data, load_commands):
    signatures = [(u32(data, offset + 8), u32(data, offset + 12)) for kind, offset, length in load_commands if kind == 0x1D and length == 16]
    require(len(signatures) == 1, "Expected one existing code-signature allocation")
    offset, capacity = signatures[0]
    require(capacity >= 12 and offset + capacity <= len(data), "Invalid code-signature allocation")
    signature = data[offset:offset + capacity]
    require(be32(signature, 0) == 0xFADE0CC0, "Expected embedded code-signature superblob")
    length, count = be32(signature, 4), be32(signature, 8)
    require(0 < count <= 64 and 12 + count * 8 <= length <= capacity, "Invalid signature index")
    blobs = []
    slots = set()
    ranges = []
    for index in range(count):
        slot, start = struct.unpack_from(">II", signature, 12 + index * 8)
        require(slot not in slots and 12 + count * 8 <= start <= length - 8, "Invalid or duplicate signature slot")
        slots.add(slot)
        blob_length = be32(signature, start + 4)
        require(8 <= blob_length <= length - start, "Invalid signature blob bounds")
        ranges.append((start, start + blob_length))
        blobs.append((slot, bytearray(signature[start:start + blob_length])))
    previous = 12 + count * 8
    for start, end in sorted(ranges):
        require(start >= previous, "Overlapping signature blobs")
        previous = end
    by_slot = dict(blobs)
    require(0 in by_slot and 5 in by_slot, "Signature lacks code directory or XML entitlements")
    xml = by_slot[5]
    require(be32(xml, 0) == 0xFADE7171, "Unsupported XML entitlements blob")
    entitlements = plistlib.loads(bytes(xml[8:]))
    require(isinstance(entitlements, dict), "Entitlements must be a dictionary")
    present = MULTICAST in entitlements
    entitlements.pop(MULTICAST, None)
    payload = plistlib.dumps(entitlements, fmt=plistlib.FMT_XML, sort_keys=True)
    by_slot[5] = bytearray(struct.pack(">II", 0xFADE7171, len(payload) + 8) + payload)
    if 7 in by_slot:
        blob = by_slot[7]
        require(be32(blob, 0) == 0xFADE7172, "Unsupported DER entitlements blob")
        payload = strip_der(bytes(blob[8:]), present)
        by_slot[7] = bytearray(struct.pack(">II", 0xFADE7172, len(payload) + 8) + payload)
    # Refresh entitlement special-slot digests in every code-directory hash
    # variant. Code-page hashes/CMS remain stale until the separate signing step.
    for slot, _ in blobs:
        directory = by_slot[slot]
        if be32(directory, 0) != 0xFADE0C02:
            continue
        require(len(directory) >= 44, "Truncated code directory")
        hash_offset, special, code_slots = be32(directory, 16), be32(directory, 24), be32(directory, 28)
        hash_size, hash_type = directory[36:38]
        algorithm = {1: (hashlib.sha1, 20), 2: (hashlib.sha256, 32), 3: (hashlib.sha256, 20), 4: (hashlib.sha384, 48)}.get(hash_type)
        require(algorithm is not None and algorithm[1] == hash_size, "Unsupported code-directory hash")
        require(special >= (7 if 7 in by_slot else 5) and special * hash_size <= hash_offset and hash_offset + code_slots * hash_size <= len(directory), "Invalid code-directory hash table")
        for entitlement_slot in (5, 7):
            if entitlement_slot not in by_slot:
                continue
            digest = algorithm[0](by_slot[entitlement_slot]).digest()[:hash_size]
            start = hash_offset - entitlement_slot * hash_size
            directory[start:start + hash_size] = digest
    rebuilt = bytearray(12 + count * 8)
    for index, (slot, _) in enumerate(blobs):
        rebuilt.extend(b"\0" * (-len(rebuilt) % 8))
        struct.pack_into(">II", rebuilt, 12 + index * 8, slot, len(rebuilt))
        rebuilt.extend(by_slot[slot])
    require(len(rebuilt) <= capacity, "Updated entitlements do not fit the original signature allocation")
    struct.pack_into(">III", rebuilt, 0, 0xFADE0CC0, len(rebuilt), count)
    rebuilt.extend(b"\0" * (capacity - len(rebuilt)))
    data[offset:offset + capacity] = rebuilt
    return (offset, capacity)


def transform(data):
    result = bytearray(data)
    for offset, size in slices(result):
        slice_ = bytearray(result[offset:offset + size])
        load_commands = commands(slice_)
        redirect_import(slice_, load_commands)
        strip_entitlements(slice_, load_commands)
        require(len(slice_) == size, "Executable slice size changed")
        result[offset:offset + size] = slice_
    return result


def main():
    require(len(sys.argv) == 2, "Expected adapter transform request JSON")
    request = json.loads(Path(sys.argv[1]).read_text())
    require(request.get("schemaVersion") == 1 and DISCOVERY_LIBRARY in request.get("injectedLibraries", []), "Missing discovery-library injection request")
    path = Path(request["executable"])
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode), "Expected regular staged executable")
    data = transform(path.read_bytes())
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
            temporary = output.name
            output.write(data)
            os.fchmod(output.fileno(), stat.S_IMODE(info.st_mode))
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary:
            os.unlink(temporary)
    print("SQ Find broadcast redirected to bounded IPv4 unicast; multicast entitlement removed from XML and DER metadata. Separate signing required.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, struct.error, plistlib.InvalidFileException) as error:
        print("SQ adapter: " + str(error), file=sys.stderr)
        sys.exit(1)
