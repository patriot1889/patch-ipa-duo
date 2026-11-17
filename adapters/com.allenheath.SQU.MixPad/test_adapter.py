#!/usr/bin/env python3
"""Build and statically verify this adapter against a supplied decrypted IPA."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

PACKAGE = Path(__file__).resolve().parent
IDENTIFIER = PACKAGE.name


def run(*args, succeeds=True):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True)
    if succeeds and result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    if not succeeds:
        assert result.returncode != 0, "Expected failure: " + " ".join(map(str, args))
    return result


def files(path):
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None
        return {item.filename: archive.read(item) for item in archive.infolist() if not item.is_dir()}


def macho(data):
    # The supported production build is thin arm64; generic tests cover fat/arm64e.
    assert struct.unpack_from("<I", data)[0] == 0xFEEDFACF
    count, size = struct.unpack_from("<II", data, 16)
    cursor = 32
    sdk = minimum = sdk_offset = None
    libraries = []
    fixups = signature = None
    for _ in range(count):
        kind, length = struct.unpack_from("<II", data, cursor)
        if kind == 0x32:
            minimum, sdk = struct.unpack_from("<II", data, cursor + 12)
            sdk_offset = cursor + 16
        if kind == 0xC:
            name = cursor + struct.unpack_from("<I", data, cursor + 8)[0]
            libraries.append(data[name:data.index(b"\0", name)].decode())
        if kind == 0x80000034:
            fixups = struct.unpack_from("<II", data, cursor + 8)
        if kind == 0x1D:
            signature = struct.unpack_from("<II", data, cursor + 8)
        cursor += length
    assert cursor == 32 + size and sdk is not None
    return dict(end=cursor, count=count, sdk=sdk, minimum=minimum,
                sdk_offset=sdk_offset, libraries=libraries, fixups=fixups, signature=signature)


def import_record(data, metadata, symbol):
    base, size = metadata["fixups"]
    _, _, imports, symbols, count, format_, _ = struct.unpack_from("<7I", data, base)
    assert format_ == 1  # The supported production build uses this import format.
    matches = []
    for index in range(count):
        offset = base + imports + 4 * index
        word = struct.unpack_from("<I", data, offset)[0]
        name = base + symbols + (word >> 9)
        end = data.index(b"\0", name, base + size)
        if data[name:end] == symbol:
            matches.append((offset, name, word))
    assert len(matches) == 1
    return matches[0]


def signature_blobs(data, metadata):
    base, capacity = metadata["signature"]
    magic, length, count = struct.unpack_from(">III", data, base)
    assert magic == 0xFADE0CC0 and length <= capacity
    result = {}
    for index in range(count):
        slot, offset = struct.unpack_from(">II", data, base + 12 + index * 8)
        length = struct.unpack_from(">I", data, base + offset + 4)[0]
        result[slot] = data[base + offset:base + offset + length]
    return result


def mutated_archive(source, output, replacements):
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(output, "w") as destination:
        for item in original.infolist():
            destination.writestr(item, replacements.get(item.filename, original.read(item)))


def verify_output(input_files, output, manifest, expected_sdk, bars, identifier):
    result = files(output)
    info_path = next(name for name in input_files if name.count("/") == 2 and name.endswith(".app/Info.plist"))
    info = plistlib.loads(input_files[info_path])
    updated = plistlib.loads(result[info_path])
    app = info_path.rsplit("/", 1)[0]
    executable = app + "/" + info["CFBundleExecutable"]
    assert updated["CFBundleIdentifier"] == identifier
    assert updated["UIDeviceFamily"] == [1, 2]
    assert "UIRequiresFullScreen" not in updated
    assert updated["UIApplicationSceneManifest"] == manifest["operations"]["setPlist"]["UIApplicationSceneManifest"]
    assert updated["DTSDKName"] == "iphoneos" + expected_sdk
    assert updated["DTPlatformVersion"] == expected_sdk
    changed_keys = {"UIApplicationSceneManifest", "UIDeviceFamily", "UIRequiresFullScreen", "DTSDKName", "DTPlatformVersion"}
    assert {k: v for k, v in info.items() if k not in changed_keys} == {k: v for k, v in updated.items() if k not in changed_keys}
    added = {app + "/Frameworks/" + library["fileName"] for library in manifest["operations"]["libraries"]}
    if bars:
        added.add(app + "/Frameworks/IPAPatcherBars.dylib")
    assert set(result) == (set(input_files) - {"iTunesArtwork"}) | added
    for name in set(input_files) & set(result) - {info_path, executable}:
        assert result[name] == input_files[name], "Unexpected resource change: " + name
    before, after = macho(input_files[executable]), macho(result[executable])
    assert after["minimum"] == before["minimum"]
    assert after["sdk"] == (27 << 16) | ((1 if expected_sdk == "27.1" else 0) << 8)
    assert after["libraries"][:len(before["libraries"])] == before["libraries"]
    expected_loads = {"@executable_path/Frameworks/" + Path(name).name for name in added}
    assert set(after["libraries"][len(before["libraries"]):]) == expected_loads
    restored = bytearray(result[executable])
    original = input_files[executable]
    old_import, old_symbol, old_word = import_record(original, before, b"_sendmsg")
    new_import, new_symbol, new_word = import_record(result[executable], after, b"_sq_find")
    assert (old_import, old_symbol) == (new_import, new_symbol)
    assert new_word >> 8 == old_word >> 8
    assert after["libraries"][(new_word & 255) - 1] == "@executable_path/Frameworks/SQFind.dylib"
    restored[new_import:new_import + 4] = original[old_import:old_import + 4]
    restored[new_symbol:new_symbol + 8] = original[old_symbol:old_symbol + 8]
    old_blobs = signature_blobs(original, before)
    new_blobs = signature_blobs(result[executable], after)
    multicast = "com.apple.developer.networking.multicast"
    old_entitlements = plistlib.loads(old_blobs[5][8:])
    new_entitlements = plistlib.loads(new_blobs[5][8:])
    assert multicast not in new_entitlements
    assert new_entitlements == {key: value for key, value in old_entitlements.items() if key != multicast}
    assert multicast.encode() not in new_blobs[7]
    assert set(old_blobs) == set(new_blobs)
    for slot, old_blob in old_blobs.items():
        if slot in (5, 7):
            continue
        if struct.unpack_from(">I", old_blob)[0] == 0xFADE0C02:
            new_blob = bytearray(new_blobs[slot])
            offset = struct.unpack_from(">I", old_blob, 16)[0]
            width, type_ = old_blob[36:38]
            digest = {1: hashlib.sha1, 2: hashlib.sha256}[type_]
            for special in (5, 7):
                start = offset - special * width
                assert new_blob[start:start + width] == digest(new_blobs[special]).digest()
                new_blob[start:start + width] = old_blob[start:start + width]
            assert new_blob == old_blob, "Code directory changed outside entitlement digests"
        else:
            assert new_blobs[slot] == old_blob, "Unrelated signature metadata changed"
    assert before["signature"] == after["signature"]
    start, capacity = after["signature"]
    restored[start:start + capacity] = original[start:start + capacity]
    restored[16:24] = original[16:24]
    restored[before["sdk_offset"]:before["sdk_offset"] + 4] = original[before["sdk_offset"]:before["sdk_offset"] + 4]
    restored[before["end"]:after["end"]] = original[before["end"]:after["end"]]
    assert restored == original, "Original code/data changed outside SDK, load commands, targeted import and signing metadata"
    for name in added:
        assert struct.unpack_from("<I", result[name], 12)[0] == 6, "Expected a dylib"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipa", type=Path)
    parser.add_argument("--patcher", type=Path, default=PACKAGE.parent.parent / "patch-ipa-duo")
    parser.add_argument("--keep-output", type=Path, help="Retain test artifacts in a new directory")
    args = parser.parse_args()
    ipa = args.ipa.resolve()
    input_hash = hashlib.sha256(ipa.read_bytes()).digest()
    input_files = files(ipa)
    manifest = json.loads((PACKAGE / "adapter.json").read_text())
    with tempfile.TemporaryDirectory(prefix="mixpad-adapter-tests-") as temporary:
        root = Path(temporary)
        if args.patcher.suffix == ".swift":
            patcher_path = root / "patch-ipa-duo"
            run("/usr/bin/xcrun", "swiftc", args.patcher.resolve(), "-o", patcher_path)
            shutil.copytree(PACKAGE, root / "adapters" / IDENTIFIER)
            patcher = [patcher_path]
        else:
            patcher = [sys.executable, args.patcher.resolve()]
        inspected = run(*patcher, "inspect", ipa).stdout
        assert "automatic from bundle identifier" in inspected and "patch supported" in inspected
        modes = [("top", []), ("side", ["--bars", "side"]), ("reserved-side", ["--display", "reserved-side"])]
        for mode, options in modes:
            output = root / (mode + ".ipa")
            patched = run(*patcher, "patch", ipa, "--output", output, *options)
            expected = "27.0" if mode == "reserved-side" else "27.1"
            verify_output(input_files, output, manifest, expected, mode != "reserved-side", IDENTIFIER)
            assert "bars=" + ("system" if mode == "reserved-side" else mode) in patched.stdout
            existing = output.read_bytes()
            run(*patcher, "patch", ipa, "--output", output, *options, succeeds=False)
            assert output.read_bytes() == existing
        info_path = next(name for name in input_files if name.count("/") == 2 and name.endswith(".app/Info.plist"))
        info = plistlib.loads(input_files[info_path])
        executable = info_path.rsplit("/", 1)[0] + "/" + info["CFBundleExecutable"]
        unsupported = dict(info, CFBundleVersion="unsupported-test-build")
        wrong_build = root / "wrong-build.ipa"
        mutated_archive(ipa, wrong_build, {info_path: plistlib.dumps(unsupported)})
        failed = root / "failed.ipa"
        response = run(*patcher, "patch", wrong_build, "--output", failed, succeeds=False)
        assert "does not support this app version/build" in response.stderr and not failed.exists()
        missing_class = root / "missing-class.ipa"
        mutated_archive(ipa, missing_class, {executable: input_files[executable].replace(b"QUIWindow\0", b"XUIWindow\0")})
        response = run(*patcher, "patch", missing_class, "--output", failed, succeeds=False)
        assert "required string QUIWindow is missing" in response.stderr and not failed.exists()
        missing_import = root / "missing-import.ipa"
        mutated_archive(ipa, missing_import, {executable: input_files[executable].replace(b"_sendmsg\0", b"_unknown\0")})
        response = run(*patcher, "patch", missing_import, "--output", failed, succeeds=False)
        assert "Expected one original sendmsg import" in response.stderr and not failed.exists()
        malformed_der = bytearray(input_files[executable])
        signature_base, _ = macho(malformed_der)["signature"]
        signature_count = struct.unpack_from(">I", malformed_der, signature_base + 8)[0]
        for index in range(signature_count):
            slot, offset = struct.unpack_from(">II", malformed_der, signature_base + 12 + index * 8)
            if slot == 7:
                malformed_der[signature_base + offset + 8] = 0x71
        bad_entitlements = root / "malformed-entitlements.ipa"
        mutated_archive(ipa, bad_entitlements, {executable: malformed_der})
        response = run(*patcher, "patch", bad_entitlements, "--output", failed, succeeds=False)
        assert "Unsupported DER entitlement root" in response.stderr and not failed.exists()
        renamed_info = dict(info, CFBundleIdentifier="com.example.renamed")
        renamed = root / "renamed.ipa"
        mutated_archive(ipa, renamed, {info_path: plistlib.dumps(renamed_info)})
        forced = root / "forced.ipa"
        run(*patcher, "patch", renamed, "--output", forced, "--adapter", IDENTIFIER)
        verify_output(files(renamed), forced, manifest, "27.1", True, "com.example.renamed")
        response = run(*patcher, "patch", ipa, "--output", failed, "--display", "reserved-side", "--bars", "top", succeeds=False)
        assert "requires --display full" in response.stderr and not failed.exists()
        assert hashlib.sha256(ipa.read_bytes()).digest() == input_hash
        if args.keep_output:
            shutil.copytree(root, args.keep_output)
    print("SQ MixPad adapter tests passed: top, side, reserved-side, forced selection, byte preservation, and safe failure paths.")


if __name__ == "__main__":
    main()
