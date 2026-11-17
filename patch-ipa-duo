#!/usr/bin/xcrun swift
import Foundation
import Darwin
import zlib

// Archive validation is adapted from the local signer and kept self-contained.
// This script has no dependency on local-ios-sign.swift or signing credentials.

struct Problem: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { description = message }
}

struct CommandResult {
    let status: Int32
    let stdout: Data
    let stderr: Data
}

func temporaryDirectory(in parent: URL = FileManager.default.temporaryDirectory) throws -> URL {
    var template = Array(parent.appendingPathComponent("patch-ipa-duo.XXXXXXXX").path.utf8CString)
    guard let path = template.withUnsafeMutableBufferPointer({ pointer in
        mkdtemp(pointer.baseAddress!).map { String(cString: $0) }
    }) else { throw Problem("Cannot create a private temporary directory.") }
    return URL(fileURLWithPath: path, isDirectory: true)
}

func command(_ executable: String, _ args: [String], cwd: URL? = nil, input: Data? = nil) throws -> CommandResult {
    let directory = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let errors = directory.appendingPathComponent("stderr")
    try Data().write(to: errors)
    let errorHandle = try FileHandle(forWritingTo: errors)
    defer { try? errorHandle.close() }
    let process = Process()
    let output = Pipe()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = args
    process.currentDirectoryURL = cwd
    let inputPipe = input.map { _ in Pipe() }
    if let inputPipe {
        guard fcntl(inputPipe.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw Problem("Could not configure private input for the subprocess.")
        }
        process.standardInput = inputPipe
    } else {
        process.standardInput = FileHandle.nullDevice
    }
    process.standardOutput = output
    process.standardError = errorHandle
    var environment = ProcessInfo.processInfo.environment
    for key in ["ZIP", "ZIPOPT", "UNZIP", "UNZIPOPT", "ZIPINFO", "ZIPINFOOPT", "TAR_OPTIONS",
                "ASC_ISSUER_ID", "ASC_KEY_ID", "ASC_KEY_PATH"] {
        environment.removeValue(forKey: key)
    }
    if executable == "/usr/bin/curl" {
        for key in ["SSLKEYLOGFILE", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"] {
            environment.removeValue(forKey: key)
        }
    }
    environment["LC_ALL"] = "C"
    process.environment = environment
    try process.run()
    if let input, let inputPipe {
        defer { try? inputPipe.fileHandleForWriting.close() }
        try inputPipe.fileHandleForWriting.write(contentsOf: input)
    }
    let data = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return CommandResult(status: process.terminationStatus, stdout: data, stderr: try Data(contentsOf: errors))
}

func plist(_ data: Data) throws -> [String: Any] {
    guard let value = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
        throw Problem("Expected a property-list dictionary.")
    }
    return value
}

func hasPattern(_ text: String, _ pattern: String) -> Bool {
    text.range(of: pattern, options: .regularExpression) != nil
}

func isBundleID(_ value: String) -> Bool {
    hasPattern(value, #"\A[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\z"#)
}

func visible(_ value: String) -> String {
    value.unicodeScalars.map { CharacterSet.controlCharacters.contains($0) ? "?" : String($0) }.joined()
}

private struct IPABytes {
    let data: Data

    func u16(_ offset: Int) -> Int {
        Int(data[offset]) | Int(data[offset + 1]) << 8
    }

    func u32(_ offset: Int, littleEndian: Bool = true) -> Int {
        if littleEndian { return u16(offset) | u16(offset + 2) << 16 }
        return Int(data[offset]) << 24 | Int(data[offset + 1]) << 16
            | Int(data[offset + 2]) << 8 | Int(data[offset + 3])
    }

    func u64(_ offset: Int, littleEndian: Bool) throws -> Int {
        let high = u32(offset + (littleEndian ? 4 : 0), littleEndian: littleEndian)
        let low = u32(offset + (littleEndian ? 0 : 4), littleEndian: littleEndian)
        guard high <= Int.max >> 32 else { throw Problem("Mach-O offset or size is too large.") }
        return high << 32 | low
    }
}

private final class IPAReader {
    let handle: FileHandle
    let size: Int

    init(_ url: URL) throws {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw Problem("Cannot open regular file \(url.lastPathComponent): \(String(cString: strerror(errno))).") }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG else {
            close(fd)
            throw Problem("Expected a regular file at \(url.lastPathComponent).")
        }
        size = Int(info.st_size)
        handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }

    func read(_ offset: Int, _ count: Int) throws -> IPABytes {
        guard offset >= 0, count >= 0, offset <= size, count <= size - offset else {
            throw Problem("A ZIP or Mach-O record points outside its file.")
        }
        if count == 0 { return IPABytes(data: Data()) }
        try handle.seek(toOffset: UInt64(offset))
        guard let data = try handle.read(upToCount: count), data.count == count else {
            throw Problem("An input file was truncated while reading it.")
        }
        return IPABytes(data: data)
    }
}

private struct IPAEntry {
    let path: String
    let directory: Bool
    let executable: Bool
    let method: Int
    let crc: Int
    let compressed: Int
    let expanded: Int
    let local: Int
    let dataOffset: Int
    let recordEnd: Int
}

private func ipaSafeComponent(_ name: Substring) -> Bool {
    !name.isEmpty && name != "." && name != ".." && !name.contains(":")
        && !name.contains("\\") && name.rangeOfCharacter(from: .controlCharacters) == nil
}

private func ipaCheckZIPExtras(_ bytes: IPABytes, start: Int, count: Int, unixMode: Int? = nil) throws {
    var offset = start
    let end = start + count
    while offset < end {
        guard end - offset >= 4 else { throw Problem("Malformed ZIP extra field.") }
        let type = bytes.u16(offset)
        let length = bytes.u16(offset + 2)
        offset += 4
        guard length <= end - offset else { throw Problem("Malformed ZIP extra field length.") }
        // Common timestamp and UID/GID fields carry no alternate paths or link targets.
        switch type {
        case 0x5455, 0x7875:
            break
        case 0x5855 where length == 8 || length == 12:
            break
        case 0x7855 where length == 0 || length == 4:
            break
        case 0x5a53 where length == 2 && unixMode == bytes.u16(offset):
            // SZ stores a Unix file mode. Accept only an exact match for the
            // already validated central type/mode; never honor an alternate type.
            break
        default:
            throw Problem("Unsupported ZIP extra field 0x\(String(type, radix: 16)).")
        }
        offset += length
    }
}

private func ipaZIPEntries(_ reader: IPAReader) throws -> [IPAEntry] {
    let tailStart = max(0, reader.size - 65_557)
    let tail = try reader.read(tailStart, reader.size - tailStart)
    guard tail.data.count >= 22 else { throw Problem("Input is too small to be an IPA ZIP archive.") }
    guard let eocd = (0...(tail.data.count - 22)).reversed().first(where: { offset in
        tail.u32(offset) == 0x06054b50 && offset + 22 + tail.u16(offset + 20) == tail.data.count
    }) else {
        throw Problem("IPA ZIP end record is missing.")
    }

    let count = tail.u16(eocd + 10)
    let centralSize = tail.u32(eocd + 12)
    let centralOffset = tail.u32(eocd + 16)
    guard tail.u16(eocd + 4) == 0, tail.u16(eocd + 6) == 0,
          tail.u16(eocd + 8) == count, count > 0, count < 65_535,
          centralSize <= 32 * 1024 * 1024,
          centralOffset + centralSize == tailStart + eocd else {
        throw Problem("Unsupported split, ZIP64, empty, or oversized ZIP directory.")
    }

    let central = try reader.read(centralOffset, centralSize)
    var offset = 0
    var entries: [IPAEntry] = []
    var total = 0
    for _ in 0..<count {
        guard centralSize - offset >= 46, central.u32(offset) == 0x02014b50 else {
            throw Problem("Malformed ZIP central directory.")
        }
        let flags = central.u16(offset + 8)
        let method = central.u16(offset + 10)
        guard flags & ~0x080e == 0, method == 0 || method == 8,
              method == 8 || flags & 0x0006 == 0 else {
            throw Problem("Encrypted ZIP entries and unsupported ZIP methods or flags are outside IPA scope.")
        }

        let crc = central.u32(offset + 16)
        let compressed = central.u32(offset + 20)
        let expanded = central.u32(offset + 24)
        let nameLength = central.u16(offset + 28)
        let extraLength = central.u16(offset + 30)
        let commentLength = central.u16(offset + 32)
        let local = central.u32(offset + 42)
        let nameStart = offset + 46
        let nameEnd = nameStart + nameLength
        guard central.u16(offset + 34) == 0,
              nameLength > 0, nameLength <= 1024,
              nameEnd + extraLength + commentLength <= centralSize,
              local < centralOffset, compressed < 0xffffffff,
              expanded <= 2 * 1024 * 1024 * 1024 else {
            throw Problem("Invalid or oversized IPA ZIP entry.")
        }
        total += expanded
        guard total <= 8 * 1024 * 1024 * 1024 else {
            throw Problem("IPA expands beyond the 8 GiB safety limit.")
        }

        let name = central.data[nameStart..<nameEnd]
        guard let rawPath = String(data: name, encoding: .utf8) else {
            throw Problem("IPA ZIP contains a filename outside UTF-8.")
        }
        let directory = rawPath.hasSuffix("/")
        let path = directory ? String(rawPath.dropLast()) : rawPath
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !parts.isEmpty, parts.count <= 40, parts.allSatisfy(ipaSafeComponent) else {
            throw Problem("IPA ZIP contains an unsafe path.")
        }
        let attributes = central.u32(offset + 38)
        let unixMode = attributes >> 16
        let kind = unixMode & 0o170000
        guard kind == 0 || kind == (directory ? 0o040000 : 0o100000),
              attributes & 0x08 == 0,
              attributes & 0x10 == 0 || directory,
              !directory || expanded == 0,
              method != 0 || compressed == expanded else {
            throw Problem("IPA ZIP contains a link, special file, or inconsistent file type.")
        }
        try ipaCheckZIPExtras(central, start: nameEnd, count: extraLength, unixMode: unixMode)

        let header = try reader.read(local, 30)
        let localExtra = header.u16(28)
        let dataOffset = local + 30 + nameLength + localExtra
        guard header.u32(0) == 0x04034b50, header.u16(6) == flags, header.u16(8) == method,
              header.u16(26) == nameLength, dataOffset + compressed <= centralOffset else {
            throw Problem("ZIP local header disagrees with the central directory.")
        }
        let fields = try reader.read(local + 30, nameLength + localExtra)
        guard fields.data.prefix(nameLength).elementsEqual(name) else {
            throw Problem("ZIP entry has conflicting local and central filenames.")
        }
        try ipaCheckZIPExtras(fields, start: nameLength, count: localExtra, unixMode: unixMode)

        var recordEnd = dataOffset + compressed
        if flags & 0x08 == 0 {
            guard header.u32(14) == crc, header.u32(18) == compressed, header.u32(22) == expanded else {
                throw Problem("ZIP local size or checksum disagrees with the central directory.")
            }
        } else {
            guard [0, crc].contains(header.u32(14)), [0, compressed].contains(header.u32(18)),
                  [0, expanded].contains(header.u32(22)), centralOffset - recordEnd >= 12 else {
                throw Problem("Invalid ZIP streaming metadata.")
            }
            let descriptor = try reader.read(recordEnd, min(16, centralOffset - recordEnd))
            let start = descriptor.u32(0) == 0x08074b50 && descriptor.data.count == 16
                && descriptor.u32(4) == crc ? 4 : 0
            guard descriptor.u32(start) == crc, descriptor.u32(start + 4) == compressed,
                  descriptor.u32(start + 8) == expanded else {
                throw Problem("ZIP data descriptor disagrees with the central directory.")
            }
            recordEnd += start + 12
        }
        entries.append(IPAEntry(path: path, directory: directory, executable: unixMode & 0o111 != 0,
                                method: method, crc: crc, compressed: compressed, expanded: expanded,
                                local: local, dataOffset: dataOffset, recordEnd: recordEnd))
        offset = nameEnd + extraLength + commentLength
    }

    var nextLocal = 0
    for entry in entries.sorted(by: { $0.local < $1.local }) {
        guard entry.local == nextLocal else {
            throw Problem("IPA ZIP contains overlapping entries or unexplained archive data.")
        }
        nextLocal = entry.recordEnd
    }
    guard offset == centralSize, nextLocal == centralOffset else {
        throw Problem("IPA ZIP contains unexplained archive data.")
    }
    return entries
}

private func ipaExtractEntry(_ entry: IPAEntry, reader: IPAReader, output: FileHandle?) throws {
    let chunkSize = 128 * 1024
    var remaining = entry.compressed
    var written = 0
    var checksum = crc32(0, nil, 0)

    func write(_ data: Data) throws {
        guard data.count <= entry.expanded - written else {
            throw Problem("ZIP entry expands beyond its declared size: \(entry.path).")
        }
        checksum = data.withUnsafeBytes { buffer in
            crc32(checksum, buffer.bindMemory(to: Bytef.self).baseAddress, uInt(data.count))
        }
        try output?.write(contentsOf: data)
        written += data.count
    }

    if entry.method == 0 {
        while remaining > 0 {
            let count = min(chunkSize, remaining)
            try write(reader.read(entry.dataOffset + entry.compressed - remaining, count).data)
            remaining -= count
        }
    } else {
        var stream = z_stream()
        guard inflateInit2_(&stream, -MAX_WBITS, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            throw Problem("Could not initialize ZIP decompression.")
        }
        defer { inflateEnd(&stream) }
        var buffer = Data(count: chunkSize)
        var finished = false
        while remaining > 0, !finished {
            let count = min(chunkSize, remaining)
            let data = try reader.read(entry.dataOffset + entry.compressed - remaining, count).data
            remaining -= count
            try data.withUnsafeBytes { input in
                stream.next_in = UnsafeMutablePointer(mutating: input.bindMemory(to: Bytef.self).baseAddress!)
                stream.avail_in = uInt(count)
                defer { stream.next_in = nil }
                repeat {
                    let status = buffer.withUnsafeMutableBytes { output in
                        stream.next_out = output.bindMemory(to: Bytef.self).baseAddress!
                        stream.avail_out = uInt(chunkSize)
                        defer { stream.next_out = nil }
                        return inflate(&stream, Z_NO_FLUSH)
                    }
                    let produced = chunkSize - Int(stream.avail_out)
                    if produced > 0 { try write(buffer.prefix(produced)) }
                    if status == Z_STREAM_END {
                        guard stream.avail_in == 0, remaining == 0 else {
                            throw Problem("ZIP entry has bytes after its deflate stream: \(entry.path).")
                        }
                        finished = true
                        break
                    }
                    if status == Z_BUF_ERROR, stream.avail_in == 0, produced == 0 { break }
                    guard status == Z_OK else { throw Problem("Invalid deflate stream: \(entry.path).") }
                } while stream.avail_in > 0 || stream.avail_out == 0
            }
        }
        guard finished else { throw Problem("Incomplete deflate stream: \(entry.path).") }
    }
    guard written == entry.expanded, checksum == uLong(entry.crc) else {
        throw Problem("ZIP entry failed its size or checksum check: \(entry.path).")
    }
}

private func ipaZIPLayout(_ entries: [IPAEntry]) throws -> (Set<String>, Set<String>, String) {
    var spellings: [String: String] = [:]
    var dirs: Set<String> = []
    var files: Set<String> = []
    var explicit: Set<String> = []
    for entry in entries {
        guard explicit.insert(entry.path).inserted else {
            throw Problem("Duplicate or normalization-equivalent ZIP path: \(entry.path).")
        }
        let parts = entry.path.split(separator: "/")
        for i in parts.indices {
            let path = parts[...i].joined(separator: "/")
            let folded = path.precomposedStringWithCanonicalMapping.folding(
                options: .caseInsensitive, locale: Locale(identifier: "en_US_POSIX"))
            if let previous = spellings[folded], !previous.utf8.elementsEqual(path.utf8) {
                throw Problem("Case or normalization collision in IPA ZIP: \(path).")
            }
            spellings[folded] = path
            if i < parts.count - 1 || entry.directory {
                dirs.insert(path)
                guard dirs.count <= 100_000 else { throw Problem("IPA contains too many directories.") }
            } else {
                files.insert(path)
            }
        }
    }
    guard files.isDisjoint(with: dirs) else {
        throw Problem("A ZIP file path is also a directory or has child entries.")
    }
    let apps = dirs.filter { $0.hasPrefix("Payload/") && $0.split(separator: "/").count == 2 && $0.hasSuffix(".app") }
    guard apps.count == 1, let app = apps.first,
          dirs.allSatisfy({ $0 == "Payload" || $0 == app || $0.hasPrefix(app + "/") }),
          files.allSatisfy({ $0.hasPrefix(app + "/") }) else {
        throw Problem("Expected only Payload/<one iOS app>.app and its contents in the IPA.")
    }
    return (dirs, files, app)
}

private func ipaUnpack(_ entries: [IPAEntry], reader: IPAReader, into root: URL, dirs: Set<String>) throws {
    for dir in dirs.sorted() {
        try FileManager.default.createDirectory(at: root.appendingPathComponent(dir), withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o755])
    }
    for entry in entries {
        if entry.directory {
            try ipaExtractEntry(entry, reader: reader, output: nil)
            continue
        }
        let path = root.appendingPathComponent(entry.path).path
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                      mode_t(entry.executable ? 0o755 : 0o644))
        guard fd >= 0 else { throw Problem("Could not safely create \(entry.path): \(String(cString: strerror(errno))).") }
        let output = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try ipaExtractEntry(entry, reader: reader, output: output)
        try output.close()
    }
}

private let ipaMachMagics: Set<Int> = [0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca,
                                       0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe]

private func ipaHasMachMagic(_ url: URL) throws -> Bool {
    let reader = try IPAReader(url)
    return try reader.size >= 4 && ipaMachMagics.contains(reader.read(0, 4).u32(0, littleEndian: false))
}

private enum IPAPlatform {
    case device, simulator

    var name: String { self == .device ? "iOS device" : "iOS Simulator" }
    var bundlePlatform: String { self == .device ? "iPhoneOS" : "iPhoneSimulator" }
    var buildVersion: Int { self == .device ? 2 : 7 }
}

private func ipaArchitectures(_ url: URL, fileType: Int, platform: IPAPlatform = .device) throws -> [String] {
    let reader = try IPAReader(url)
    let magic = try reader.read(0, 4).u32(0, littleEndian: false)
    var slices: [(offset: Int, size: Int, cpu: Int?, subtype: Int?)] = []
    if [0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca].contains(magic) {
        let little = magic == 0xbebafeca || magic == 0xbfbafeca
        let fat64 = magic == 0xcafebabf || magic == 0xbfbafeca
        let width = fat64 ? 32 : 20
        let count = try reader.read(4, 4).u32(0, littleEndian: little)
        guard (1...16).contains(count) else { throw Problem("Invalid universal Mach-O architecture count.") }
        let table = try reader.read(8, count * width)
        for index in 0..<count {
            let base = index * width
            let cpu = table.u32(base, littleEndian: little)
            let subtype = table.u32(base + 4, littleEndian: little)
            let offset = try fat64 ? table.u64(base + 8, littleEndian: little) : table.u32(base + 8, littleEndian: little)
            let size = try fat64 ? table.u64(base + 16, littleEndian: little) : table.u32(base + 12, littleEndian: little)
            guard offset >= 8 + count * width, offset <= reader.size, size <= reader.size - offset else {
                throw Problem("Universal Mach-O contains an out-of-bounds slice.")
            }
            slices.append((offset, size, cpu, subtype))
        }
    } else {
        slices.append((0, reader.size, nil, nil))
    }

    var previousEnd = 0
    var architectures: Set<String> = []
    for slice in slices.sorted(by: { $0.offset < $1.offset }) {
        guard slice.offset >= previousEnd, slice.size >= 32 else {
            throw Problem("Universal Mach-O contains an overlapping or truncated slice.")
        }
        previousEnd = slice.offset + slice.size
        let header = try reader.read(slice.offset, 32)
        let cpu = header.u32(4)
        let subtype = header.u32(8)
        guard header.u32(0) == 0xfeedfacf,
              slice.cpu == nil || slice.cpu == cpu,
              slice.subtype == nil || slice.subtype == subtype,
              header.u32(12) == fileType else {
            throw Problem("Expected a 64-bit Mach-O executable or dynamic library of the declared type.")
        }
        let baseSubtype = subtype & 0x00ffffff
        let architecture: String
        switch (cpu, baseSubtype) {
        case (0x0100000c, 0): architecture = "arm64"
        case (0x0100000c, 2): architecture = "arm64e"
        case (0x01000007, 3) where platform == .simulator: architecture = "x86_64"
        case (0x01000007, 8) where platform == .simulator: architecture = "x86_64h"
        default: throw Problem("Mach-O has an unsupported architecture for \(platform.name).")
        }
        guard architectures.insert(architecture).inserted else {
            throw Problem("Mach-O contains duplicate architecture slices.")
        }
        let count = header.u32(16)
        let size = header.u32(20)
        guard count > 0, count <= 8192, size <= min(slice.size - 32, 16 * 1024 * 1024) else {
            throw Problem("Invalid Mach-O load command table.")
        }
        let commands = try reader.read(slice.offset + 32, size)
        var offset = 0
        var hasExpectedPlatform = false
        for _ in 0..<count {
            guard size - offset >= 8 else { throw Problem("Truncated Mach-O load command.") }
            let kind = commands.u32(offset)
            let length = commands.u32(offset + 4)
            guard length >= 8, length <= size - offset, length % 8 == 0 else {
                throw Problem("Invalid Mach-O load command size.")
            }
            switch kind {
            case 0x32: // LC_BUILD_VERSION
                guard length >= 24, commands.u32(offset + 8) == platform.buildVersion else {
                    throw Problem("Mach-O was not built for \(platform.name).")
                }
                hasExpectedPlatform = true
            case 0x25: // LC_VERSION_MIN_IPHONEOS
                let legacyPlatform: IPAPlatform = cpu == 0x01000007 ? .simulator : .device
                guard length >= 16, legacyPlatform == platform else {
                    throw Problem("Mach-O was not built for \(platform.name).")
                }
                hasExpectedPlatform = true
            case 0x24, 0x2f, 0x30:
                throw Problem("Mach-O was not built for \(platform.name).")
            case 0x21, 0x2c: // LC_ENCRYPTION_INFO and LC_ENCRYPTION_INFO_64
                guard length >= 20, commands.u32(offset + 16) == 0 else {
                    throw Problem("Mach-O is encrypted or has invalid encryption metadata.")
                }
            default:
                break
            }
            offset += length
        }
        guard offset == size, hasExpectedPlatform else {
            throw Problem("Mach-O does not declare the \(platform.name) platform.")
        }
    }
    return architectures.sorted()
}

private struct IPABundle {
    let path: String
    let id: String
    let executable: String
}

private func ipaBundle(_ path: String, type: String, root: URL, files: Set<String>,
                       platform: IPAPlatform = .device) throws -> IPABundle {
    let info = path + "/Info.plist"
    guard files.contains(info) else { throw Problem("Missing Info.plist in \(path).") }
    let reader = try IPAReader(root.appendingPathComponent(info))
    guard reader.size <= 4 * 1024 * 1024 else { throw Problem("Bundle Info.plist is too large in \(path).") }
    let properties = try plist(reader.read(0, reader.size).data)
    guard let id = properties["CFBundleIdentifier"] as? String, isBundleID(id),
          let executable = properties["CFBundleExecutable"] as? String,
          !executable.contains("/"), ipaSafeComponent(Substring(executable)),
          !["embedded.mobileprovision", "_codesignature", "coderesources"].contains(executable.lowercased()),
          files.contains(path + "/" + executable) else {
        throw Problem("Bundle has a missing, invalid or reserved identifier or executable in \(path).")
    }
    if let packageType = properties["CFBundlePackageType"], packageType as? String != type {
        throw Problem("Unexpected CFBundlePackageType in \(path).")
    }
    if let platforms = properties["CFBundleSupportedPlatforms"], platforms as? [String] != [platform.bundlePlatform] {
        throw Problem("Bundle in \(path) was not built for \(platform.name).")
    }
    return IPABundle(path: path, id: id, executable: path + "/" + executable)
}

private struct IPACodeItem {
    let path: String
    let executable: String
    let id: String?
    let fileType: Int
}

private func ipaCodeItems(_ appPath: String, root: URL, dirs: Set<String>, files: Set<String>) throws -> [IPACodeItem] {
    let app = try ipaBundle(appPath, type: "APPL", root: root, files: files)
    let pluginPrefix = appPath + "/PlugIns/"
    let extensions = try dirs.filter {
        $0.hasPrefix(pluginPrefix) && !$0.dropFirst(pluginPrefix.count).contains("/") && $0.hasSuffix(".appex")
    }.sorted().map { path in
        let bundle = try ipaBundle(path, type: "XPC!", root: root, files: files)
        guard bundle.id.hasPrefix(app.id + ".") else {
            throw Problem("Extension bundle ID \(bundle.id) must start with \(app.id).")
        }
        return bundle
    }
    guard Set(extensions.map(\.id)).count == extensions.count else {
        throw Problem("The IPA contains extensions with duplicate bundle identifiers.")
    }

    var ordered: [IPACodeItem] = []
    var allowedBundles: Set<String> = [appPath]
    for bundle in extensions + [app] {
        allowedBundles.insert(bundle.path)
        let prefix = bundle.path + "/Frameworks/"
        let libraries = files.filter {
            $0.hasPrefix(prefix) && !$0.dropFirst(prefix.count).contains("/") && $0.hasSuffix(".dylib")
        }.sorted()
        for library in libraries {
            ordered.append(IPACodeItem(path: library, executable: library, id: nil, fileType: 6))
        }
        let frameworkPaths = dirs.filter {
            $0.hasPrefix(prefix) && !$0.dropFirst(prefix.count).contains("/") && $0.hasSuffix(".framework")
        }.sorted()
        for path in frameworkPaths {
            guard !dirs.contains(path + "/Versions") else {
                throw Problem("Versioned frameworks are unsupported in IPA mode: \(path).")
            }
            allowedBundles.insert(path)
            let framework = try ipaBundle(path, type: "FMWK", root: root, files: files)
            ordered.append(IPACodeItem(path: path, executable: framework.executable, id: nil, fileType: 6))
        }
        ordered.append(IPACodeItem(path: bundle.path, executable: bundle.executable, id: bundle.id, fileType: 2))
    }

    let unsupportedBundleSuffixes: Set<String> = ["app", "appex", "framework", "xpc", "plugin", "systemextension", "kext"]
    for dir in dirs.sorted() where !allowedBundles.contains(dir) {
        if unsupportedBundleSuffixes.contains((dir as NSString).pathExtension.lowercased()) {
            throw Problem("Unsupported nested code bundle: \(dir).")
        }
    }
    let knownExecutables = Set(ordered.map(\.executable))
    for file in files.sorted() where !knownExecutables.contains(file) {
        if try ipaHasMachMagic(root.appendingPathComponent(file)) {
            throw Problem("Unsupported Mach-O location: \(file).")
        }
    }
    return ordered
}

private func ipaCommandFailure(_ result: CommandResult) -> String {
    let error = String(decoding: result.stderr, as: UTF8.self)
        .split(whereSeparator: \.isNewline).suffix(4).joined(separator: " ")
    return error.isEmpty ? "exit \(result.status)" : error
}

func selfTestIPA() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let app = root.appendingPathComponent("Payload/Test.app", isDirectory: true)
    try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
    let asset = app.appendingPathComponent("asset")
    let original = Data(repeating: 0xab, count: 300_000)
    try original.write(to: asset)
    let zip = root.appendingPathComponent("fixture.ipa")
    let packed = try command("/usr/bin/zip", ["-q", "-X", "-r", zip.path, "Payload"], cwd: root)
    guard packed.status == 0 else { throw Problem("Could not create self-test IPA fixture.") }

    let reader = try IPAReader(zip)
    let entries = try ipaZIPEntries(reader)
    let (dirs, _, _) = try ipaZIPLayout(entries)
    let expanded = root.appendingPathComponent("expanded", isDirectory: true)
    try FileManager.default.createDirectory(at: expanded, withIntermediateDirectories: false)
    try ipaUnpack(entries, reader: reader, into: expanded, dirs: dirs)
    let copy = try Data(contentsOf: expanded.appendingPathComponent("Payload/Test.app/asset"))
    guard copy == original else { throw Problem("Self-test IPA payload did not round-trip.") }

    func expectRejection(_ name: String, _ test: () throws -> Void) throws {
        do {
            try test()
        } catch {
            return
        }
        throw Problem("Self-test IPA incorrectly accepted \(name).")
    }

    let conflictingInfo: [String: Any] = [
        "CFBundleIdentifier": "com.example.test",
        "CFBundleExecutable": "Embedded.MobileProvision",
        "CFBundlePackageType": "APPL"
    ]
    let infoData = try PropertyListSerialization.data(fromPropertyList: conflictingInfo, format: .xml, options: 0)
    try infoData.write(to: app.appendingPathComponent("Info.plist"))
    try Data().write(to: app.appendingPathComponent("Embedded.MobileProvision"))
    try expectRejection("an executable aliased to the embedded profile") {
        _ = try ipaBundle("Payload/Test.app", type: "APPL", root: root,
                          files: ["Payload/Test.app/Info.plist", "Payload/Test.app/Embedded.MobileProvision"])
    }

    let input = try Data(contentsOf: zip)
    let name = Data("Payload/Test.app/asset".utf8)
    var traversal = input
    var replaced = 0
    while let location = traversal.range(of: name) {
        traversal.replaceSubrange(location, with: Data("Payload/Test.app/../xx".utf8))
        replaced += 1
    }
    guard replaced == 2 else { throw Problem("Unexpected self-test IPA fixture layout.") }
    let traversalURL = root.appendingPathComponent("traversal.ipa")
    try traversal.write(to: traversalURL)
    try expectRejection("a traversal path") {
        _ = try ipaZIPEntries(IPAReader(traversalURL))
    }

    let dataEntry = entries.first { $0.path.hasSuffix("/asset") }!
    var corrupt = input
    corrupt[dataEntry.dataOffset] ^= 0xff
    let corruptURL = root.appendingPathComponent("corrupt.ipa")
    try corrupt.write(to: corruptURL)
    try expectRejection("a damaged compressed entry") {
        try ipaExtractEntry(dataEntry, reader: IPAReader(corruptURL), output: nil)
    }

    try FileManager.default.createSymbolicLink(at: app.appendingPathComponent("link"),
                                                withDestinationURL: asset)
    let symlinkZIP = root.appendingPathComponent("symlink.ipa")
    let linked = try command("/usr/bin/zip", ["-q", "-X", "-y", "-r", symlinkZIP.path, "Payload"], cwd: root)
    guard linked.status == 0 else { throw Problem("Could not create self-test IPA link fixture.") }
    try expectRejection("a symlink") {
        _ = try ipaZIPEntries(IPAReader(symlinkZIP))
    }
}

func requireTest(_ condition: @autoclosure () throws -> Bool, _ label: String) throws {
    guard try condition() else { throw Problem("Self-test failed: \(label)") }
}

func requireFailure(_ label: String, _ operation: () throws -> Void) throws {
    do { try operation() } catch { return }
    throw Problem("Self-test failed (expected rejection): \(label)")
}

// MARK: - IPA patcher (standalone; never signs)

private let patchUsage = """
Usage:
  patch-ipa-duo inspect INPUT.ipa [--adapter BUNDLE_IDENTIFIER]
  patch-ipa-duo patch INPUT.ipa --output OUTPUT.ipa
      [--display full|reserved-side] [--bars default|side|top] [--enable-iphone]
      [--adapter BUNDLE_IDENTIFIER]
  patch-ipa-duo --self-test

Full-mode top/side overrides build and inject a best-effort UIKit bar hook using
the selected Xcode iPhoneOS SDK (27.1 or later). Optional adapters live beside
this script in adapters/<bundle-identifier>/ (manifest, native source and tests).
Adapters are selected automatically by the app's bundle identifier. --adapter
forces a named adapter, retaining version/build checks and the app's identifier.
Output requires separate signing. Existing output files are never overwritten.
"""

private struct PatchOptions {
    let inspect: Bool
    let input: URL
    var output: URL?
    var display = "full"
    var bars = "default"
    var enableIPhone = false
    var adapterIdentifier: String?

    init(_ args: [String]) throws {
        guard args.count >= 2, ["inspect", "patch"].contains(args[0]), !args[1].hasPrefix("--") else {
            throw Problem(patchUsage)
        }
        inspect = args[0] == "inspect"
        input = URL(fileURLWithPath: args[1])
        var index = 2
        var seen: Set<String> = []
        while index < args.count {
            let flag = args[index]
            guard (!inspect || flag == "--adapter"), seen.insert(flag).inserted else { throw Problem("Unexpected or repeated option: \(flag).") }
            if flag == "--enable-iphone" { enableIPhone = true; index += 1; continue }
            guard ["--output", "--display", "--bars", "--adapter"].contains(flag), index + 1 < args.count else {
                throw Problem("Unknown option or missing value: \(flag).")
            }
            let value = args[index + 1]
            guard !value.hasPrefix("--") else { throw Problem("Missing value for \(flag).") }
            switch flag {
            case "--output": output = URL(fileURLWithPath: value)
            case "--display": display = value
            case "--bars": bars = value
            default:
                guard isBundleID(value) else { throw Problem("--adapter requires a canonical bundle identifier, not a file path.") }
                adapterIdentifier = value
            }
            index += 2
        }
        guard ["full", "reserved-side"].contains(display), ["default", "side", "top"].contains(bars) else {
            throw Problem("Invalid display or bars option.\n\(patchUsage)")
        }
        guard inspect || output != nil else { throw Problem("patch requires --output OUTPUT.ipa.") }
        guard display != "reserved-side" || bars != "top" else {
            throw Problem("--bars top requires --display full.")
        }
    }
}

private struct PatchSDKRecord {
    let offset: Int
    let sdk: Int
    let minimum: Int
}

private func patchVersion(_ value: Int) -> String {
    let major = value >> 16
    let minor = (value >> 8) & 255
    let patch = value & 255
    return patch == 0 ? "\(major).\(minor)" : "\(major).\(minor).\(patch)"
}

// ipaArchitectures validates the complete slice/load-command structure first.
private func patchSlices(_ url: URL) throws -> [(offset: Int, size: Int)] {
    let reader = try IPAReader(url)
    let magic = try reader.read(0, 4).u32(0, littleEndian: false)
    if [0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca].contains(magic) {
        let little = magic == 0xbebafeca || magic == 0xbfbafeca
        let fat64 = magic == 0xcafebabf || magic == 0xbfbafeca
        let width = fat64 ? 32 : 20
        let count = try reader.read(4, 4).u32(0, littleEndian: little)
        let table = try reader.read(8, count * width)
        return try (0..<count).map { index in
            let offset = try fat64 ? table.u64(index * width + 8, littleEndian: little)
                : table.u32(index * width + 8, littleEndian: little)
            let size = try fat64 ? table.u64(index * width + 16, littleEndian: little)
                : table.u32(index * width + 12, littleEndian: little)
            return (offset, size)
        }
    }
    return [(0, reader.size)]
}

private func patchSDKRecords(_ url: URL, fileType: Int = 2) throws -> [PatchSDKRecord] {
    _ = try ipaArchitectures(url, fileType: fileType)
    let reader = try IPAReader(url)
    var records: [PatchSDKRecord] = []
    for slice in try patchSlices(url) {
        let start = slice.offset
        let header = try reader.read(start, 32)
        let commands = try reader.read(start + 32, header.u32(20))
        var offset = 0
        var sliceRecords: [PatchSDKRecord] = []
        for _ in 0..<header.u32(16) {
            let kind = commands.u32(offset)
            if kind == 0x32 || kind == 0x25 {
                let field = offset + (kind == 0x32 ? 16 : 12)
                sliceRecords.append(PatchSDKRecord(offset: start + 32 + field,
                    sdk: commands.u32(field), minimum: commands.u32(field - 4)))
            }
            offset += commands.u32(offset + 4)
        }
        guard sliceRecords.count == 1 else { throw Problem("Each executable slice must declare exactly one SDK version.") }
        records += sliceRecords
    }
    return records
}

private let patchBarLibrary = "IPAPatcherBars.dylib"
private let patchBarLoadPath = "@executable_path/Frameworks/" + patchBarLibrary

// Self-contained source: the CLI needs no adjacent source files at runtime.
private let patchBarSource = #"""
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <stdatomic.h>

static atomic_bool PatchRescanQueued;

static NSInteger PatchBehavior(id self, SEL selector) {
    if (@available(iOS 27.1, *)) {
        return PATCH_TOP ? UIVerticalBarBehaviorDisabled : UIVerticalBarBehaviorAutomatic;
    }
    return 0;
}

static BOOL PatchIsController(Class cls) {
    for (Class current = cls; current; current = class_getSuperclass(current)) {
        if (current == [UIViewController class]) return YES;
    }
    return NO;
}

static void PatchControllers(void) {
    if (@available(iOS 27.1, *)) {
        unsigned int count = 0;
        Class *classes = objc_copyClassList(&count);
        SEL selector = @selector(preferredVerticalBarBehavior);
        Method base = class_getInstanceMethod([UIViewController class], selector);
        const char *types = method_getTypeEncoding(base);
        for (unsigned int index = 0; index < count; index++) {
            Class cls = classes[index];
            if (!PatchIsController(cls)) continue;
            // Add on inheriting classes; replace only the class's own implementation.
            if (!class_addMethod(cls, selector, (IMP)PatchBehavior, types)) {
                class_replaceMethod(cls, selector, (IMP)PatchBehavior, types);
            }
        }
        free(classes);
    }
}

static void PatchImageAdded(const struct mach_header *header, intptr_t slide) {
    // dyld calls under its loader lock. Defer all Objective-C work to the main queue.
    if (atomic_exchange(&PatchRescanQueued, true)) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        atomic_store(&PatchRescanQueued, false);
        PatchControllers();
    });
}

@interface IPAPatcherBarsBootstrap : NSObject
@end
@implementation IPAPatcherBarsBootstrap
+ (void)load {
    if (@available(iOS 27.1, *)) {
        PatchControllers();
        _dyld_register_func_for_add_image(PatchImageAdded);
    }
}
@end
"""#

private struct PatchInjection {
    let header: Int
    let offset: Int
    let count: Int
    let size: Int
}

// Only consume zeroed header padding before any file-backed section/segment.
// Never move code, sections, chained fixups, or fat slices to create space.
private func patchInjectionPlan(_ url: URL, library: String = patchBarLoadPath) throws -> [PatchInjection] {
    try patchInjectionPlan(url, libraries: [library])
}

private func patchInjectionPlan(_ url: URL, libraries: [String]) throws -> [PatchInjection] {
    _ = try ipaArchitectures(url, fileType: 2)
    let reader = try IPAReader(url)
    guard !libraries.isEmpty, Set(libraries).count == libraries.count else { throw Problem("Injection requires unique library paths.") }
    let commandSize = libraries.reduce(0) { $0 + ((24 + $1.utf8.count + 1 + 7) & ~7) }
    var plan: [PatchInjection] = []
    for slice in try patchSlices(url) {
        let header = try reader.read(slice.offset, 32)
        let size = header.u32(20)
        let commands = try reader.read(slice.offset + 32, size)
        var offset = 0
        var boundary = slice.size
        var hasSections = false
        for _ in 0..<header.u32(16) {
            let kind = commands.u32(offset)
            let length = commands.u32(offset + 4)
            if [0xc, 0x18, 0x80000018, 0x8000001f, 0x80000023].contains(kind) {
                guard length >= 24 else { throw Problem("Malformed dylib load command.") }
                let nameOffset = commands.u32(offset + 8)
                guard nameOffset >= 24, nameOffset < length else { throw Problem("Invalid dylib load-command name.") }
                let bytes = commands.data[(offset + nameOffset)..<(offset + length)]
                guard let end = bytes.firstIndex(of: 0) else { throw Problem("Unterminated dylib load-command name.") }
                if libraries.contains(String(decoding: bytes[..<end], as: UTF8.self)) {
                    throw Problem("A requested library is already injected. Use the original IPA to patch again.")
                }
            }
            if kind == 0x19 { // LC_SEGMENT_64
                guard length >= 72 else { throw Problem("Truncated segment command.") }
                let fileOffset = try commands.u64(offset + 40, littleEndian: true)
                let fileSize = try commands.u64(offset + 48, littleEndian: true)
                guard fileOffset <= slice.size, fileSize <= slice.size - fileOffset else { throw Problem("Segment points outside its Mach-O slice.") }
                if fileOffset > 0 && fileSize > 0 { boundary = min(boundary, fileOffset) }
                let sections = commands.u32(offset + 64)
                guard sections <= (length - 72) / 80 else { throw Problem("Invalid segment section table.") }
                for index in 0..<sections {
                    let section = offset + 72 + index * 80
                    let type = commands.u32(section + 64) & 255
                    let sectionSize = try commands.u64(section + 40, littleEndian: true)
                    let sectionOffset = commands.u32(section + 48)
                    if sectionSize > 0 && ![1, 12, 18].contains(type) {
                        guard sectionOffset <= slice.size, sectionSize <= slice.size - sectionOffset else { throw Problem("Section points outside its Mach-O slice.") }
                        hasSections = true
                        boundary = min(boundary, sectionOffset)
                    }
                }
            }
            offset += length
        }
        let end = 32 + size
        guard hasSections, boundary >= end, commandSize <= boundary - end,
              try reader.read(slice.offset + end, commandSize).data.allSatisfy({ $0 == 0 }) else {
            throw Problem("Insufficient Mach-O load-command space for injected libraries; zeroed header padding before a file-backed section is required.")
        }
        plan.append(PatchInjection(header: slice.offset, offset: slice.offset + end, count: header.u32(16), size: size))
    }
    return plan
}

private func patchInject(_ url: URL, plan: [PatchInjection], libraries: [String] = [patchBarLoadPath]) throws {
    var load = Data()
    for library in libraries {
        let name = Data((library + "\0").utf8)
        let size = (24 + name.count + 7) & ~7
        let words: [UInt32] = [0xc, UInt32(size), 24, 0, 0x10000, 0x10000]
        load.append(words.map(\.littleEndian).withUnsafeBytes { Data($0) })
        load.append(name)
        load.append(Data(count: size - 24 - name.count))
    }
    let handle = try FileHandle(forWritingTo: url)
    defer { try? handle.close() }
    for item in plan {
        try handle.seek(toOffset: UInt64(item.offset))
        try handle.write(contentsOf: load)
        let fields = [UInt32(item.count + libraries.count), UInt32(item.size + load.count)].map(\.littleEndian)
        try handle.seek(toOffset: UInt64(item.header + 16))
        try handle.write(contentsOf: fields.withUnsafeBytes { Data($0) })
    }
}

private func patchBuildBars(_ executable: URL, mode: String, output: URL, work: URL) throws {
    let source = work.appendingPathComponent("IPAPatcherBars.m")
    try Data(patchBarSource.utf8).write(to: source)
    try patchBuildLibrary(executable, source: source, loadPath: patchBarLoadPath,
                          defines: ["PATCH_TOP=\(mode == "top" ? 1 : 0)"], output: output, work: work)
}

private func patchBuildLibrary(_ executable: URL, source: URL, loadPath: String, defines: [String] = [], output: URL, work: URL) throws {
    let reader = try IPAReader(executable)
    let records = try patchSDKRecords(executable)
    let slices = try patchSlices(executable)
    var libraries: [URL] = []
    for (index, slice) in slices.enumerated() {
        let header = try reader.read(slice.offset, 32)
        let architecture = header.u32(8) & 0x00ffffff == 2 ? "arm64e" : "arm64"
        let library = work.appendingPathComponent("\(UUID().uuidString)-\(architecture).dylib")
        let built = try command("/usr/bin/xcrun", ["--sdk", "iphoneos", "clang", "-dynamiclib", "-fobjc-arc", "-fblocks",
            "-target", "\(architecture)-apple-ios\(patchVersion(records[index].minimum))", "-framework", "UIKit",
            "-Werror", "-Wl,-adhoc_codesign", "-install_name", loadPath, source.path, "-o", library.path] + defines.map { "-D" + $0 })
        guard built.status == 0 else { throw Problem("Cannot build injected library \(source.lastPathComponent) with the selected iPhoneOS SDK: \(ipaCommandFailure(built))") }
        _ = try ipaArchitectures(library, fileType: 6)
        guard try patchSDKRecords(library, fileType: 6).allSatisfy({ $0.minimum <= records[index].minimum }) else {
            throw Problem("The injected library cannot preserve this architecture's deployment target with the selected Xcode toolchain.")
        }
        libraries.append(library)
    }
    if libraries.count == 1 {
        try FileManager.default.copyItem(at: libraries[0], to: output)
    } else {
        let combined = try command("/usr/bin/xcrun", ["lipo", "-create"] + libraries.map(\.path) + ["-output", output.path])
        guard combined.status == 0 else { throw Problem("Cannot combine injected-library architectures: \(ipaCommandFailure(combined))") }
    }
    guard try ipaArchitectures(output, fileType: 6) == ipaArchitectures(executable, fileType: 2) else {
        throw Problem("Injected-library architectures do not match the executable.")
    }
}

private func patchHasScene(_ info: [String: Any]) -> Bool {
    guard let manifest = info["UIApplicationSceneManifest"] as? [String: Any],
          let configurations = manifest["UISceneConfigurations"] as? [String: Any],
          let application = configurations["UIWindowSceneSessionRoleApplication"] as? [[String: Any]] else { return false }
    return !application.isEmpty && application.allSatisfy { !$0.isEmpty }
}

private indirect enum AdapterPlistValue: Codable {
    case string(String), bool(Bool), integer(Int), real(Double), array([AdapterPlistValue]), dictionary([String: AdapterPlistValue])

    init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer()
        if let result = try? value.decode(Bool.self) { self = .bool(result) }
        else if let result = try? value.decode(Int.self) { self = .integer(result) }
        else if let result = try? value.decode(Double.self) { self = .real(result) }
        else if let result = try? value.decode(String.self) { self = .string(result) }
        else if let result = try? value.decode([AdapterPlistValue].self) { self = .array(result) }
        else { self = .dictionary(try value.decode([String: AdapterPlistValue].self)) }
    }

    func encode(to encoder: Encoder) throws {
        var value = encoder.singleValueContainer()
        switch self {
        case .string(let result): try value.encode(result)
        case .bool(let result): try value.encode(result)
        case .integer(let result): try value.encode(result)
        case .real(let result): try value.encode(result)
        case .array(let result): try value.encode(result)
        case .dictionary(let result): try value.encode(result)
        }
    }

    var plistValue: Any {
        switch self {
        case .string(let result): return result
        case .bool(let result): return result
        case .integer(let result): return result
        case .real(let result): return result
        case .array(let result): return result.map(\.plistValue)
        case .dictionary(let result): return result.mapValues(\.plistValue)
        }
    }
}

private struct PatchAdapter: Codable {
    struct Build: Codable, Equatable {
        let version: String
        let build: String
    }
    let schemaVersion: Int
    let bundleIdentifier: String
    let aliases: [String]
    let name: String
    let supportedBuilds: [Build]
    let fullModeDefaultBars: String
    let supportedFullModeBars: [String]
    let plannedChanges: [String]
    struct Operations: Codable {
        struct ExecutableTransform: Codable { let source: String }
        struct Library: Codable {
            let source: String
            let fileName: String
            var loadPath: String { "@executable_path/Frameworks/" + fileName }
        }
        let enableIPhone: Bool
        let removePlistKeys: [String]
        let setPlist: [String: AdapterPlistValue]
        let requiresAbsentPlistKeys: [String]
        let requiredExecutableStrings: [String]
        let libraries: [Library]
        var executableTransform: ExecutableTransform? = nil
    }
    let patchUnavailableReason: String?
    var operations: Operations? = nil
    var resourceDirectory: URL? = nil

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, bundleIdentifier, aliases, name, supportedBuilds, fullModeDefaultBars
        case supportedFullModeBars, plannedChanges, patchUnavailableReason, operations
    }

    var identifiers: [String] { [bundleIdentifier] + aliases }
}

private struct PatchAdapterMatch {
    let adapter: PatchAdapter
    let supportedBuild: Bool
    let forced: Bool

    func requirePatchSupport() throws {
        guard supportedBuild else {
            throw Problem("Adapter \(adapter.name) does not support this app version/build. No output produced.")
        }
        guard adapter.operations != nil else {
            throw Problem("\(adapter.patchUnavailableReason ?? "Adapter patch operations are unavailable.") No output produced.")
        }
    }
}

private func patchAdapterDirectory(script: URL = URL(fileURLWithPath: CommandLine.arguments[0])) -> URL {
    script.resolvingSymlinksInPath().deletingLastPathComponent().appendingPathComponent("adapters", isDirectory: true)
}

private func patchLoadAdapters(in directory: URL) throws -> [PatchAdapter] {
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDirectory) else { return [] }
    guard isDirectory.boolValue else { throw Problem("Adapter path must be a directory: \(directory.path).") }
    let entries = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]).sorted { $0.path < $1.path }
    var adapters: [PatchAdapter] = []
    var identifiers: Set<String> = []
    for entry in entries {
        let package = try entry.resourceValues(forKeys: [.isDirectoryKey]).isDirectory == true
        if !package && entry.pathExtension != "json" { continue }
        let file = package ? entry.appendingPathComponent("adapter.json") : entry
        if package && !FileManager.default.fileExists(atPath: file.path) { continue }
        let reader = try IPAReader(file)
        guard reader.size <= 1024 * 1024 else { throw Problem("Adapter descriptor is too large: \(file.lastPathComponent).") }
        var adapter: PatchAdapter
        do { adapter = try JSONDecoder().decode(PatchAdapter.self, from: reader.read(0, reader.size).data) }
        catch { throw Problem("Invalid adapter descriptor \(file.lastPathComponent): \(error.localizedDescription)") }
        guard adapter.schemaVersion == (adapter.operations == nil ? 1 : 2),
              (package ? entry.lastPathComponent == adapter.bundleIdentifier : file.lastPathComponent == adapter.bundleIdentifier + ".json"),
              adapter.identifiers.allSatisfy(isBundleID),
              Set(adapter.identifiers).count == adapter.identifiers.count,
              !adapter.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              (adapter.operations != nil ? adapter.schemaVersion == 2 && package && adapter.patchUnavailableReason == nil
               : !(adapter.patchUnavailableReason ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty),
              !adapter.supportedBuilds.isEmpty,
              adapter.supportedBuilds.allSatisfy({ !$0.version.isEmpty && !$0.build.isEmpty }),
              ["default", "top", "side"].contains(adapter.fullModeDefaultBars),
              !adapter.supportedFullModeBars.isEmpty,
              Set(adapter.supportedFullModeBars).count == adapter.supportedFullModeBars.count,
              adapter.supportedFullModeBars.allSatisfy({ ["default", "top", "side"].contains($0) }),
              adapter.supportedFullModeBars.contains(adapter.fullModeDefaultBars) else {
            throw Problem("Invalid adapter metadata or bundle-identifier filename: \(file.lastPathComponent).")
        }
        adapter.resourceDirectory = file.deletingLastPathComponent().resolvingSymlinksInPath()
        if let operations = adapter.operations {
            let protected: Set<String> = ["CFBundleIdentifier", "CFBundleExecutable", "CFBundleVersion", "CFBundleShortVersionString", "CFBundleSupportedPlatforms", "MinimumOSVersion", "UIDeviceFamily", "UIRequiredDeviceCapabilities", "DTSDKName", "DTPlatformVersion"]
            guard protected.isDisjoint(with: Set(operations.removePlistKeys).union(operations.setPlist.keys)),
                  operations.libraries.count <= 8,
                  Set(operations.libraries.map(\.fileName)).count == operations.libraries.count,
                  operations.requiredExecutableStrings.allSatisfy({ !$0.isEmpty && !$0.contains("\0") }),
                  operations.libraries.allSatisfy({ $0.fileName.hasSuffix(".dylib") && !$0.fileName.contains("/") && ipaSafeComponent(Substring($0.fileName)) && $0.fileName.caseInsensitiveCompare(patchBarLibrary) != .orderedSame }) else {
                throw Problem("Invalid adapter operations in \(adapter.bundleIdentifier).")
            }
            for library in operations.libraries { _ = try patchAdapterSource(adapter, relativePath: library.source) }
            if let transform = operations.executableTransform {
                _ = try patchAdapterResource(adapter, relativePath: transform.source, suffix: ".py")
            }
        }
        for identifier in adapter.identifiers {
            guard identifiers.insert(identifier).inserted else { throw Problem("Multiple adapters claim bundle identifier \(identifier).") }
        }
        adapters.append(adapter)
    }
    return adapters
}

private func patchAdapterSource(_ adapter: PatchAdapter, relativePath: String) throws -> URL {
    try patchAdapterResource(adapter, relativePath: relativePath, suffix: ".m")
}

private func patchAdapterResource(_ adapter: PatchAdapter, relativePath: String, suffix: String) throws -> URL {
    let parts = relativePath.split(separator: "/", omittingEmptySubsequences: false)
    guard let directory = adapter.resourceDirectory, !parts.isEmpty, parts.allSatisfy(ipaSafeComponent), relativePath.hasSuffix(suffix) else {
        throw Problem("Adapter resource must be a \(suffix) file within its package.")
    }
    let source = directory.appendingPathComponent(relativePath).resolvingSymlinksInPath()
    guard source.path.hasPrefix(directory.path + "/") else { throw Problem("Adapter source escapes its package.") }
    let reader = try IPAReader(source)
    guard reader.size <= 1024 * 1024 else { throw Problem("Adapter source is too large.") }
    return source
}

private func patchTransformExecutable(_ executable: URL, adapter: PatchAdapterMatch?, libraries: [String], work: URL) throws {
    guard let adapter, let transform = adapter.adapter.operations?.executableTransform else { return }
    let source = try patchAdapterResource(adapter.adapter, relativePath: transform.source, suffix: ".py")
    let request = work.appendingPathComponent("adapter-transform-request.json")
    let payload: [String: Any] = ["schemaVersion": 1, "executable": executable.path, "injectedLibraries": libraries]
    try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]).write(to: request)
    let result = try command("/usr/bin/python3", [source.path, request.path])
    guard result.status == 0 else { throw Problem("Adapter executable transformation failed: \(ipaCommandFailure(result))") }
    print("Adapter transformation: \(visible(String(decoding: result.stdout, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)))")
    _ = try ipaArchitectures(executable, fileType: 2)
}

private func patchMatchAdapter(_ info: [String: Any], adapters: [PatchAdapter]) -> PatchAdapterMatch? {
    guard let identifier = info["CFBundleIdentifier"] as? String,
          let adapter = adapters.first(where: { $0.identifiers.contains(identifier) }) else { return nil }
    let supported = adapter.supportedBuilds.contains {
        $0.version == info["CFBundleShortVersionString"] as? String && $0.build == info["CFBundleVersion"] as? String
    }
    return PatchAdapterMatch(adapter: adapter, supportedBuild: supported, forced: false)
}

private func patchSelectAdapter(_ info: [String: Any], adapters: [PatchAdapter], forcedIdentifier: String?) throws -> PatchAdapterMatch? {
    guard let forcedIdentifier else { return patchMatchAdapter(info, adapters: adapters) }
    guard let adapter = adapters.first(where: { $0.bundleIdentifier == forcedIdentifier }) else {
        throw Problem("Requested adapter \(forcedIdentifier) was not found in the adapters directory. Use its canonical bundle identifier.")
    }
    // Manual selection bypasses only identifier matching. The adapter still owns
    // build support and patch availability; the IPA's bundle ID is never changed.
    var matchingInfo = info
    matchingInfo["CFBundleIdentifier"] = adapter.bundleIdentifier
    let match = patchMatchAdapter(matchingInfo, adapters: [adapter])!
    return PatchAdapterMatch(adapter: adapter, supportedBuild: match.supportedBuild, forced: true)
}

private func patchResolvedOptions(_ options: PatchOptions, adapter: PatchAdapterMatch?) throws -> PatchOptions {
    guard let adapter else { return options }
    try adapter.requirePatchSupport()
    var result = options
    if options.display == "full" {
        if options.bars == "default" { result.bars = adapter.adapter.fullModeDefaultBars }
        guard adapter.adapter.supportedFullModeBars.contains(result.bars) else {
            throw Problem("Adapter \(adapter.adapter.name) does not support --bars \(result.bars).")
        }
    }
    result.enableIPhone = options.enableIPhone || adapter.adapter.operations!.enableIPhone
    return result
}

private func patchAdapterInfo(_ info: [String: Any], adapter: PatchAdapterMatch?) throws -> [String: Any] {
    guard let operations = adapter?.adapter.operations else { return info }
    for key in operations.requiresAbsentPlistKeys where info[key] != nil {
        throw Problem("Adapter requires an original app without \(key). Use an unpatched input IPA.")
    }
    var result = info
    for key in operations.removePlistKeys { result.removeValue(forKey: key) }
    for (key, value) in operations.setPlist { result[key] = value.plistValue }
    return result
}

private func patchValidateAdapterExecutable(_ executable: URL, adapter: PatchAdapterMatch?) throws {
    guard let operations = adapter?.adapter.operations, !operations.requiredExecutableStrings.isEmpty else { return }
    let reader = try IPAReader(executable)
    for slice in try patchSlices(executable) {
        let data = try reader.read(slice.offset, slice.size).data
        for value in operations.requiredExecutableStrings where data.range(of: Data((value + "\0").utf8)) == nil {
            throw Problem("Adapter executable preflight failed: required string \(value) is missing in a Mach-O slice.")
        }
    }
}

private func patchResolve(_ info: [String: Any], records: [PatchSDKRecord], options: PatchOptions,
                          adapter: PatchAdapterMatch? = nil) throws -> ([String: Any], Int) {
    if let adapter { try adapter.requirePatchSupport() }
    let configured = try patchAdapterInfo(info, adapter: adapter)
    guard patchHasScene(configured) else {
        throw Problem("App has no existing application scene configuration; a compatibility adapter is required. Scene configuration was not fabricated.")
    }
    let sdk = options.display == "reserved-side" ? 27 << 16 : max((27 << 16) | (1 << 8), records.map(\.sdk).max() ?? 0)
    guard records.allSatisfy({ $0.minimum <= sdk }) else {
        throw Problem("The selected SDK \(patchVersion(sdk)) is below the executable's minimum OS; cannot preserve the deployment target.")
    }
    if let minimum = info["MinimumOSVersion"] as? String {
        guard minimum.compare(patchVersion(sdk), options: .numeric) != .orderedDescending else {
            throw Problem("The selected SDK \(patchVersion(sdk)) is below MinimumOSVersion \(minimum).")
        }
    }
    var result = configured
    guard let families = info["UIDeviceFamily"] as? [Int], !families.isEmpty,
          families.allSatisfy({ [1, 2].contains($0) }) else { throw Problem("Expected iPhone/iPad UIDeviceFamily metadata.") }
    if (options.enableIPhone || adapter?.adapter.operations?.enableIPhone == true) && !families.contains(1) { result["UIDeviceFamily"] = [1] + families }
    result["DTSDKName"] = "iphoneos" + patchVersion(sdk)
    result["DTPlatformVersion"] = patchVersion(sdk)
    return (result, sdk)
}

private func patchIPACommand(_ args: [String], adapterDirectory: URL = patchAdapterDirectory()) throws {
    if args == ["--help"] || args == ["-h"] { print(patchUsage); return }
    if args == ["--self-test"] { try selfTestPatch(); return }
    var options = try PatchOptions(args)
    if let output = options.output {
        var existing = stat()
        guard lstat(output.path, &existing) != 0, errno == ENOENT else {
            throw Problem("Output already exists or cannot be inspected: \(output.path).")
        }
    }
    let reader = try IPAReader(options.input)
    let allEntries = try ipaZIPEntries(reader)
    // Validate and checksum permitted store artwork, then omit it from the payload.
    let artwork = allEntries.filter { $0.path == "iTunesArtwork" && !$0.directory }
    guard artwork.count <= 1 else { throw Problem("Duplicate iTunesArtwork archive entry.") }
    for entry in artwork { try ipaExtractEntry(entry, reader: reader, output: nil) }
    let entries = allEntries.filter { $0.path != "iTunesArtwork" || $0.directory }
    let (dirs, files, appPath) = try ipaZIPLayout(entries)
    let work = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: work) }
    try ipaUnpack(entries, reader: reader, into: work, dirs: dirs)
    let ordered = try ipaCodeItems(appPath, root: work, dirs: dirs, files: files)
    for item in ordered { _ = try ipaArchitectures(work.appendingPathComponent(item.executable), fileType: item.fileType) }
    let app = try ipaBundle(appPath, type: "APPL", root: work, files: files)
    let infoURL = work.appendingPathComponent(app.path + "/Info.plist")
    let executable = work.appendingPathComponent(app.executable)
    let info = try plist(Data(contentsOf: infoURL))
    let adapter = try patchSelectAdapter(info, adapters: patchLoadAdapters(in: adapterDirectory), forcedIdentifier: options.adapterIdentifier)
    let records = try patchSDKRecords(executable)
    print("App: \(visible(app.id)); executable: \(visible(app.executable))")
    print("Executable SDK: \(records.map { patchVersion($0.sdk) }.joined(separator: ", ")); minimum OS: \(records.map { patchVersion($0.minimum) }.joined(separator: ", "))")
    print("Plist SDK: \(visible(info["DTSDKName"] as? String ?? "absent")); platform version: \(visible(info["DTPlatformVersion"] as? String ?? "absent"))")
    print("Device families: \(visible(String(describing: info["UIDeviceFamily"] ?? "absent"))); application scene: \(patchHasScene(info) ? "present" : "absent")")
    print("Adapter: \(adapter.map { visible($0.adapter.name) + " (" + $0.adapter.bundleIdentifier + "; " + ($0.supportedBuild ? ($0.adapter.operations == nil ? "inspection only" : "patch supported") : "unsupported version/build") + ")" } ?? "generic")")
    if let adapter { print("Adapter selection: \(adapter.forced ? "forced by --adapter" : "automatic from bundle identifier")") }
    if options.inspect {
        print("Scene manifest: \(visible(String(describing: info["UIApplicationSceneManifest"] ?? "absent")))")
        print("Available now: \((adapter == nil && patchHasScene(info)) || (adapter?.supportedBuild == true && adapter?.adapter.operations != nil) ? "full/default|top|side bars; reserved-side/system bars; --enable-iphone (subject to adapter overrides)" : "inspection only; compatibility adapter required")")
        if let adapter {
            print("Adapter full-mode bars: default=\(adapter.adapter.fullModeDefaultBars); supported=\(adapter.adapter.supportedFullModeBars.joined(separator: ", "))")
            print("Adapter changes: \(visible(adapter.adapter.plannedChanges.joined(separator: " ")))")
            print("Adapter status: \(adapter.supportedBuild ? visible(adapter.adapter.patchUnavailableReason ?? "Patch operations available.") : "No supported build matches this app version/build.")")
        }
        print("Top/side injection requires header padding and Xcode iPhoneOS SDK 27.1+.")
        return
    }
    options = try patchResolvedOptions(options, adapter: adapter)
    try patchValidateAdapterExecutable(executable, adapter: adapter)
    let (updated, sdk) = try patchResolve(info, records: records, options: options, adapter: adapter)
    let barPath = app.path + "/Frameworks/" + patchBarLibrary
    let injectBars = options.display == "full" && options.bars != "default"
    if options.display == "reserved-side" && files.contains(barPath) {
        throw Problem("Input already contains a bar hook. Use the original IPA for reserved-side system placement.")
    }
    let adapterLibraries = adapter?.adapter.operations?.libraries ?? []
    let libraryNames = adapterLibraries.map(\.fileName) + (injectBars ? [patchBarLibrary] : [])
    let loadPaths = libraryNames.map { "@executable_path/Frameworks/" + $0 }
    for name in libraryNames {
        let path = app.path + "/Frameworks/" + name
        guard !(files.union(dirs)).contains(where: { $0.caseInsensitiveCompare(path) == .orderedSame }) else {
            throw Problem("Injected-library output path already exists. Use the original IPA to patch again.")
        }
    }
    let injection = loadPaths.isEmpty ? [] : try patchInjectionPlan(executable, libraries: loadPaths)
    print("Resolved: display=\(options.display), bars=\(options.display == "reserved-side" ? "system" : options.bars == "default" ? "existing" : options.bars), SDK=\(patchVersion(sdk)), families=\(updated["UIDeviceFamily"]!)")
    if records.contains(where: { $0.sdk > sdk }) { print("Warning: linked SDK downgraded to \(patchVersion(sdk)); deployment target preserved.") }
    let handle = try FileHandle(forWritingTo: executable)
    do {
        for record in records {
            var value = UInt32(sdk).littleEndian
            try handle.seek(toOffset: UInt64(record.offset))
            try handle.write(contentsOf: withUnsafeBytes(of: &value) { Data($0) })
        }
        try handle.close()
    } catch { try? handle.close(); throw error }
    for library in adapterLibraries {
        let output = work.appendingPathComponent(app.path + "/Frameworks/" + library.fileName)
        try FileManager.default.createDirectory(at: output.deletingLastPathComponent(), withIntermediateDirectories: true)
        let source = try patchAdapterSource(adapter!.adapter, relativePath: library.source)
        try patchBuildLibrary(executable, source: source, loadPath: library.loadPath, output: output, work: work)
        print("Built adapter library: \(library.fileName)")
    }
    if injectBars {
        let library = work.appendingPathComponent(barPath)
        try FileManager.default.createDirectory(at: library.deletingLastPathComponent(), withIntermediateDirectories: true)
        try patchBuildBars(executable, mode: options.bars, output: library, work: work)
        print("Injected source-built UIKit hook: \(options.bars == "top" ? "horizontal top/bottom bars" : "automatic placement (side where supported)"). Best effort on iOS 27.1+; sign the new dylib with the app.")
    }
    if !loadPaths.isEmpty { try patchInject(executable, plan: injection, libraries: loadPaths) }
    try patchTransformExecutable(executable, adapter: adapter, libraries: loadPaths, work: work)
    try PropertyListSerialization.data(fromPropertyList: updated, format: .binary, options: 0).write(to: infoURL)
    guard try patchSDKRecords(executable).allSatisfy({ $0.sdk == sdk }) else { throw Problem("SDK verification failed.") }
    // Keep original signature metadata for the separate signer to recover entitlements.
    // Its hashes are stale after patching and must never be presented as valid signing.
    let output = options.output!
    let staging = try temporaryDirectory(in: output.deletingLastPathComponent())
    defer { try? FileManager.default.removeItem(at: staging) }
    let archive = staging.appendingPathComponent("patched.ipa")
    let zipped = try command("/usr/bin/zip", ["-q", "-X", "-r", archive.path, "Payload"], cwd: work)
    guard zipped.status == 0 else { throw Problem("Could not package patched IPA: \(ipaCommandFailure(zipped)).") }
    let check = try IPAReader(archive)
    let checkedEntries = try ipaZIPEntries(check)
    _ = try ipaZIPLayout(checkedEntries)
    for entry in checkedEntries { try ipaExtractEntry(entry, reader: check, output: nil) }
    guard link(archive.path, output.path) == 0 else {
        throw Problem("Could not publish without overwriting output: \(String(cString: strerror(errno))).")
    }
    print("Patched IPA written to \(visible(output.path)). Requires separate signing before installation; original signature hashes are stale.")
}

private func selfTestBarRuntime(work: URL) throws {
    // Exercise the actual ObjC hook against a minimal controller hierarchy on macOS.
    // This verifies dispatch/overrides, not visual UIKit placement on a Duo.
    let shim = #"""
    #import <Foundation/Foundation.h>
    #import <objc/message.h>
    typedef NS_ENUM(NSInteger, UIVerticalBarBehavior) {
        UIVerticalBarBehaviorAutomatic = 0, UIVerticalBarBehaviorDisabled = 1
    };
    @interface UIViewController : NSObject
    @property(nonatomic, readonly) NSInteger preferredVerticalBarBehavior;
    @end
    @implementation UIViewController
    - (NSInteger)preferredVerticalBarBehavior { return 99; }
    @end
    @interface FixtureController : UIViewController
    @end
    @implementation FixtureController
    - (NSInteger)preferredVerticalBarBehavior { return 88; }
    @end
    """#
    let main = #"""
    static NSInteger FixtureOriginal(id self, SEL selector) { return 77; }
    int main(void) {
        @autoreleasepool {
            NSInteger expected = PATCH_TOP ? 1 : 0;
            if ([UIViewController new].preferredVerticalBarBehavior != expected) return 1;
            if ([FixtureController new].preferredVerticalBarBehavior != expected) return 2;
            Class late = objc_allocateClassPair([UIViewController class], "LateFixtureController", 0);
            class_addMethod(late, @selector(preferredVerticalBarBehavior), (IMP)FixtureOriginal, "q@:");
            objc_registerClassPair(late);
            PatchControllers();
            id controller = [late new];
            NSInteger result = ((NSInteger (*)(id, SEL))objc_msgSend)(controller, @selector(preferredVerticalBarBehavior));
            return result == expected ? 0 : 3;
        }
    }
    """#
    let source = work.appendingPathComponent("bar-runtime.m")
    let code = patchBarSource.replacingOccurrences(of: "#import <UIKit/UIKit.h>", with: shim) + "\n" + main
    try Data(code.utf8).write(to: source)
    for mode in ["top", "side"] {
        let output = work.appendingPathComponent("bar-runtime-" + mode)
        let built = try command("/usr/bin/xcrun", ["--sdk", "macosx", "clang", "-fobjc-arc", "-fblocks", "-framework", "Foundation",
            "-DPATCH_TOP=\(mode == "top" ? 1 : 0)", "-Werror", source.path, "-o", output.path])
        guard built.status == 0 else { throw Problem("Cannot build hook dispatch test: \(ipaCommandFailure(built))") }
        let run = try command(output.path, [])
        try requireTest(run.status == 0, "\(mode) runtime dispatch on base, overriding, and late classes")
    }
}

private func selfTestBarInjection(work: URL, app: URL) throws {
    let source = work.appendingPathComponent("main.c")
    try Data("int main(void) { return 0; }\n".utf8).write(to: source)
    var inputs: [String] = []
    for architecture in ["arm64", "arm64e"] {
        let binary = work.appendingPathComponent("fixture-" + architecture)
        let build = try command("/usr/bin/xcrun", ["--sdk", "iphoneos", "clang", "-target", "\(architecture)-apple-ios15.0",
            "-Wl,-headerpad,0x400", source.path, "-o", binary.path])
        guard build.status == 0 else { throw Problem("Cannot build device test fixture: \(ipaCommandFailure(build))") }
        inputs.append(binary.path)
    }
    let executable = app.appendingPathComponent("Fixture")
    try FileManager.default.removeItem(at: executable)
    let combined = try command("/usr/bin/xcrun", ["lipo", "-create"] + inputs + ["-output", executable.path])
    try requireTest(combined.status == 0, "build universal device fixture")
    let original = try Data(contentsOf: executable)
    let originalRecords = try patchSDKRecords(executable)
    let plan = try patchInjectionPlan(executable)
    let multiple = [patchBarLoadPath, "@executable_path/Frameworks/FixtureAdapter.dylib"]
    let multiplePlan = try patchInjectionPlan(executable, libraries: multiple)
    let multipleBinary = work.appendingPathComponent("multi-library-fixture")
    try original.write(to: multipleBinary)
    try patchInject(multipleBinary, plan: multiplePlan, libraries: multiple)
    _ = try ipaArchitectures(multipleBinary, fileType: 2)
    let multiData = try Data(contentsOf: multipleBinary)
    let multiBytes = IPABytes(data: multiData)
    var restoredMulti = multiData
    for item in multiplePlan {
        try requireTest(multiBytes.u32(item.header + 16) == item.count + 2, "inject multiple libraries in each universal slice")
        let end = item.header + 32 + multiBytes.u32(item.header + 20)
        restoredMulti.replaceSubrange((item.header + 16)..<(item.header + 24), with: original[(item.header + 16)..<(item.header + 24)])
        restoredMulti.replaceSubrange(item.offset..<end, with: original[item.offset..<end])
    }
    try requireTest(restoredMulti == original, "multiple-library injection preserves all original code/data")
    let input = work.appendingPathComponent("bars-input.ipa")
    let packed = try command("/usr/bin/zip", ["-q", "-X", "-r", input.path, "Payload"], cwd: work)
    try requireTest(packed.status == 0, "pack bar fixture")
    for mode in ["top", "side"] {
        let output = work.appendingPathComponent("bars-\(mode).ipa")
        try patchIPACommand(["patch", input.path, "--output", output.path, "--bars", mode])
        let root = work.appendingPathComponent("bars-\(mode)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        let reader = try IPAReader(output)
        let entries = try ipaZIPEntries(reader)
        let (dirs, files, appPath) = try ipaZIPLayout(entries)
        try ipaUnpack(entries, reader: reader, into: root, dirs: dirs)
        let library = root.appendingPathComponent(appPath + "/Frameworks/" + patchBarLibrary)
        try requireTest(try ipaArchitectures(library, fileType: 6) == ["arm64", "arm64e"], "hook covers both architectures")
        let seal = try command("/usr/bin/codesign", ["--display", "--entitlements", "-", "--xml", library.path])
        try requireTest(seal.status == 0, "linker ad-hoc seal permits separate signer entitlement inspection")
        let items = try ipaCodeItems(appPath, root: root, dirs: dirs, files: files)
        try requireTest(items.contains { $0.executable.hasSuffix("/" + patchBarLibrary) }, "separate signer discovers injected dylib")
        let patchedExecutable = root.appendingPathComponent(appPath + "/Fixture")
        let after = try Data(contentsOf: patchedExecutable)
        let bytes = IPABytes(data: after)
        let size = (24 + patchBarLoadPath.utf8.count + 1 + 7) & ~7
        for item in plan {
            try requireTest(bytes.u32(item.header + 16) == item.count + 1 && bytes.u32(item.header + 20) == item.size + size, "update Mach-O command counts")
            try requireTest(bytes.u32(item.offset) == 0xc && bytes.u32(item.offset + 4) == size, "inject LC_LOAD_DYLIB")
            let name = Data((patchBarLoadPath + "\0").utf8)
            try requireTest(after.subdata(in: (item.offset + 24)..<(item.offset + 24 + name.count)) == name, "load path points inside app")
        }
        // The original linked SDK is newer than 27.1; nothing outside header padding changes.
        try requireTest(try patchSDKRecords(patchedExecutable).map(\.sdk) == originalRecords.map(\.sdk), "preserve newer SDK during injection")
        var restored = after
        for item in plan {
            restored.replaceSubrange((item.header + 16)..<(item.header + 24), with: original[(item.header + 16)..<(item.header + 24)])
            restored.replaceSubrange(item.offset..<(item.offset + size), with: original[item.offset..<(item.offset + size)])
        }
        try requireTest(restored == original, "injection preserves original code, data and slice offsets")
        try requireFailure("do not inject twice") { _ = try patchInjectionPlan(patchedExecutable) }
        let rejected = work.appendingPathComponent("repatch-\(mode).ipa")
        try requireFailure("bar path collision cannot publish") { try patchIPACommand(["patch", output.path, "--output", rejected.path, "--bars", "side"]) }
        try requireTest(!FileManager.default.fileExists(atPath: rejected.path), "collision produces no output")
    }
    // Zero padding alone is not enough: the first file-backed section is authoritative.
    var tight = original
    let firstSlice = try patchSlices(executable)[0]
    let firstHeader = IPABytes(data: original)
    var cursor = firstSlice.offset + 32
    for _ in 0..<firstHeader.u32(firstSlice.offset + 16) {
        let length = firstHeader.u32(cursor + 4)
        if firstHeader.u32(cursor) == 0x19 && firstHeader.u32(cursor + 64) > 0 {
            let field = cursor + 72 + 48
            var value = UInt32(plan[0].offset - firstSlice.offset).littleEndian
            tight.replaceSubrange(field..<(field + 4), with: withUnsafeBytes(of: &value) { Data($0) })
            break
        }
        cursor += length
    }
    let tightURL = work.appendingPathComponent("tight-padding")
    try tight.write(to: tightURL)
    try requireFailure("refuse section data even when zero") { _ = try patchInjectionPlan(tightURL) }
    var occupied = original
    occupied[plan[0].offset] = 1
    let occupiedURL = work.appendingPathComponent("nonzero-padding")
    try occupied.write(to: occupiedURL)
    try requireFailure("refuse nonzero header padding") { _ = try patchInjectionPlan(occupiedURL) }
}

private func selfTestAdapters(in work: URL) throws -> URL {
    let directory = work.appendingPathComponent("test-adapters")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    let adapter = PatchAdapter(schemaVersion: 1, bundleIdentifier: "com.example.patchfixture", aliases: ["com.example.original"],
        name: "Fixture adapter", supportedBuilds: [.init(version: "1.0", build: "100")], fullModeDefaultBars: "top",
        supportedFullModeBars: ["top", "side"], plannedChanges: ["Fixture scene bridge"], patchUnavailableReason: "Fixture bridge is pending.")
    let file = directory.appendingPathComponent(adapter.bundleIdentifier + ".json")
    let encoded = try JSONEncoder().encode(adapter)
    try encoded.write(to: file)
    let loaded = try patchLoadAdapters(in: directory)
    let forcedOptions = try PatchOptions(["inspect", "input.ipa", "--adapter", adapter.bundleIdentifier])
    try requireTest(forcedOptions.inspect && forcedOptions.adapterIdentifier == adapter.bundleIdentifier, "inspect accepts manual adapter")
    try requireTest(try PatchOptions(["patch", "input.ipa", "--output", "output.ipa", "--adapter", adapter.bundleIdentifier]).adapterIdentifier == adapter.bundleIdentifier, "patch accepts manual adapter")
    try requireFailure("missing adapter value") { _ = try PatchOptions(["inspect", "input.ipa", "--adapter"]) }
    try requireFailure("missing adapter value before another flag") { _ = try PatchOptions(["patch", "input.ipa", "--output", "output.ipa", "--adapter", "--bars", "top"]) }
    try requireFailure("adapter paths rejected") { _ = try PatchOptions(["inspect", "input.ipa", "--adapter", "../adapter.json"]) }
    try requireFailure("repeated adapter option") { _ = try PatchOptions(["inspect", "input.ipa", "--adapter", adapter.bundleIdentifier, "--adapter", adapter.bundleIdentifier]) }
    try requireFailure("inspect patch-only option") { _ = try PatchOptions(["inspect", "input.ipa", "--bars", "top"]) }
    var info: [String: Any] = ["CFBundleIdentifier": adapter.bundleIdentifier, "CFBundleShortVersionString": "1.0", "CFBundleVersion": "100"]
    try requireTest(patchMatchAdapter(info, adapters: loaded)?.supportedBuild == true, "adapter canonical identifier and supported build")
    info["CFBundleIdentifier"] = adapter.aliases[0]
    try requireTest(patchMatchAdapter(info, adapters: loaded)?.adapter.bundleIdentifier == adapter.bundleIdentifier, "adapter alias resolves canonical descriptor")
    info["CFBundleVersion"] = "101"
    let unsupported = patchMatchAdapter(info, adapters: loaded)
    try requireTest(unsupported != nil && unsupported?.supportedBuild == false, "known app unsupported build stays with adapter")
    try requireFailure("unsupported adapter build") { try unsupported!.requirePatchSupport() }
    info["CFBundleVersion"] = "100"
    info["CFBundleShortVersionString"] = "2.0"
    try requireTest(patchMatchAdapter(info, adapters: loaded)?.supportedBuild == false, "adapter version must also match")
    info["CFBundleIdentifier"] = "com.example.unrelated"
    try requireTest(patchMatchAdapter(info, adapters: loaded) == nil, "unrelated apps use generic patcher")
    info["CFBundleShortVersionString"] = "1.0"
    let forced = try patchSelectAdapter(info, adapters: loaded, forcedIdentifier: adapter.bundleIdentifier)
    try requireTest(forced?.forced == true && forced?.supportedBuild == true, "manual selection bypasses bundle identifier matching")
    try requireTest(info["CFBundleIdentifier"] as? String == "com.example.unrelated", "forcing preserves input identifier")
    let automatic = try patchSelectAdapter(info, adapters: loaded, forcedIdentifier: nil)
    try requireTest(automatic == nil, "without manual flag unmatched app stays generic")
    info["CFBundleIdentifier"] = adapter.bundleIdentifier
    try requireTest(try patchSelectAdapter(info, adapters: loaded, forcedIdentifier: nil)?.forced == false, "matching app automatically selects adapter")
    let alternate = PatchAdapter(schemaVersion: 1, bundleIdentifier: "com.example.alternate", aliases: [], name: "Alternate fixture",
        supportedBuilds: adapter.supportedBuilds, fullModeDefaultBars: "side", supportedFullModeBars: ["side"], plannedChanges: [], patchUnavailableReason: "Alternate bridge is pending.")
    let overridden = try patchSelectAdapter(info, adapters: loaded + [alternate], forcedIdentifier: alternate.bundleIdentifier)
    try requireTest(overridden?.adapter.bundleIdentifier == alternate.bundleIdentifier && overridden?.forced == true, "manual adapter overrides a different automatic match")
    info["CFBundleVersion"] = "101"
    let forcedUnsupported = try patchSelectAdapter(info, adapters: loaded, forcedIdentifier: adapter.bundleIdentifier)
    try requireTest(forcedUnsupported?.supportedBuild == false, "manual selection retains build checks")
    try requireFailure("manual selection cannot bypass unsupported build") { try forcedUnsupported!.requirePatchSupport() }
    try requireFailure("missing requested adapter") { _ = try patchSelectAdapter(info, adapters: loaded, forcedIdentifier: "com.example.missing") }
    try requireFailure("forcing requires canonical ID") { _ = try patchSelectAdapter(info, adapters: loaded, forcedIdentifier: adapter.aliases[0]) }
    try requireTest(try patchLoadAdapters(in: work.appendingPathComponent("missing-adapters")).isEmpty, "generic script runs without adapters directory")
    try requireTest(patchAdapterDirectory(script: work.appendingPathComponent("patch-ipa-duo")) == work.appendingPathComponent("adapters", isDirectory: true), "discovery is relative to script")
    let link = work.appendingPathComponent("patch-link")
    let target = work.appendingPathComponent("patch-ipa-duo")
    try Data().write(to: target)
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
    try requireTest(patchAdapterDirectory(script: link) == patchAdapterDirectory(script: target), "adapter lookup follows script symlink")
    try Data("{".utf8).write(to: file)
    try requireFailure("malformed adapter JSON") { _ = try patchLoadAdapters(in: directory) }
    try encoded.write(to: file)
    let wrongName = directory.appendingPathComponent("com.example.wrong.json")
    try FileManager.default.moveItem(at: file, to: wrongName)
    try requireFailure("adapter filename must be canonical bundle identifier") { _ = try patchLoadAdapters(in: directory) }
    try FileManager.default.moveItem(at: wrongName, to: file)
    let duplicate = PatchAdapter(schemaVersion: 1, bundleIdentifier: "com.example.duplicate", aliases: adapter.aliases,
        name: "Duplicate", supportedBuilds: adapter.supportedBuilds, fullModeDefaultBars: "top", supportedFullModeBars: ["top"],
        plannedChanges: [], patchUnavailableReason: "Pending")
    let duplicateFile = directory.appendingPathComponent(duplicate.bundleIdentifier + ".json")
    try JSONEncoder().encode(duplicate).write(to: duplicateFile)
    try requireFailure("ambiguous adapter alias") { _ = try patchLoadAdapters(in: directory) }
    try FileManager.default.removeItem(at: duplicateFile)
    var invalid = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
    invalid["schemaVersion"] = 2
    try JSONSerialization.data(withJSONObject: invalid).write(to: file)
    try requireFailure("unknown adapter schema") { _ = try patchLoadAdapters(in: directory) }
    invalid["schemaVersion"] = 1
    invalid["bundleIdentifier"] = "../invalid"
    try JSONSerialization.data(withJSONObject: invalid).write(to: file)
    try requireFailure("invalid adapter bundle identifier") { _ = try patchLoadAdapters(in: directory) }
    try encoded.write(to: file)
    let activeRoot = work.appendingPathComponent("active-adapters")
    let package = activeRoot.appendingPathComponent(adapter.bundleIdentifier)
    try FileManager.default.createDirectory(at: package, withIntermediateDirectories: true)
    let source = package.appendingPathComponent("bridge.m")
    try Data("#import <UIKit/UIKit.h>\n".utf8).write(to: source)
    var active = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
    active["schemaVersion"] = 2
    active.removeValue(forKey: "patchUnavailableReason")
    active["supportedFullModeBars"] = ["top"]
    let scene: [String: Any] = ["UISceneConfigurations": ["UIWindowSceneSessionRoleApplication": [["UISceneDelegateClassName": "FixtureSceneDelegate"]]], "UIApplicationSupportsMultipleScenes": false]
    let operations: [String: Any] = ["enableIPhone": true, "removePlistKeys": ["UIRequiresFullScreen"],
        "setPlist": ["UIApplicationSceneManifest": scene], "requiresAbsentPlistKeys": ["UIApplicationSceneManifest"],
        "requiredExecutableStrings": ["FixtureRequiredClass"], "libraries": [["source": "bridge.m", "fileName": "FixtureBridge.dylib"]]]
    active["operations"] = operations
    let activeFile = package.appendingPathComponent("adapter.json")
    try JSONSerialization.data(withJSONObject: active).write(to: activeFile)
    let ready = try patchLoadAdapters(in: activeRoot)
    let match = patchMatchAdapter(["CFBundleIdentifier": adapter.bundleIdentifier, "CFBundleShortVersionString": "1.0", "CFBundleVersion": "100"], adapters: ready)!
    try match.requirePatchSupport()
    let options = try PatchOptions(["patch", "in", "--output", "out"])
    let resolved = try patchResolvedOptions(options, adapter: match)
    try requireTest(resolved.bars == "top" && resolved.enableIPhone, "adapter resolves bar and family defaults")
    var side = options
    side.bars = "side"
    try requireFailure("adapter rejects unsupported bar override") { _ = try patchResolvedOptions(side, adapter: match) }
    side.display = "reserved-side"
    try requireTest(try patchResolvedOptions(side, adapter: match).bars == "side", "reserved-side keeps system placement")
    let configured = try patchAdapterInfo(["UIRequiresFullScreen": true, "MinimumOSVersion": "15.0"], adapter: match)
    try requireTest(configured["UIRequiresFullScreen"] == nil && patchHasScene(configured) && configured["MinimumOSVersion"] as? String == "15.0", "adapter applies only declared plist changes")
    try requireTest((configured["UIApplicationSceneManifest"] as? [String: Any])?["UIApplicationSupportsMultipleScenes"] as? Bool == false, "adapter JSON preserves booleans")
    try requireFailure("adapter does not overwrite an existing scene") { _ = try patchAdapterInfo(configured, adapter: match) }
    let executable = work.appendingPathComponent("string-preflight")
    try Data("prefix\0FixtureRequiredClass\0".utf8).write(to: executable)
    try patchValidateAdapterExecutable(executable, adapter: match)
    try Data("missing marker".utf8).write(to: executable)
    try requireFailure("adapter requires native class marker") { try patchValidateAdapterExecutable(executable, adapter: match) }
    var unsafeOperations = operations
    unsafeOperations["setPlist"] = ["CFBundleIdentifier": "com.example.forbidden"]
    active["operations"] = unsafeOperations
    try JSONSerialization.data(withJSONObject: active).write(to: activeFile)
    try requireFailure("adapter cannot change protected bundle identifier") { _ = try patchLoadAdapters(in: activeRoot) }
    unsafeOperations = operations
    unsafeOperations["libraries"] = [["source": "../escape.m", "fileName": "FixtureBridge.dylib"]]
    active["operations"] = unsafeOperations
    try JSONSerialization.data(withJSONObject: active).write(to: activeFile)
    try requireFailure("adapter source remains in its package") { _ = try patchLoadAdapters(in: activeRoot) }
    active["operations"] = operations
    try JSONSerialization.data(withJSONObject: active).write(to: activeFile)
    return directory
}

private func selfTestPatch() throws {
    let extra = IPABytes(data: Data([0x53, 0x5a, 2, 0, 0xed, 0x81]))
    try ipaCheckZIPExtras(extra, start: 0, count: 6, unixMode: 0o100755)
    try requireFailure("SZ cannot contradict central ZIP mode") { try ipaCheckZIPExtras(extra, start: 0, count: 6, unixMode: 0o120755) }
    try requireFailure("SZ requires central ZIP mode") { try ipaCheckZIPExtras(extra, start: 0, count: 6) }
    let options = try PatchOptions(["patch", "in.ipa", "--output", "out.ipa"])
    let scene: [String: Any] = ["UISceneConfigurations": ["UIWindowSceneSessionRoleApplication": [["UISceneDelegateClassName": "ExistingScene"]]]]
    let info: [String: Any] = ["UIDeviceFamily": [2], "UIApplicationSceneManifest": scene, "UIRequiredDeviceCapabilities": ["arm64"], "MinimumOSVersion": "15.0"]
    let record = PatchSDKRecord(offset: 0, sdk: (18 << 16) | (2 << 8), minimum: 15 << 16)
    let (generic, sdk) = try patchResolve(info, records: [record], options: options)
    try requireTest(sdk == (27 << 16) | (1 << 8), "full defaults to SDK 27.1")
    try requireTest(generic["UIDeviceFamily"] as? [Int] == [2], "generic preserves iPad-only family without flag")
    try requireTest(NSDictionary(dictionary: generic["UIApplicationSceneManifest"] as! [String: Any]).isEqual(to: scene), "preserve scene manifest")
    try requireTest(generic["UIRequiredDeviceCapabilities"] as? [String] == ["arm64"] && generic["MinimumOSVersion"] as? String == "15.0", "preserve requirements and deployment")
    var enabled = options
    enabled.enableIPhone = true
    let universal = try patchResolve(info, records: [record], options: enabled).0
    try requireTest(universal["UIDeviceFamily"] as? [Int] == [1, 2], "add iPhone and retain iPad")
    try requireTest(try patchResolve(universal, records: [record], options: enabled).0["UIDeviceFamily"] as? [Int] == [1, 2], "iPhone flag idempotent")
    let newer = PatchSDKRecord(offset: 0, sdk: (28 << 16) | (2 << 8), minimum: 15 << 16)
    try requireTest(try patchResolve(info, records: [newer], options: options).1 == newer.sdk, "preserve newer SDK")
    var reserved = options
    reserved.display = "reserved-side"
    try requireTest(try patchResolve(info, records: [newer], options: reserved).1 == 27 << 16, "reserved SDK 27.0")
    try requireFailure("reserved/top conflict") { _ = try PatchOptions(["patch", "in", "--output", "out", "--display", "reserved-side", "--bars", "top"]) }
    try requireFailure("high minimum OS") { _ = try patchResolve(info, records: [PatchSDKRecord(offset: 0, sdk: 28 << 16, minimum: (27 << 16) | (1 << 8))], options: reserved) }
    var legacy = info
    legacy.removeValue(forKey: "UIApplicationSceneManifest")
    try requireFailure("legacy scene requires adapter") { _ = try patchResolve(legacy, records: [record], options: enabled) }
    var top = options
    top.bars = "top"
    try requireTest(try patchResolve(info, records: [record], options: top).1 == sdk, "accept top override")
    top.bars = "side"
    try requireTest(try patchResolve(info, records: [record], options: top).1 == sdk, "accept side override")
    let work = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: work) }
    let adapterDirectory = try selfTestAdapters(in: work)
    let binary = work.appendingPathComponent("main")
    for subtype: UInt32 in [0, 2] {
        let words: [UInt32] = [0xfeedfacf, 0x0100000c, subtype, 2, 1, 24, 0, 0, 0x32, 24, 2, 15 << 16, 18 << 16, 0]
        try words.map(\.littleEndian).withUnsafeBytes { Data($0) }.write(to: binary)
        let parsed = try patchSDKRecords(binary)
        try requireTest(parsed.count == 1 && parsed[0].offset == 48 && parsed[0].minimum == 15 << 16, "parse arm64/arm64e SDK location")
    }
    let thin = try Data(contentsOf: binary)
    var fat = Data()
    let fatWords: [UInt32] = [0xcafebabe, 2, 0x0100000c, 0, 4096, 56, 12, 0x0100000c, 2, 8192, 56, 12]
    fat.append(fatWords.map(\.bigEndian).withUnsafeBytes { Data($0) })
    fat.append(Data(count: 4096 - fat.count))
    var arm64 = thin
    arm64[8] = 0
    fat.append(arm64)
    fat.append(Data(count: 8192 - fat.count))
    fat.append(thin)
    try fat.write(to: binary)
    try requireTest(try patchSDKRecords(binary).map(\.offset) == [4144, 8240], "universal slice SDK offsets")

    let appPath = "Payload/Fixture.app"
    let app = work.appendingPathComponent(appPath)
    try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
    try fat.write(to: app.appendingPathComponent("Fixture"))
    var fixture = info
    fixture["CFBundleIdentifier"] = "com.example.patchfixture"
    fixture["CFBundleExecutable"] = "Fixture"
    fixture["CFBundlePackageType"] = "APPL"
    fixture["CFBundleShortVersionString"] = "1.0"
    fixture["CFBundleVersion"] = "100"
    let infoURL = app.appendingPathComponent("Info.plist")
    try PropertyListSerialization.data(fromPropertyList: fixture, format: .binary, options: 0).write(to: infoURL)
    try Data("artwork".utf8).write(to: work.appendingPathComponent("iTunesArtwork"))
    let input = work.appendingPathComponent("input.ipa")
    let output = work.appendingPathComponent("output.ipa")
    let zipped = try command("/usr/bin/zip", ["-q", "-X", "-r", input.path, "Payload", "iTunesArtwork"], cwd: work)
    try requireTest(zipped.status == 0, "pack patch fixture")
    let original = try Data(contentsOf: input)
    try patchIPACommand(["inspect", input.path], adapterDirectory: adapterDirectory)
    let adapterOutput = work.appendingPathComponent("adapter-blocked.ipa")
    do {
        try patchIPACommand(["patch", input.path, "--output", adapterOutput.path], adapterDirectory: adapterDirectory)
        throw Problem("Self-test failed: adapter patch unexpectedly succeeded.")
    } catch let error as Problem {
        try requireTest(error.description.contains("Fixture bridge is pending."), "adapter owns patch diagnostic")
    }
    try requireTest(!FileManager.default.fileExists(atPath: adapterOutput.path), "unavailable adapter never publishes output")
    var renamedFixture = fixture
    renamedFixture["CFBundleIdentifier"] = "com.example.renamed"
    try PropertyListSerialization.data(fromPropertyList: renamedFixture, format: .binary, options: 0).write(to: infoURL)
    let renamedInput = work.appendingPathComponent("renamed.ipa")
    let renamedPacked = try command("/usr/bin/zip", ["-q", "-X", "-r", renamedInput.path, "Payload"], cwd: work)
    try requireTest(renamedPacked.status == 0, "pack renamed app fixture")
    try PropertyListSerialization.data(fromPropertyList: fixture, format: .binary, options: 0).write(to: infoURL)
    try patchIPACommand(["inspect", renamedInput.path, "--adapter", "com.example.patchfixture"], adapterDirectory: adapterDirectory)
    let forcedOutput = work.appendingPathComponent("forced-blocked.ipa")
    do {
        try patchIPACommand(["patch", renamedInput.path, "--output", forcedOutput.path, "--adapter", "com.example.patchfixture"], adapterDirectory: adapterDirectory)
        throw Problem("Self-test failed: forced adapter was ignored.")
    } catch let error as Problem {
        try requireTest(error.description.contains("Fixture bridge is pending."), "forced adapter owns diagnostic for renamed IPA")
    }
    try requireTest(!FileManager.default.fileExists(atPath: forcedOutput.path), "forced unavailable adapter produces no output")
    let missingOutput = work.appendingPathComponent("missing-adapter.ipa")
    try requireFailure("missing forced adapter cannot fall back to generic patching") {
        try patchIPACommand(["patch", renamedInput.path, "--output", missingOutput.path, "--adapter", "com.example.missing"], adapterDirectory: adapterDirectory)
    }
    try requireTest(!FileManager.default.fileExists(atPath: missingOutput.path), "missing adapter produces no output")
    try patchIPACommand(["inspect", input.path])
    try patchIPACommand(["patch", input.path, "--output", output.path, "--enable-iphone"])
    try requireTest(try Data(contentsOf: input) == original, "input unchanged")
    let expanded = work.appendingPathComponent("checked")
    try FileManager.default.createDirectory(at: expanded, withIntermediateDirectories: false)
    let outputReader = try IPAReader(output)
    let outputEntries = try ipaZIPEntries(outputReader)
    let (outputDirs, _, _) = try ipaZIPLayout(outputEntries)
    try ipaUnpack(outputEntries, reader: outputReader, into: expanded, dirs: outputDirs)
    let result = try plist(Data(contentsOf: expanded.appendingPathComponent(appPath + "/Info.plist")))
    try requireTest(result["UIDeviceFamily"] as? [Int] == [1, 2] && result["DTSDKName"] as? String == "iphoneos27.1", "published plist changes")
    let resultRecords = try patchSDKRecords(expanded.appendingPathComponent(appPath + "/Fixture"))
    try requireTest(resultRecords.count == 2 && resultRecords.allSatisfy { $0.sdk == sdk && $0.minimum == 15 << 16 }, "patch all slices and preserve minimum OS")
    let reservedOutput = work.appendingPathComponent("reserved.ipa")
    try patchIPACommand(["patch", output.path, "--output", reservedOutput.path, "--display", "reserved-side", "--bars", "side"])
    let reservedRoot = work.appendingPathComponent("reserved-check")
    try FileManager.default.createDirectory(at: reservedRoot, withIntermediateDirectories: false)
    let reservedReader = try IPAReader(reservedOutput)
    let reservedEntries = try ipaZIPEntries(reservedReader)
    let (reservedDirs, _, _) = try ipaZIPLayout(reservedEntries)
    try ipaUnpack(reservedEntries, reader: reservedReader, into: reservedRoot, dirs: reservedDirs)
    try requireTest(try patchSDKRecords(reservedRoot.appendingPathComponent(appPath + "/Fixture")).allSatisfy { $0.sdk == 27 << 16 && $0.minimum == 15 << 16 }, "reserved output SDK and deployment")
    let reservedInfo = try plist(Data(contentsOf: reservedRoot.appendingPathComponent(appPath + "/Info.plist")))
    try requireTest(reservedInfo["DTSDKName"] as? String == "iphoneos27.0" && reservedInfo["DTPlatformVersion"] as? String == "27.0", "reserved plist matches executable")
    let published = try Data(contentsOf: output)
    try requireFailure("refuse existing output") { try patchIPACommand(["patch", input.path, "--output", output.path]) }
    try requireTest(try Data(contentsOf: output) == published, "existing output preserved")
    let failed = work.appendingPathComponent("failed.ipa")
    try requireFailure("missing load-command padding produces no output") {
        try patchIPACommand(["patch", input.path, "--output", failed.path, "--bars", "top"])
    }
    try requireTest(!FileManager.default.fileExists(atPath: failed.path), "failure leaves no published output")
    let legacyWords: [UInt32] = [0xfeedfacf, 0x0100000c, 0, 2, 1, 16, 0, 0, 0x25, 16, 15 << 16, 18 << 16]
    try legacyWords.map(\.littleEndian).withUnsafeBytes { Data($0) }.write(to: binary)
    try requireTest(try patchSDKRecords(binary).first?.offset == 44, "legacy SDK command location")
    let unsafeFamily = "\u{1b}[2J"
    try requireTest(!visible(String(describing: unsafeFamily)).contains("\u{1b}"), "inspection escapes plist control characters")
    let encryptedWords: [UInt32] = [0xfeedfacf, 0x0100000c, 0, 2, 2, 48, 0, 0,
                                    0x32, 24, 2, 15 << 16, 18 << 16, 0, 0x2c, 24, 0, 0, 1, 0]
    try encryptedWords.map(\.littleEndian).withUnsafeBytes { Data($0) }.write(to: binary)
    try requireFailure("encrypted binary") { _ = try patchSDKRecords(binary) }
    try selfTestBarRuntime(work: work)
    try selfTestBarInjection(work: work, app: app)
    try selfTestIPA()
    print("Patcher self-tests passed.")
}

do {
    try patchIPACommand(Array(CommandLine.arguments.dropFirst()))
} catch let error as Problem {
    FileHandle.standardError.write(Data("Error: \(visible(error.description))\n".utf8))
    exit(1)
} catch {
    FileHandle.standardError.write(Data("Error: \(visible(error.localizedDescription))\n".utf8))
    exit(1)
}
