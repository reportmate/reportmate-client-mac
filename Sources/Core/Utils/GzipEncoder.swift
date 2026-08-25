import Compression
import Foundation

/// Wraps Apple's raw-DEFLATE encoder in a gzip container.
///
/// A full collection serializes to a megabyte or more of highly repetitive
/// module JSON, and gzip takes about an eighth of that to the wire. A body
/// that spends less time in flight has a correspondingly smaller window in
/// which the upload can be interrupted, and an interrupted upload is by far
/// the most common way a check-in is turned away.
///
/// `COMPRESSION_ZLIB` is Apple's name for bare DEFLATE with no zlib header and
/// no checksum, so it cannot be sent as-is under any Content-Encoding without
/// guessing which of the two readings of "deflate" the other end implements.
/// Framing it as gzip removes the ambiguity: the header, CRC and length are
/// fifteen lines, and what goes on the wire is then unambiguous to every HTTP
/// stack there is.
public enum GzipEncoder {

    /// Gzip-compress `data`, or return nil if the encoder could not run.
    ///
    /// Returning nil rather than throwing is deliberate: compression is an
    /// optimisation, and a device must never lose its check-in because the
    /// payload would not compress. The caller sends the body uncompressed.
    public static func compress(_ data: Data) -> Data? {
        guard !data.isEmpty else { return nil }

        let deflated = rawDeflate(data)
        guard let deflated, !deflated.isEmpty else { return nil }

        var out = Data([
            0x1f, 0x8b,  // magic
            0x08,        // DEFLATE
            0x00,        // no optional fields
            0x00, 0x00, 0x00, 0x00,  // mtime omitted: it would make an
                                     // otherwise byte-identical body differ
                                     // every run for no reader's benefit
            0x00,        // no extra-compression flags
            0xff,        // unknown OS
        ])
        out.append(deflated)
        appendLittleEndian(crc32(of: data), to: &out)
        appendLittleEndian(UInt32(truncatingIfNeeded: data.count), to: &out)
        return out
    }

    private static func rawDeflate(_ data: Data) -> Data? {
        // Worst case for incompressible input is slightly larger than the
        // source, so the destination has to have headroom or the encode
        // silently returns 0 and the check-in goes up uncompressed.
        let capacity = data.count + (data.count / 2) + 64
        var destination = Data(count: capacity)

        let written = destination.withUnsafeMutableBytes { dst -> Int in
            guard let dstBase = dst.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return data.withUnsafeBytes { src -> Int in
                guard let srcBase = src.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return compression_encode_buffer(
                    dstBase, capacity,
                    srcBase, data.count,
                    nil, COMPRESSION_ZLIB
                )
            }
        }

        guard written > 0 else { return nil }
        return destination.prefix(written)
    }

    private static func appendLittleEndian(_ value: UInt32, to data: inout Data) {
        data.append(contentsOf: [
            UInt8(truncatingIfNeeded: value),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 24),
        ])
    }

    private static let crcTable: [UInt32] = (0..<256).map { index -> UInt32 in
        var value = UInt32(index)
        for _ in 0..<8 {
            value = (value & 1 == 1) ? (0xEDB8_8320 ^ (value >> 1)) : (value >> 1)
        }
        return value
    }

    private static func crc32(of data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            crc = crcTable[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }
}
