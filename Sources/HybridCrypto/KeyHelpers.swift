import Foundation
import CryptoKit

/// Helpers for exporting and working with hybrid key material.
@available(iOS 26.0, macOS 26.0, macCatalyst 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
extension HybridKeyHandle {
    /// Concatenated public key material for simple storage or transmission.
    /// Format: [classicalPublic (64 bytes for P-256)] + [pqPublic]
    public var concatenatedPublic: Data {
        classicalPublic + pqPublic
    }

    /// Human-readable description of the public keys (hex, truncated).
    public var publicDescription: String {
        let classicalHex = classicalPublic.prefix(16).map { String(format: "%02x", $0) }.joined()
        let pqHex = pqPublic.prefix(16).map { String(format: "%02x", $0) }.joined()
        return "HybridKey(\(identifier.prefix(8))…) EC:\(classicalHex)… PQ:\(pqHex)…"
    }

    /// Attempt to reconstruct a HybridKeyHandle from concatenated public data.
    /// Note: identifier must be supplied separately; this only restores public material.
    public static func fromConcatenatedPublic(
        identifier: String,
        data: Data,
        classicalLength: Int = 64
    ) throws -> HybridKeyHandle {
        guard data.count > classicalLength else {
            throw CryptoError.encodingFailed
        }
        let classical = data.prefix(classicalLength)
        let pq = data.dropFirst(classicalLength)
        return HybridKeyHandle(
            identifier: identifier,
            classicalPublic: Data(classical),
            pqPublic: Data(pq)
        )
    }
}

/// Utility for encoding public keys in a simple length-prefixed format.
/// Format: [UInt32 EC length][EC bytes][UInt32 PQ length][PQ bytes].
/// Lengths are big-endian. This framing does not identify the algorithm.
public enum KeyExport {
    /// Throws if either key is empty or exceeds UInt32.max.
    public static func encodePublic(
        classical: Data,
        pq: Data
    ) throws -> Data {
        guard !classical.isEmpty,
              !pq.isEmpty,
              let ecLength = UInt32(exactly: classical.count),
              let pqLength = UInt32(exactly: pq.count) else {
            throw CryptoError.encodingFailed
        }

        var result = Data()

        func append(_ value: Data, length: UInt32) {
            var bigEndianLength = length.bigEndian
            withUnsafeBytes(of: &bigEndianLength) {
                result.append(contentsOf: $0)
            }
            result.append(value)
        }

        append(classical, length: ecLength)
        append(pq, length: pqLength)
        return result
    }

    /// Checks framing only; key validity requires CryptoKit parsing.
    public static func decodePublic(
        from data: Data
    ) throws -> (classical: Data, pq: Data) {
        try data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            var offset = 0

            func read() throws -> Data {
                guard bytes.count - offset >= 4 else {
                    throw CryptoError.encodingFailed
                }

                // Byte-wise decoding avoids alignment assumptions.
                var encodedLength: UInt32 = 0
                for _ in 0..<4 {
                    encodedLength = (encodedLength << 8) | UInt32(bytes[offset])
                    offset += 1
                }

                let length = Int(encodedLength)
                guard length > 0, bytes.count - offset >= length else {
                    throw CryptoError.encodingFailed
                }

                let slice = Data(bytes[offset..<(offset + length)])
                offset += length
                return slice
            }

            let classical = try read()
            let pq = try read()

            // Ensure no trailing bytes remain.
            guard offset == bytes.count else {
                throw CryptoError.encodingFailed
            }

            return (classical, pq)
        }
    }
}
