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
public enum KeyExport {
    public static func encodePublic(classical: Data, pq: Data) -> Data {
        var data = Data()
        func append(_ value: Data) {
            var len = UInt32(value.count).bigEndian
            withUnsafeBytes(of: &len) { data.append(contentsOf: $0) }
            data.append(value)
        }
        append(classical)
        append(pq)
        return data
    }

    public static func decodePublic(from data: Data) throws -> (classical: Data, pq: Data) {
        var offset = 0
        func read() throws -> Data {
            guard offset + 4 <= data.count else {
                throw CryptoError.encodingFailed
            }
            let len = data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self).bigEndian }
            offset += 4
            guard offset + Int(len) <= data.count else {
                throw CryptoError.encodingFailed
            }
            let slice = data.subdata(in: offset..<(offset + Int(len)))
            offset += Int(len)
            return slice
        }
        let classical = try read()
        let pq = try read()
        return (classical, pq)
    }
}
