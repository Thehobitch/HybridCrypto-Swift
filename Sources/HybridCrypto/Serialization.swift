import Foundation

extension HybridSignature {
    /// Simple length-prefixed binary encoding:
    /// [algorithm UTF-8 length (UInt32)] [algorithm] [message length (UInt32)] [message]
    /// [pqSignature length (UInt32)] [pqSignature] [classicalSignature length (UInt32)] [classicalSignature]
    public func encoded() -> Data {
        var data = Data()
        func append(_ value: Data) {
            var len = UInt32(value.count).bigEndian
            withUnsafeBytes(of: &len) { data.append(contentsOf: $0) }
            data.append(value)
        }
        append(Data(algorithm.utf8))
        append(message)
        append(pqSignature)
        append(classicalSignature)
        return data
    }

    public static func decoded(from data: Data) throws -> HybridSignature {
        var offset = 0
        func read() throws -> Data {
            guard offset + 4 <= data.count else { throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "truncated")) }
            let len = data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self).bigEndian }
            offset += 4
            guard offset + Int(len) <= data.count else { throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "truncated payload")) }
            let slice = data.subdata(in: offset..<(offset + Int(len)))
            offset += Int(len)
            return slice
        }
        let algo = String(data: try read(), encoding: .utf8) ?? ""
        let message = try read()
        let pq = try read()
        let classical = try read()
        return HybridSignature(pqSignature: pq, classicalSignature: classical, message: message, algorithm: algo)
    }
}
