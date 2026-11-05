import Foundation
import CryptoKit

/// Local in-process implementation of CryptoDriver.
/// Uses the static HybridCrypto path under the hood.
/// Suitable for testing and as a reference implementation.
@available(iOS 26.0, macOS 26.0, macCatalyst 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
public final class LocalCryptoDriver: CryptoDriver {
    public let name = "Local"

    private var keys: [String: (classical: P256.Signing.PrivateKey, pq: MLDSA65.PrivateKey)] = [:]

    public init() {}

    public func generateHybridKeyPair() throws -> HybridKeyHandle {
        let (classical, pq) = try HybridCrypto.generateKeyPair()
        let id = UUID().uuidString
        keys[id] = (classical, pq)
        return HybridKeyHandle(
            identifier: id,
            classicalPublic: classical.publicKey.rawRepresentation,
            pqPublic: pq.publicKey.rawRepresentation
        )
    }

    public func hybridSign(identifier: String, message: Data) throws -> HybridSignature {
        guard let pair = keys[identifier] else {
            throw CryptoError.keyNotFound
        }
        return try HybridCrypto.sign(message: message, classicalKey: pair.classical, pqKey: pair.pq)
    }

    public func hybridVerify(classicalPublic: Data, pqPublic: Data,
                             signature: HybridSignature, message: Data) throws -> Bool {
        let classical = try P256.Signing.PublicKey(rawRepresentation: classicalPublic)
        let pq = try MLDSA65.PublicKey(rawRepresentation: pqPublic)
        return try HybridCrypto.verify(signature, message: message,
                                       classicalPublic: classical,
                                       pqPublic: pq)
    }
}
