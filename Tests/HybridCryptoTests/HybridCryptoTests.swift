import XCTest
@testable import HybridCrypto
import CryptoKit

@available(iOS 26.0, macOS 26.0, macCatalyst 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
final class HybridCryptoTests: XCTestCase {
    func testLocalSignVerify() throws {
        let (ec, pq) = try HybridCrypto.generateKeyPair()
        let message = Data("hello hybrid".utf8)
        let sig = try HybridCrypto.sign(message: message, classicalKey: ec, pqKey: pq)
        let valid = try HybridCrypto.verify(sig, message: message,
                                            classicalPublic: ec.publicKey,
                                            pqPublic: pq.publicKey)
        XCTAssertTrue(valid)
    }

    func testSerializationRoundTrip() throws {
        let (ec, pq) = try HybridCrypto.generateKeyPair()
        let message = Data("serialize me".utf8)
        let sig = try HybridCrypto.sign(message: message, classicalKey: ec, pqKey: pq)
        let encoded = sig.encoded()
        let decoded = try HybridSignature.decoded(from: encoded)
        XCTAssertEqual(decoded.algorithm, sig.algorithm)
        XCTAssertEqual(decoded.message, sig.message)
        XCTAssertEqual(decoded.pqSignature, sig.pqSignature)
        XCTAssertEqual(decoded.classicalSignature, sig.classicalSignature)
    }

    func testLocalDriver() throws {
        let driver = LocalCryptoDriver()
        let handle = try driver.generateHybridKeyPair()
        let message = Data("driver path".utf8)
        let sig = try driver.hybridSign(identifier: handle.identifier, message: message)
        let valid = try driver.hybridVerify(classicalPublic: handle.classicalPublic,
                                            pqPublic: handle.pqPublic,
                                            signature: sig,
                                            message: message)
        XCTAssertTrue(valid)
    }
}
