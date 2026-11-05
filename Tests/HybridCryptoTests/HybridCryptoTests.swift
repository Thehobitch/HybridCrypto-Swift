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

    func testLocalDriverKeyNotFound() throws {
        let driver = LocalCryptoDriver()
        let message = Data("missing key".utf8)
        XCTAssertThrowsError(try driver.hybridSign(identifier: "nonexistent", message: message)) { error in
            XCTAssertEqual(error as? CryptoError, CryptoError.keyNotFound)
        }
    }

    func testTamperedSignatureFails() throws {
        let (ec, pq) = try HybridCrypto.generateKeyPair()
        let message = Data("original".utf8)
        var sig = try HybridCrypto.sign(message: message, classicalKey: ec, pqKey: pq)
        // Tamper with classical signature
        var classical = sig.classicalSignature
        classical[0] ^= 0xFF
        sig = HybridSignature(
            pqSignature: sig.pqSignature,
            classicalSignature: classical,
            message: sig.message,
            algorithm: sig.algorithm
        )
        let valid = try HybridCrypto.verify(sig, message: message,
                                            classicalPublic: ec.publicKey,
                                            pqPublic: pq.publicKey)
        XCTAssertFalse(valid)
    }

    func testWrongMessageFails() throws {
        let (ec, pq) = try HybridCrypto.generateKeyPair()
        let message = Data("correct".utf8)
        let sig = try HybridCrypto.sign(message: message, classicalKey: ec, pqKey: pq)
        let wrong = Data("wrong".utf8)
        let valid = try HybridCrypto.verify(sig, message: wrong,
                                            classicalPublic: ec.publicKey,
                                            pqPublic: pq.publicKey)
        XCTAssertFalse(valid)
    }

    func testKeyHelpers() throws {
        let (ec, pq) = try HybridCrypto.generateKeyPair()
        let handle = HybridKeyHandle(
            identifier: "test-id",
            classicalPublic: ec.publicKey.rawRepresentation,
            pqPublic: pq.publicKey.rawRepresentation
        )

        let encoded = try KeyExport.encodePublic(classical: handle.classicalPublic, pq: handle.pqPublic)
        let (decodedClassical, decodedPQ) = try KeyExport.decodePublic(from: encoded)
        XCTAssertEqual(decodedClassical, handle.classicalPublic)
        XCTAssertEqual(decodedPQ, handle.pqPublic)

        let reconstructed = try HybridKeyHandle.fromConcatenatedPublic(
            identifier: handle.identifier,
            data: handle.concatenatedPublic
        )
        XCTAssertEqual(reconstructed.classicalPublic, handle.classicalPublic)
        XCTAssertEqual(reconstructed.pqPublic, handle.pqPublic)

        XCTAssertFalse(handle.publicDescription.isEmpty)
    }

    func testKeyExportRejectsEmpty() {
        XCTAssertThrowsError(try KeyExport.encodePublic(classical: Data(), pq: Data([0x01])))
        XCTAssertThrowsError(try KeyExport.encodePublic(classical: Data([0x01]), pq: Data()))
    }
}
