// SPDX-FileCopyrightText: © 2026 Hybrid Crypto Example
// SPDX-License-Identifier: CC-BY-4.0
//
// This software is licensed under the Creative Commons Attribution 4.0 International License.
// You may share and adapt it for any purpose, even commercially, as long as you give appropriate credit.
// Full license: https://creativecommons.org/licenses/by/4.0/
//
// Note: Creative Commons licenses are generally recommended for content rather than source code.
// For production software, consider a standard open-source license such as MIT or Apache-2.0.
// This file uses CC BY 4.0 as requested.

import Foundation
import CryptoKit

// MARK: - Design Requirements
/// Core requirements for this hybrid cryptographic software:
///
/// 1. Efficiency
///    - Minimize allocations and copies of key material and signatures.
///    - Prefer fixed-size operations and avoid unnecessary intermediate structures.
///    - Keep the hot path (sign/verify) as thin as possible.
///    - Support hardware-accelerated paths (CryptoKit, nShield FPGA/PQC) without extra abstraction cost.
///
/// 2. Simplicity
///    - Small, obvious API surface.
///    - One clear way to do hybrid sign/verify/keygen.
///    - Drivers are optional; the default path stays local and direct.
///    - No configuration ceremony for common use cases.
///    - Code should be readable in a single pass.

// MARK: - Core Types (kept minimal)
public struct HybridSignature {
    public let pqSignature: Data
    public let classicalSignature: Data
    public let message: Data
    public let algorithm: String

    public var combined: Data { pqSignature + classicalSignature }

    public init(pqSignature: Data, classicalSignature: Data, message: Data, algorithm: String) {
        self.pqSignature = pqSignature
        self.classicalSignature = classicalSignature
        self.message = message
        self.algorithm = algorithm
    }
}

public struct HybridKeyHandle {
    public let identifier: String
    public let classicalPublic: Data
    public let pqPublic: Data

    public init(identifier: String, classicalPublic: Data, pqPublic: Data) {
        self.identifier = identifier
        self.classicalPublic = classicalPublic
        self.pqPublic = pqPublic
    }
}

// MARK: - Simple Direct API (default, most efficient path)
/// Prefer this for local use. Zero driver overhead.
@available(iOS 26.0, macOS 26.0, macCatalyst 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
public struct HybridCrypto {
    public static let algorithm = "ECDSA-P256+ML-DSA-65"
    private let driver: any CryptoDriver

    /// Driver-backed operations are explicitly selected; static operations stay local.
    public init(driver: any CryptoDriver) {
        self.driver = driver
    }

    public func generateKeyPair() throws -> HybridKeyHandle {
        try driver.generateHybridKeyPair()
    }

    public func sign(key: HybridKeyHandle, message: Data) throws -> HybridSignature {
        try driver.hybridSign(identifier: key.identifier, message: message)
    }

    /// Verify locally with trusted public keys, including signatures from remote drivers.
    public func verify(_ signature: HybridSignature, message: Data,
                       key: HybridKeyHandle) throws -> Bool {
        try Self.verify(signature, message: message,
                        classicalPublic: P256.Signing.PublicKey(rawRepresentation: key.classicalPublic),
                        pqPublic: MLDSA65.PublicKey(rawRepresentation: key.pqPublic))
    }

    /// Generate a hybrid key pair (P-256 ECDSA + ML-DSA-65).
    public static func generateKeyPair() throws -> (classical: P256.Signing.PrivateKey, pq: MLDSA65.PrivateKey) {
        (P256.Signing.PrivateKey(), try MLDSA65.PrivateKey())
    }

    /// Hybrid sign. Both signatures are produced; verification requires both.
    public static func sign(message: Data,
                            classicalKey: P256.Signing.PrivateKey,
                            pqKey: MLDSA65.PrivateKey) throws -> HybridSignature {
        let pqSig = try pqKey.signature(for: message)
        let ecSig = try classicalKey.signature(for: message).rawRepresentation
        return HybridSignature(
            pqSignature: pqSig,
            classicalSignature: ecSig,
            message: message,
            algorithm: Self.algorithm
        )
    }

    /// Hybrid verify. Returns true only if both classical and PQC signatures are valid.
    public static func verify(_ signature: HybridSignature,
                              message: Data,
                              classicalPublic: P256.Signing.PublicKey,
                              pqPublic: MLDSA65.PublicKey) throws -> Bool {
        guard signature.algorithm == Self.algorithm,
              signature.message == message,
              !signature.pqSignature.isEmpty,
              signature.classicalSignature.count == 64 else { return false }
        let isValidPQ = pqPublic.isValidSignature(signature.pqSignature, for: message)
        let ecSig = try P256.Signing.ECDSASignature(rawRepresentation: signature.classicalSignature)
        let isValidEC = classicalPublic.isValidSignature(ecSig, for: message)
        return isValidPQ && isValidEC
    }
}

// MARK: - Optional Driver Protocol (for HSM / remote backends)
/// Use only when you need a remote HSM. Kept minimal to preserve simplicity.
public protocol CryptoDriver {
    func generateHybridKeyPair() throws -> HybridKeyHandle
    func hybridSign(identifier: String, message: Data) throws -> HybridSignature
    func hybridVerify(classicalPublic: Data, pqPublic: Data, signature: HybridSignature, message: Data) throws -> Bool
    var name: String { get }
}

// MARK: - Explicit backend errors
public enum CryptoDriverError: Error {
    case invalidEndpoint
    case backendNotImplemented
}

// MARK: - nShield REST Driver
/// Interface placeholder. No remote operation succeeds until a real backend is wired in.
public final class NShieldRESTDriver: CryptoDriver {
    public let name = "nShield-REST"
    private let baseURL: URL

    public init(baseURL: URL) throws {
        guard baseURL.scheme?.lowercased() == "https",
              let host = baseURL.host, !host.isEmpty,
              baseURL.user == nil, baseURL.password == nil else {
            throw CryptoDriverError.invalidEndpoint
        }
        self.baseURL = baseURL
    }

    public func generateHybridKeyPair() throws -> HybridKeyHandle {
        throw CryptoDriverError.backendNotImplemented
    }

    public func hybridSign(identifier: String, message: Data) throws -> HybridSignature {
        throw CryptoDriverError.backendNotImplemented
    }

    public func hybridVerify(classicalPublic: Data, pqPublic: Data,
                             signature: HybridSignature, message: Data) throws -> Bool {
        throw CryptoDriverError.backendNotImplemented
    }
}

// MARK: - Implemented local capabilities
public enum SupportedAlgorithms {
    public static let classical = ["ECDSA-P256"]
    public static let postQuantum = ["ML-DSA-65"]
    public static let hybrid = ["ECDSA-P256+ML-DSA-65"]
}

// Usage (requires the platform versions declared on HybridCrypto):
// let (ecKey, pqKey) = try HybridCrypto.generateKeyPair()
// let message = Data("payload".utf8)
// let signature = try HybridCrypto.sign(message: message, classicalKey: ecKey, pqKey: pqKey)
// let valid = try HybridCrypto.verify(signature, message: message,
//                                     classicalPublic: ecKey.publicKey,
//                                     pqPublic: pqKey.publicKey)
// Remote driver construction now throws:
// let driver = try NShieldRESTDriver(baseURL: URL(string: "https://hsm.example")!)
// let crypto = HybridCrypto(driver: driver)
// Backend operations currently throw CryptoDriverError.backendNotImplemented.
