# HybridCrypto-Swift

Hybrid cryptographic library for Swift using CryptoKit (ECDSA-P256 + ML-DSA-65).

## Design Goals
- **Efficiency**: Thin hot path, minimal allocations, hardware-accelerated where available.
- **Simplicity**: Small API surface. Local path is direct; drivers are optional.

## Requirements
- iOS 26+ / macOS 26+ (or equivalent) for CryptoKit ML-DSA support.
- Swift 6+.

## Usage
```swift
import HybridCrypto

// Local path
let (ecKey, pqKey) = try HybridCrypto.generateKeyPair()
let message = Data("payload".utf8)
let signature = try HybridCrypto.sign(message: message, classicalKey: ecKey, pqKey: pqKey)
let valid = try HybridCrypto.verify(signature, message: message,
                                    classicalPublic: ecKey.publicKey,
                                    pqPublic: pqKey.publicKey)
```

## Driver Path
Optional `CryptoDriver` protocol for HSM / remote backends. `NShieldRESTDriver` is a stub.

## License
CC-BY-4.0 (as requested in source). Consider MIT or Apache-2.0 for production use.

## Status
Initial implementation. Contributions welcome for:
- Local driver implementation
- Serialization
- Tests
- Additional hybrid combinations
- Real nShield / HSM backend
