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

// Serialization
let encoded = signature.encoded()
let decoded = try HybridSignature.decoded(from: encoded)

// Local driver path
let driver = LocalCryptoDriver()
let handle = try driver.generateHybridKeyPair()
let driverSig = try driver.hybridSign(identifier: handle.identifier, message: message)
```

## Driver Path
Optional `CryptoDriver` protocol for HSM / remote backends.  
`LocalCryptoDriver` is a full in-process implementation.  
`NShieldRESTDriver` remains a stub.

## Testing
```bash
swift test
```

## License
MIT License. See [LICENSE](LICENSE).

## Status
Core local path, local driver, basic serialization, and tests are in place.  
Contributions welcome for:
- Real nShield / HSM backend
- Additional hybrid combinations
- Key storage / export helpers
- More comprehensive test vectors
