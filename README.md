# SIWX-RS: Multi-Chain Sign-In with X Library

A Rust library for implementing Sign-In with X (SIWX) authentication across multiple blockchain networks, following the [EIP-4361](https://eips.ethereum.org/EIPS/eip-4361) standard.

## Features

- **Multi-chain support**: Ethereum and Solana (extensible to other chains)
- **EIP-4361 compliance**: Standard message format for authentication
- **Smart contract wallet support**: Designed for EOA and contract wallets
- **Backend agnostic**: Use any blockchain library (ethers-rs, alloy-rs, etc.)
- **Flexible signature verification**: Support for different signature formats
- **Public key abstraction**: Trait-based design for extensible public key support
- **Async/await support**: Modern Rust async patterns
- **Comprehensive validation**: Message, signature, and public key validation
- **Extensible architecture**: Easy to add new chains, signature types, and public key formats

## Supported Chains

- **Ethereum** (Mainnet & Testnets)
  - EIP-191 personal_sign signatures
  - EIP-1271 smart contract signatures
  - secp256k1 cryptography
- **Solana** (Mainnet & Testnets)
  - Ed25519 signatures
  - Base58 encoding

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
siwx-rs = { version = "0.1.0", features = ["full"] }
```

### Feature Flags

- `default`: Core functionality only
- `ethereum`: Ethereum-specific dependencies (alloy-primitives, alloy-json-abi)
- `solana`: Solana-specific dependencies (solana-sdk, bs58, ed25519-dalek)
- `full`: All features enabled

## Quick Start

### Basic Usage

```rust
use siwx_rs::prelude::*;

#[tokio::main]
async fn main() -> SiwxResult<()> {
    // Create a SIWX message for Ethereum
    let message = SiwxMessage::new_with_current_time(
        "example.com",
        "0x1234567890123456789012345678901234567890",
        "https://example.com/login",
        "1",
        SiwxMessage::generate_nonce(),
    )
    .with_statement("Sign in to Example App")
    .with_expiration_time(
        (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
    );

    // Get the message to sign
    let message_to_sign = message.message_to_sign()?;
    println!("Message to sign:\n{}", message_to_sign);

    // Create a verifier
    let verifier = VerifierFactory::ethereum();

    // Verify a signature (example)
    let signature = Signature::eip191(
        "0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "0x1234567890123456789012345678901234567890",
    );

    let public_key = PublicKeyFactory::ethereum("0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
    let is_valid = verifier.verify(&message, &signature, &public_key).await?;
    println!("Signature valid: {}", is_valid);

    Ok(())
}
```

### Ethereum Example

```rust
use siwx_rs::prelude::*;

// Create Ethereum SIWX message
let eth_message = SiwxMessage::new_with_chain(
    "example.com",
    "0x1234567890123456789012345678901234567890",
    "https://example.com/login",
    "1",
    chrono::Utc::now().to_rfc3339(),
    SiwxMessage::generate_nonce(),
    Chain::Ethereum,
)
.with_statement("Sign in to Example App")
.with_expiration_time(
    (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
);

// Get EIP-191 formatted message
let message_to_sign = eth_message.message_to_sign()?;

// Create verifier with default backend
let verifier = VerifierFactory::ethereum();
```

### Solana Example

```rust
use siwx_rs::prelude::*;

// Create Solana SIWX message
let sol_message = SiwxMessage::new_with_chain(
    "example.com",
    "11111111111111111111111111111112",
    "https://example.com/login",
    "1",
    chrono::Utc::now().to_rfc3339(),
    SiwxMessage::generate_nonce(),
    Chain::Solana,
)
.with_statement("Sign in to Example App");

// Get Solana formatted message
let message_to_sign = sol_message.message_to_sign()?;

// Create verifier with default backend
let verifier = VerifierFactory::solana();
```

## Message Format

The library generates messages following the EIP-4361 standard:

### Ethereum Format
```
example.com wants you to sign in with your Ethereum account:
0x1234567890123456789012345678901234567890

Sign in to Example App

URI: https://example.com/login
Version: 1
Chain ID: 1
Nonce: 12345678-1234-1234-1234-123456789012
Issued At: 2024-01-01T00:00:00Z
Expiration Time: 2024-01-01T01:00:00Z
```

### Solana Format
```
example.com wants you to sign in with your Solana account:
11111111111111111111111111111112

Sign in to Example App

URI: https://example.com/login
Version: 1
Chain ID: 101
Nonce: 12345678-1234-1234-1234-123456789012
Issued At: 2024-01-01T00:00:00Z
```

## Public Key Abstraction

The library provides a trait-based abstraction for public keys, making it easy to support different blockchain-specific public key formats and add new ones in the future.

### Using Public Keys

```rust
use siwx_rs::prelude::*;

// Create Ethereum public key
let eth_public_key = PublicKeyFactory::ethereum(
    "0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
);

// Create Solana public key
let sol_public_key = PublicKeyFactory::solana("11111111111111111111111111111112");

// Auto-detect public key type
let auto_detected = PublicKeyFactory::auto_detect("0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890")?;

// Chain-specific creation
let eth_for_chain = PublicKeyFactory::for_chain(
    "0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
    Chain::Ethereum
);
```

### Public Key Validation

```rust
// Validate public key format
eth_public_key.validate()?;

// Check signature type support
if eth_public_key.supports_signature_type(&SignatureType::Eip191) {
    println!("Supports EIP-191 signatures");
}

// Get address from public key
let address = eth_public_key.address()?;
```

### Extending for New Chains

To add support for a new blockchain, implement the `PublicKey` trait:

```rust
use siwx_rs::{PublicKey, Chain, SiwxError, SiwxResult, SignatureType};

struct BitcoinPublicKey {
    key: String,
}

impl PublicKey for BitcoinPublicKey {
    fn chain(&self) -> Chain {
        Chain::Bitcoin // You'd need to add this to the Chain enum
    }

    fn as_string(&self) -> String {
        self.key.clone()
    }

    fn as_bytes(&self) -> SiwxResult<Vec<u8>> {
        // Implement Bitcoin-specific decoding
        Ok(vec![])
    }

    fn validate(&self) -> SiwxResult<()> {
        // Implement Bitcoin-specific validation
        Ok(())
    }

    fn address(&self) -> SiwxResult<String> {
        // Implement Bitcoin address derivation
        Ok(self.key.clone())
    }

    fn supports_signature_type(&self, signature_type: &SignatureType) -> bool {
        matches!(signature_type, SignatureType::Bitcoin) // You'd need to add this
    }

    fn key_type(&self) -> &'static str {
        "secp256k1"
    }
}
```

## Signature Verification

### Using Default Backends

```rust
// Create verifier with default backend
let verifier = VerifierFactory::ethereum();

// Verify signature
let public_key = PublicKeyFactory::ethereum("0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
let is_valid = verifier.verify(&message, &signature, &public_key).await?;
```

### Custom Backend Implementation

```rust
use async_trait::async_trait;

struct CustomEthereumBackend;

#[async_trait]
impl SignatureVerifierBackend for CustomEthereumBackend {
    async fn verify(
        &self,
        message: &SiwxMessage,
        signature: &Signature,
        public_key: &dyn PublicKey,
    ) -> SiwxResult<bool> {
        // Your custom verification logic here
        // You can use ethers-rs, alloy-rs, or any other library
        Ok(true)
    }

    fn supported_chain(&self) -> Chain {
        Chain::Ethereum
    }

    fn supported_signature_types(&self) -> Vec<SignatureType> {
        vec![SignatureType::Eip191, SignatureType::Eip1271]
    }
}

// Use custom backend
let verifier = SignatureVerifier::new(Chain::Ethereum)
    .with_backend(Box::new(CustomEthereumBackend));
```

## Smart Contract Wallet Support

The library is designed to support smart contract wallets through EIP-1271:

```rust
// Create EIP-1271 signature for smart contract wallet
let signature = Signature::eip1271(
    "0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
    "0x1234567890123456789012345678901234567890", // Contract address
);

// Custom backend for EIP-1271 verification
struct Eip1271Backend;

#[async_trait]
impl SignatureVerifierBackend for Eip1271Backend {
    async fn verify(
        &self,
        message: &SiwxMessage,
        signature: &Signature,
        public_key: &dyn PublicKey,
    ) -> SiwxResult<bool> {
        // Call isValidSignature on the contract
        // This would typically involve an RPC call
        Ok(true)
    }

    fn supported_chain(&self) -> Chain {
        Chain::Ethereum
    }

    fn supported_signature_types(&self) -> Vec<SignatureType> {
        vec![SignatureType::Eip1271]
    }
}
```

## Message Validation

The library provides comprehensive message validation:

```rust
// Validate message format
message.validate()?;

// Check if message has expired
if message.is_expired()? {
    return Err(SiwxError::MessageExpired);
}

// Check if message is valid for signing
if !message.is_valid_for_signing()? {
    return Err(SiwxError::InvalidMessageFormat("Message not yet valid".into()));
}
```

## Error Handling

The library uses custom error types for better error handling:

```rust
use siwx_rs::SiwxError;

match result {
    Ok(_) => println!("Success"),
    Err(SiwxError::MessageExpired) => println!("Message has expired"),
    Err(SiwxError::InvalidSignature(msg)) => println!("Invalid signature: {}", msg),
    Err(SiwxError::VerificationFailed(msg)) => println!("Verification failed: {}", msg),
    Err(e) => println!("Other error: {}", e),
}
```

## Examples

Run the examples:

```bash
# Basic usage
cargo run --example basic_usage

# Public key abstraction example
cargo run --example public_key_usage

# With specific features
cargo run --example basic_usage --features ethereum
cargo run --example basic_usage --features solana
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Roadmap

- [ ] Support for more chains (Polygon, BSC, etc.)
- [ ] More signature types
- [ ] Web3 integration examples
- [ ] Performance optimizations
- [ ] More comprehensive documentation
- [ ] CLI tool for message generation and verification 