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
- `ethereum`: Ethereum-specific dependencies (Alloy meta crate)
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

    // Verify a signature (example). For Ethereum EIP-191, provide the signer address.
    // You may pass either an Ethereum address (recommended) or an uncompressed
    // secp256k1 public key (65 bytes, 0x04-prefixed) as the "public key" parameter.
    // Verification is address-based and recovers the signer from the signature.
    let signature = Signature::eip191(
        "0x<65-byte-signature-hex-rsv>",
        "0x1234567890123456789012345678901234567890",
    );

    // Pass the signer address as the key (address-only flow)
    let public_key = PublicKeyFactory::ethereum(
        "0x1234567890123456789012345678901234567890"
    )?;
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

// Create verifier with default backend (supports EIP-191 and EIP-1271)
let verifier = VerifierFactory::ethereum();
// EIP-191 address-only flow: pass the address as the key
let addr_key = PublicKeyFactory::ethereum(
    "0x1234567890123456789012345678901234567890"
)?;
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

### Solana Smart Accounts (PDAs) and Squads Compatibility

The Solana backend supports smart accounts implemented as Program Derived Accounts (PDAs). Since PDAs cannot sign, SIWX must be signed by an authority key associated with the PDA. The verifier then:

- Validates the SIWX message address equals the PDA derived from the provided seeds and program id
- Verifies the Ed25519 signature against the authority public key

To use this flow, provide the following in the `Signature` metadata:

- `program_id`: the program id that owns the PDA (base58 string)
- `pda_seeds`: JSON array of base58-encoded seed byte arrays used to derive the PDA (e.g., `["<SEED1_BASE58>", "<SEED2_BASE58>"]`). Do not use base64. If you have raw bytes, encode each with base58 (e.g., `bs58::encode(&seed_bytes).into_string()`).

Example using an authority key for a PDA:

```rust
use siwx_rs::prelude::*;

// Assume you already know the PDA and its program id/seeds used to derive it
let program_id_b58 = "<PROGRAM_ID_BASE58>";
let pda_address_b58 = "<PDA_ADDRESS_BASE58>";
let pda_seeds_json = serde_json::json!(["<SEED1_BASE58>", "<SEED2_BASE58>"]).to_string();

// Build SIWX message addressed to the PDA
let message = SiwxMessage::new_with_chain(
    "example.com",
    pda_address_b58.to_string(),
    "https://example.com/login",
    "1",
    chrono::Utc::now().to_rfc3339(),
    SiwxMessage::generate_nonce(),
    Chain::Solana,
);

// Authority signs the message (ed25519). `authority_pubkey_b58` is base58 of the authority key
let sig_b58 = "<AUTHORITY_SIGNATURE_BASE58>";
let authority_pubkey_b58 = "<AUTHORITY_PUBKEY_BASE58>";

let signature = Signature::ed25519(sig_b58, authority_pubkey_b58)
    .with_metadata("program_id", program_id_b58.to_string())
    .with_metadata("pda_seeds", pda_seeds_json);

let public_key = PublicKeyFactory::solana(pda_address_b58);
let verifier = VerifierFactory::solana();
let is_valid = verifier.verify(&message, &signature, &public_key).await?;
```

Squads (SquadsX) vaults are PDAs. This flow is compatible with Squads as long as you use an authority key (e.g., a member key or relayer key) to sign off-chain and pass the correct `program_id` and `pda_seeds`. The verifier will confirm the PDA derivation and the authority signature.

Notes:

- This library does not (yet) enforce on-chain multisig policy (e.g., membership/threshold checks) for Squads. If you need that, you can layer an optional RPC-backed check to validate that the authority is authorized for the given vault before accepting the signature.
- PDA derivation uses `solana_sdk::Pubkey::find_program_address` with the provided seeds; no RPC calls are made during verification.
- For more about Squads, see the official docs: [Squads Protocol documentation](https://docs.squads.so/).

#### Example: derive a Squads PDA and build metadata

```rust
use bs58;
use hex;
use siwx_rs::prelude::*;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

// Replace with the real Squads v4 Program ID
let program_id = Pubkey::from_str("<SQUADS_V4_PROGRAM_ID>").unwrap();

// Replace with actual Squads seeds per their documentation.
// Here we show two generic seed buffers as an example.
let seed1: Vec<u8> = b"multisig".to_vec();
let seed2: Vec<u8> = hex::decode("<MULTISIG_ID_HEX>").unwrap();

// Derive the PDA address
let (pda, _bump) = Pubkey::find_program_address(&[&seed1, &seed2], &program_id);
let pda_address_b58 = pda.to_string();

// Prepare pda_seeds metadata as base58-encoded seed buffers
let pda_seeds_json = serde_json::json!([
    bs58::encode(&seed1).into_string(),
    bs58::encode(&seed2).into_string(),
])
.to_string();

// Build the SIWX message addressed to the PDA
let message = SiwxMessage::new_with_chain(
    "example.com",
    pda_address_b58.clone(),
    "https://example.com/login",
    "1",
    chrono::Utc::now().to_rfc3339(),
    SiwxMessage::generate_nonce(),
    Chain::Solana,
);

// Authority signs the message off-chain (produce sig_b58, authority_pubkey_b58)
let signature = Signature::ed25519(sig_b58, authority_pubkey_b58)
    .with_metadata("program_id", program_id.to_string())
    .with_metadata("pda_seeds", pda_seeds_json);

let public_key = PublicKeyFactory::solana(pda_address_b58);
let verifier = VerifierFactory::solana();
let is_valid = verifier.verify(&message, &signature, &public_key).await?;
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

// Create Ethereum public key (uncompressed 65-byte secp256k1, 0x04 + 64 bytes)
let eth_public_key = PublicKeyFactory::ethereum("0x04<128-hex-chars-of-uncompressed-pubkey>");

// Create Solana public key
let sol_public_key = PublicKeyFactory::solana("11111111111111111111111111111112");

// Auto-detect public key type
let auto_detected = PublicKeyFactory::auto_detect("0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890")?;

// Chain-specific creation
let eth_for_chain = PublicKeyFactory::for_chain(
    "0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
    Chain::Ethereum
)?;
```

### Public Key Validation

```rust
// Validate public key format
eth_public_key.validate()?;

// Check signature type support
if eth_public_key.supports_signature_type(&SignatureType::Eip191) {
    println!("Supports EIP-191 signatures");
}

// Get address from public key (requires that the key was constructed with a known address,
// or a future version of this library adds on-the-fly derivation)
let address = eth_public_key.address()?; // may error if address derivation is not available
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
// Create verifier with default backend (Ethereum supports EIP-191 and EIP-1271)
let verifier = VerifierFactory::ethereum();

// Verify signature (Ethereum supports passing an address or uncompressed secp256k1 pubkey)
// Address-only recommended:
let public_key = PublicKeyFactory::ethereum("0x1234567890123456789012345678901234567890")?;
let is_valid = verifier.verify(&message, &signature, &public_key).await?;
```

### Ethereum Backend Configuration

- The default Ethereum backend supports:
  - EIP-191 (personal_sign) with 65-byte signatures (r|s|v). The verifier recovers the signer
    address from the signature and compares it to `message.address`/`signature.signer`.
  - EIP-1271 (smart contract validation) by calling `isValidSignature` via RPC.
- RPC URL resolution order for EIP-1271:
  - Explicit URL if you build the backend with one
  - `ETHEREUM_RPC_URL` env var
  - `ETH_RPC_URL` env var
  - Fallback: a public Infura mainnet endpoint

To set an explicit RPC URL, construct the verifier with the backend manually (feature `ethereum` must be enabled):

```rust
use siwx_rs::prelude::*;
#[cfg(feature = "ethereum")]
use siwx_rs::backend::ethereum::EthereumSecp256k1Verifier;

let verifier = SignatureVerifier::new(Chain::Ethereum)
    .with_backend(Box::new(EthereumSecp256k1Verifier::with_rpc_url("https://mainnet.infura.io/v3/<KEY>")));
```

Or set an environment variable (no code changes needed):

```bash
export ETHEREUM_RPC_URL="https://mainnet.infura.io/v3/<KEY>"
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

    fn supported_signature_types(&self) -> Vec<SignatureType> { vec![SignatureType::Eip191, SignatureType::Eip1271] }
}

// Use custom backend
let verifier = SignatureVerifier::new(Chain::Ethereum)
    .with_backend(Box::new(CustomEthereumBackend));
```

## Smart Contract Wallet Support (EIP-1271)

The default Ethereum backend validates EIP-1271 signatures by calling `isValidSignature` on the contract specified by `signature.signer`. Requirements:

- `message.address` must equal the contract address (prevents cross-contract replay).
- `signature.signer` must be the contract address.
- `signature.signature` must be a 0x-prefixed even-length hex string (arbitrary length per contract).
- No public key is required for EIP-1271; the provided "public key" parameter is ignored by the verifier.

Example:

```rust
use siwx_rs::prelude::*;

let message = SiwxMessage::new(
    "example.com",
    "0xContractAddress...", // same as the contract address below
    "https://example.com/login",
    "1",
    "2024-01-01T00:00:00Z",
    "nonce123",
);

let signature = Signature::eip1271(
    "0x<contract-defined-signature-hex>",
    "0xContractAddress...",
);

// You may pass an address as the key; it is not used by EIP-1271 verification
let dummy_key = PublicKeyFactory::ethereum(contract_address)?;
let verifier = VerifierFactory::ethereum();
let ok = verifier.verify(&message, &signature, &dummy_key).await?;
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
