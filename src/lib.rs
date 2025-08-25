//! Sign-In with X (SIWX) - Multi-chain authentication library
//!
//! This library provides a unified interface for blockchain authentication
//! supporting Ethereum and Solana chains, following the EIP-4361 standard.
//!
//! ## Features
//!
//! - **Multi-chain support**: Ethereum and Solana
//! - **EIP-4361 compliance**: Standard message format for authentication
//! - **Smart contract wallet support**: Designed for EOA and contract wallets
//! - **Backend agnostic**: Use any blockchain library (ethers-rs, alloy-rs, etc.)
//! - **Flexible signature verification**: Support for different signature formats
//!
//! ## Usage
//!
//! ```rust
//! use siwx_rs::{SiwxMessage, Chain, SignatureVerifier};
//!
//! // Create a SIWX message
//! let message = SiwxMessage::new(
//!     "example.com",
//!     "0x1234567890123456789012345678901234567890",
//!     "https://example.com/login",
//!     "1",
//!     "2024-01-01T00:00:00Z",
//!     "nonce123"
//! );
//!
//! // Generate message to sign
//! let message_to_sign = message.to_string();
//!
//! // Verify signature (implementation depends on your backend)
//! // let verifier = SignatureVerifier::new(Chain::Ethereum);
//! // let is_valid = verifier.verify(&message, &signature).await?;
//! ```

pub mod backend;
pub mod chain;
pub mod error;
pub mod message;
pub mod public_key;
pub mod signature;
pub mod utils;
pub mod verifier;

pub use chain::Chain;
pub use error::{SiwxError, SiwxResult};
pub use message::SiwxMessage;
#[cfg(feature = "ethereum")]
pub use public_key::EthereumPublicKey;
#[cfg(feature = "solana")]
pub use public_key::SolanaPublicKey;
#[cfg(not(feature = "solana"))]
pub use public_key::{PublicKey, PublicKeyEnum, PublicKeyFactory};
#[cfg(feature = "solana")]
pub use public_key::{
    PublicKey, PublicKeyEnum, PublicKeyFactory, SolanaPublicKey as _SolanaPublicKeyMarker,
};
pub use signature::{Signature, SignatureType};
pub use verifier::SignatureVerifier;

/// Re-export commonly used types
pub mod prelude {
    #[cfg(feature = "ethereum")]
    pub use super::EthereumPublicKey;
    #[cfg(feature = "solana")]
    pub use super::SolanaPublicKey;
    pub use super::{
        Chain, PublicKey, PublicKeyEnum, PublicKeyFactory, Signature, SignatureType,
        SignatureVerifier, SiwxError, SiwxMessage, SiwxResult,
    };
}
