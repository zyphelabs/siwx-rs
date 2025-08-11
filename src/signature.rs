use crate::{Chain, SiwxError, SiwxResult};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Signature types supported by the library
#[typeshare::typeshare]
#[typeshare::typeshare]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum SignatureType {
    /// EIP-191 personal_sign (Ethereum)
    Eip191,
    /// EIP-1271 smart contract signature (Ethereum)
    Eip1271,
    /// Ed25519 signature (Solana)
    Ed25519,
    /// Custom signature type
    Custom(String),
}

impl SignatureType {
    /// Get the signature type for a given chain
    pub fn for_chain(chain: Chain) -> Self {
        match chain {
            Chain::Ethereum | Chain::EthereumTestnet => SignatureType::Eip191,
            Chain::Solana | Chain::SolanaTestnet => SignatureType::Ed25519,
        }
    }

    /// Check if this signature type supports smart contract wallets
    pub fn supports_smart_contracts(&self) -> bool {
        matches!(self, SignatureType::Eip1271)
    }
}

impl fmt::Display for SignatureType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureType::Eip191 => write!(f, "EIP-191"),
            SignatureType::Eip1271 => write!(f, "EIP-1271"),
            SignatureType::Ed25519 => write!(f, "Ed25519"),
            SignatureType::Custom(s) => write!(f, "Custom({})", s),
        }
    }
}

/// Signature data structure
#[typeshare::typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// The signature type
    pub signature_type: SignatureType,
    /// The signature bytes (hex encoded for Ethereum, base58 for Solana)
    pub signature: String,
    /// The public key or address that signed the message
    pub signer: String,
    /// Additional metadata for the signature
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

impl Signature {
    /// Create a new signature
    pub fn new(
        signature_type: SignatureType,
        signature: impl Into<String>,
        signer: impl Into<String>,
    ) -> Self {
        Self {
            signature_type,
            signature: signature.into(),
            signer: signer.into(),
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Create an EIP-191 signature
    pub fn eip191(signature: impl Into<String>, signer: impl Into<String>) -> Self {
        Self::new(SignatureType::Eip191, signature, signer)
    }

    /// Create an EIP-1271 signature
    pub fn eip1271(signature: impl Into<String>, signer: impl Into<String>) -> Self {
        Self::new(SignatureType::Eip1271, signature, signer)
    }

    /// Create an Ed25519 signature
    pub fn ed25519(signature: impl Into<String>, signer: impl Into<String>) -> Self {
        Self::new(SignatureType::Ed25519, signature, signer)
    }

    /// Add metadata to the signature
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Validate the signature format
    pub fn validate_format(&self) -> SiwxResult<()> {
        match self.signature_type {
            SignatureType::Eip191 => self.validate_ethereum_eip191_format(),
            SignatureType::Eip1271 => self.validate_eip1271_format(),
            SignatureType::Ed25519 => self.validate_solana_format(),
            SignatureType::Custom(_) => Ok(()), // Custom types are not validated
        }
    }

    /// Validate Ethereum signature format
    fn validate_ethereum_eip191_format(&self) -> SiwxResult<()> {
        // EIP-191 signatures must be 65 bytes (r,s,v) and hex-encoded
        if !self.signature.starts_with("0x") {
            return Err(SiwxError::InvalidSignature(
                "Ethereum signature must start with 0x".into(),
            ));
        }

        let hex_part = &self.signature[2..];
        if hex_part.len() != 130 {
            return Err(SiwxError::InvalidSignature(format!(
                "Ethereum signature must be 65 bytes (130 hex chars), got {}",
                hex_part.len()
            )));
        }

        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SiwxError::InvalidSignature(
                "Ethereum signature must be valid hex".into(),
            ));
        }

        Ok(())
    }

    /// Validate EIP-1271 signature format (contract-defined). We only require 0x-prefixed valid hex
    /// and even length, but do NOT enforce 65-byte length.
    fn validate_eip1271_format(&self) -> SiwxResult<()> {
        if !self.signature.starts_with("0x") {
            return Err(SiwxError::InvalidSignature(
                "Ethereum signature must start with 0x".into(),
            ));
        }
        let hex_part = &self.signature[2..];
        if hex_part.is_empty() || hex_part.len() % 2 != 0 {
            return Err(SiwxError::InvalidSignature(
                "Ethereum signature hex must be non-empty and even length".into(),
            ));
        }
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SiwxError::InvalidSignature(
                "Ethereum signature must be valid hex".into(),
            ));
        }
        Ok(())
    }

    /// Validate Solana signature format
    fn validate_solana_format(&self) -> SiwxResult<()> {
        // Solana signatures should be base58-encoded
        if self.signature.is_empty() {
            return Err(SiwxError::InvalidSignature(
                "Solana signature cannot be empty".into(),
            ));
        }

        // Basic base58 validation (alphanumeric without 0, O, I, l)
        if !self
            .signature
            .chars()
            .all(|c| c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l'))
        {
            return Err(SiwxError::InvalidSignature(
                "Solana signature must be valid base58".into(),
            ));
        }

        Ok(())
    }

    /// Get the signature as bytes
    pub fn as_bytes(&self) -> SiwxResult<Vec<u8>> {
        match self.signature_type {
            SignatureType::Eip191 | SignatureType::Eip1271 => {
                // Remove 0x prefix and decode hex
                let hex_part = self.signature.strip_prefix("0x").unwrap_or(&self.signature);
                hex::decode(hex_part).map_err(|e| {
                    SiwxError::InvalidSignature(format!("Invalid hex encoding: {}", e))
                })
            }
            SignatureType::Ed25519 => {
                // Decode base58
                #[cfg(feature = "solana")]
                {
                    use bs58;
                    bs58::decode(&self.signature).into_vec().map_err(|e| {
                        SiwxError::InvalidSignature(format!("Invalid base58 encoding: {}", e))
                    })
                }
                #[cfg(not(feature = "solana"))]
                {
                    Err(SiwxError::InvalidSignature(
                        "Solana feature not enabled".into(),
                    ))
                }
            }
            SignatureType::Custom(_) => Err(SiwxError::InvalidSignature(
                "Cannot convert custom signature to bytes".into(),
            )),
        }
    }

    /// Get the recovery ID for Ethereum signatures
    pub fn recovery_id(&self) -> SiwxResult<u8> {
        match self.signature_type {
            SignatureType::Eip191 => {
                let bytes = self.as_bytes()?;
                if bytes.len() != 65 {
                    return Err(SiwxError::InvalidSignature(
                        "Ethereum EIP-191 signature must be 65 bytes".into(),
                    ));
                }
                Ok(bytes[64])
            }
            SignatureType::Eip1271 => Err(SiwxError::InvalidSignature(
                "Recovery ID is not available for EIP-1271 signatures".into(),
            )),
            _ => Err(SiwxError::InvalidSignature(
                "Recovery ID only available for EIP-191 Ethereum signatures".into(),
            )),
        }
    }

    /// Get the r and s components for Ethereum signatures
    pub fn r_s_components(&self) -> SiwxResult<(Vec<u8>, Vec<u8>)> {
        match self.signature_type {
            SignatureType::Eip191 => {
                let bytes = self.as_bytes()?;
                if bytes.len() != 65 {
                    return Err(SiwxError::InvalidSignature(
                        "Ethereum EIP-191 signature must be 65 bytes".into(),
                    ));
                }
                let r = bytes[..32].to_vec();
                let s = bytes[32..64].to_vec();
                Ok((r, s))
            }
            SignatureType::Eip1271 => Err(SiwxError::InvalidSignature(
                "R and S components are not available for EIP-1271 signatures".into(),
            )),
            _ => Err(SiwxError::InvalidSignature(
                "R and S components only available for EIP-191 Ethereum signatures".into(),
            )),
        }
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} signature by {}: {}",
            self.signature_type, self.signer, self.signature
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_creation() {
        let sig = Signature::eip191(
            "0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "0x1234567890123456789012345678901234567890",
        );

        assert_eq!(sig.signature_type, SignatureType::Eip191);
        assert_eq!(sig.signer, "0x1234567890123456789012345678901234567890");
    }

    #[test]
    fn test_ethereum_signature_validation() {
        // Valid signature
        let valid_sig = Signature::eip191(
            "0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "0x1234567890123456789012345678901234567890",
        );
        assert!(valid_sig.validate_format().is_ok());

        // Invalid signature (wrong length)
        let invalid_sig = Signature::eip191(
            "0x123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
            "0x1234567890123456789012345678901234567890",
        );
        assert!(invalid_sig.validate_format().is_err());

        // Invalid signature (no 0x prefix)
        let invalid_sig2 = Signature::eip191(
            "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "0x1234567890123456789012345678901234567890",
        );
        assert!(invalid_sig2.validate_format().is_err());
    }

    #[test]
    fn test_signature_type_for_chain() {
        assert_eq!(
            SignatureType::for_chain(Chain::Ethereum),
            SignatureType::Eip191
        );
        assert_eq!(
            SignatureType::for_chain(Chain::Solana),
            SignatureType::Ed25519
        );
    }

    #[test]
    fn test_smart_contract_support() {
        assert!(!SignatureType::Eip191.supports_smart_contracts());
        assert!(SignatureType::Eip1271.supports_smart_contracts());
        assert!(!SignatureType::Ed25519.supports_smart_contracts());
    }

    #[test]
    fn test_eip1271_signature_format_validation() {
        // Valid: 0x-prefixed, even-length hex
        let sig = Signature::eip1271("0x1234abcdef", "0x1234567890123456789012345678901234567890");
        assert!(sig.validate_format().is_ok());

        // Invalid: not 0x-prefixed
        let sig = Signature::eip1271("1234abcdef", "0x1234567890123456789012345678901234567890");
        assert!(sig.validate_format().is_err());

        // Invalid: odd-length hex
        let sig = Signature::eip1271("0x123", "0x1234567890123456789012345678901234567890");
        assert!(sig.validate_format().is_err());
    }

    #[test]
    fn test_helpers_error_on_eip1271() {
        // EIP-1271 signatures can be arbitrary length hex; ensure helpers error clearly
        let sig = Signature::eip1271("0xdeadbeef", "0x1234567890123456789012345678901234567890");
        let err1 = sig.recovery_id().unwrap_err();
        let err2 = sig.r_s_components().unwrap_err();
        match err1 {
            SiwxError::InvalidSignature(msg) => {
                assert!(msg.contains("not available for EIP-1271"))
            }
            _ => panic!("unexpected error type"),
        }
        match err2 {
            SiwxError::InvalidSignature(msg) => {
                assert!(msg.contains("not available for EIP-1271"))
            }
            _ => panic!("unexpected error type"),
        }
    }
}
