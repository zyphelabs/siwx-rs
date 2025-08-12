use crate::{Chain, SiwxError, SiwxResult};
#[cfg(feature = "ethereum")]
use alloy::primitives::{keccak256, Address};
use serde::{Deserialize, Serialize};
use std::fmt;
#[cfg(feature = "ethereum")]
use std::str::FromStr;

/// Trait for blockchain-specific public key implementations
pub trait PublicKey: Send + Sync + fmt::Debug + fmt::Display {
    /// Get the chain this public key belongs to
    fn chain(&self) -> Chain;

    /// Get the public key as a string representation
    fn as_string(&self) -> String;

    /// Get the public key as bytes
    fn as_bytes(&self) -> SiwxResult<Vec<u8>>;

    /// Validate the public key format
    fn validate(&self) -> SiwxResult<()>;

    /// Get the address derived from this public key
    fn address(&self) -> SiwxResult<String>;

    /// Check if this public key can be used for the given signature type
    fn supports_signature_type(&self, signature_type: &crate::SignatureType) -> bool;

    /// Get the key type identifier
    fn key_type(&self) -> &'static str;
}

/// Ethereum address wrapper implementing `PublicKey` for address-only flows
#[cfg(feature = "ethereum")]
#[typeshare::typeshare]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumAddress {
    /// The address (Alloy Address)
    #[typeshare(skip)]
    pub address: Address,
}

#[cfg(feature = "ethereum")]
impl EthereumAddress {
    pub fn new(address: impl Into<String>) -> SiwxResult<Self> {
        let addr = address.into();
        Address::from_str(addr.as_str())
            .map(|parsed| Self { address: parsed })
            .map_err(|e| SiwxError::InvalidAddress(format!("Invalid ethereum address: {e}")))
    }
}

#[cfg(feature = "ethereum")]
impl PublicKey for EthereumAddress {
    fn chain(&self) -> Chain {
        Chain::Ethereum
    }

    fn as_string(&self) -> String {
        format!("0x{:x}", self.address)
    }

    fn as_bytes(&self) -> SiwxResult<Vec<u8>> {
        Ok(self.address.0.to_vec())
    }

    fn validate(&self) -> SiwxResult<()> {
        Ok(())
    }

    fn address(&self) -> SiwxResult<String> {
        Ok(self.as_string())
    }

    fn supports_signature_type(&self, signature_type: &crate::SignatureType) -> bool {
        matches!(
            signature_type,
            crate::SignatureType::Eip191 | crate::SignatureType::Eip1271
        )
    }

    fn key_type(&self) -> &'static str {
        "address"
    }
}

#[cfg(feature = "ethereum")]
impl fmt::Display for EthereumAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

/// Unified Ethereum key that can be either an address or a public key
#[cfg(feature = "ethereum")]
#[typeshare::typeshare]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EthereumKey {
    Address(EthereumAddress),
    PublicKey(EthereumPublicKey),
}

#[cfg(feature = "ethereum")]
impl EthereumKey {
    pub fn from_string(key: impl Into<String>) -> SiwxResult<Self> {
        let s = key.into();
        let s_norm = if s.starts_with("0x") {
            s
        } else {
            format!("0x{}", s)
        };
        if s_norm.len() == 42 {
            Ok(EthereumKey::Address(EthereumAddress::new(s_norm)?))
        } else {
            Ok(EthereumKey::PublicKey(EthereumPublicKey::new(s_norm)))
        }
    }
}

#[cfg(feature = "ethereum")]
impl PublicKey for EthereumKey {
    fn chain(&self) -> Chain {
        Chain::Ethereum
    }

    fn as_string(&self) -> String {
        match self {
            EthereumKey::Address(a) => a.as_string(),
            EthereumKey::PublicKey(pk) => pk.as_string(),
        }
    }

    fn as_bytes(&self) -> SiwxResult<Vec<u8>> {
        match self {
            EthereumKey::Address(a) => a.as_bytes(),
            EthereumKey::PublicKey(pk) => pk.as_bytes(),
        }
    }

    fn validate(&self) -> SiwxResult<()> {
        match self {
            EthereumKey::Address(a) => a.validate(),
            EthereumKey::PublicKey(pk) => pk.validate(),
        }
    }

    fn address(&self) -> SiwxResult<String> {
        match self {
            EthereumKey::Address(a) => a.address(),
            EthereumKey::PublicKey(pk) => pk.address(),
        }
    }

    fn supports_signature_type(&self, signature_type: &crate::SignatureType) -> bool {
        match self {
            EthereumKey::Address(a) => a.supports_signature_type(signature_type),
            EthereumKey::PublicKey(pk) => pk.supports_signature_type(signature_type),
        }
    }

    fn key_type(&self) -> &'static str {
        match self {
            EthereumKey::Address(a) => a.key_type(),
            EthereumKey::PublicKey(pk) => pk.key_type(),
        }
    }
}

#[cfg(feature = "ethereum")]
impl fmt::Display for EthereumKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EthereumKey::Address(a) => write!(f, "{}", a),
            EthereumKey::PublicKey(pk) => write!(f, "{}", pk),
        }
    }
}

/// Ethereum public key implementation
#[cfg(feature = "ethereum")]
#[typeshare::typeshare]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumPublicKey {
    /// The public key in hex format (with or without 0x prefix)
    pub key: String,
    /// The derived address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

#[cfg(feature = "ethereum")]
impl EthereumPublicKey {
    /// Create a new Ethereum public key from hex string
    pub fn new(key: impl Into<String>) -> Self {
        let key = key.into();
        Self {
            key: Self::normalize_hex(&key),
            address: None,
        }
    }

    /// Create a new Ethereum public key with pre-computed address
    pub fn with_address(key: impl Into<String>, address: impl Into<String>) -> Self {
        let key = key.into();
        Self {
            key: Self::normalize_hex(&key),
            address: Some(address.into()),
        }
    }

    /// Normalize hex string to include 0x prefix
    fn normalize_hex(hex: &str) -> String {
        if hex.starts_with("0x") {
            hex.to_string()
        } else {
            format!("0x{}", hex)
        }
    }

    /// Derive Ethereum address from public key (keccak256 of uncompressed pubkey without prefix)
    fn derive_address(&self) -> SiwxResult<String> {
        if let Some(ref addr) = self.address {
            return Ok(addr.clone());
        }

        let bytes = self.as_bytes()?;
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return Err(SiwxError::InvalidPublicKey(
                "Ethereum public key must be 65 bytes uncompressed (0x04 + 64 bytes)".into(),
            ));
        }
        let hash = keccak256(&bytes[1..]);
        let addr = Address::from_slice(&hash[12..]);
        Ok(format!("0x{:x}", addr))
    }
}

#[cfg(feature = "ethereum")]
impl PublicKey for EthereumPublicKey {
    fn chain(&self) -> Chain {
        Chain::Ethereum
    }

    fn as_string(&self) -> String {
        self.key.clone()
    }

    fn as_bytes(&self) -> SiwxResult<Vec<u8>> {
        let hex_part = self.key.strip_prefix("0x").unwrap_or(&self.key);
        hex::decode(hex_part)
            .map_err(|e| SiwxError::InvalidPublicKey(format!("Invalid hex encoding: {}", e)))
    }

    fn validate(&self) -> SiwxResult<()> {
        // Validate hex format
        let hex_part = self.key.strip_prefix("0x").unwrap_or(&self.key);
        if hex_part.len() != 130 {
            return Err(SiwxError::InvalidPublicKey(format!(
                "Ethereum public key must be 65 bytes (130 hex chars), got {}",
                hex_part.len()
            )));
        }

        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SiwxError::InvalidPublicKey(
                "Ethereum public key must be valid hex".into(),
            ));
        }

        Ok(())
    }

    fn address(&self) -> SiwxResult<String> {
        self.derive_address()
    }

    fn supports_signature_type(&self, signature_type: &crate::SignatureType) -> bool {
        matches!(
            signature_type,
            crate::SignatureType::Eip191 | crate::SignatureType::Eip1271
        )
    }

    fn key_type(&self) -> &'static str {
        "secp256k1"
    }
}

#[cfg(feature = "ethereum")]
impl fmt::Display for EthereumPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.key)
    }
}

/// Solana public key implementation
#[cfg(feature = "solana")]
#[typeshare::typeshare]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaPublicKey {
    /// The public key in base58 format
    pub key: String,
    /// The derived address (same as key for Solana)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

#[cfg(feature = "solana")]
impl SolanaPublicKey {
    /// Create a new Solana public key from base58 string
    pub fn new(key: impl Into<String>) -> Self {
        let key = key.into();
        Self {
            key: key.clone(),
            address: Some(key),
        }
    }

    /// Create a new Solana public key with custom address
    pub fn with_address(key: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            address: Some(address.into()),
        }
    }
}

#[cfg(feature = "solana")]
impl PublicKey for SolanaPublicKey {
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn as_string(&self) -> String {
        self.key.clone()
    }

    fn as_bytes(&self) -> SiwxResult<Vec<u8>> {
        #[cfg(feature = "solana")]
        {
            use bs58;
            bs58::decode(&self.key)
                .into_vec()
                .map_err(|e| SiwxError::InvalidPublicKey(format!("Invalid base58 encoding: {}", e)))
        }
        #[cfg(not(feature = "solana"))]
        {
            Err(SiwxError::InvalidPublicKey(
                "Solana feature not enabled".into(),
            ))
        }
    }

    fn validate(&self) -> SiwxResult<()> {
        if self.key.is_empty() {
            return Err(SiwxError::InvalidPublicKey(
                "Solana public key cannot be empty".into(),
            ));
        }

        // Basic base58 validation (alphanumeric without 0, O, I, l)
        if !self
            .key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l'))
        {
            return Err(SiwxError::InvalidPublicKey(
                "Solana public key must be valid base58".into(),
            ));
        }

        // Validate length (Solana public keys are typically 32 bytes = ~44 base58 chars)
        if self.key.len() < 32 || self.key.len() > 44 {
            return Err(SiwxError::InvalidPublicKey(format!(
                "Solana public key length should be between 32-44 chars, got {}",
                self.key.len()
            )));
        }

        Ok(())
    }

    fn address(&self) -> SiwxResult<String> {
        Ok(self.address.clone().unwrap_or_else(|| self.key.clone()))
    }

    fn supports_signature_type(&self, signature_type: &crate::SignatureType) -> bool {
        matches!(signature_type, crate::SignatureType::Ed25519)
    }

    fn key_type(&self) -> &'static str {
        "ed25519"
    }
}

#[cfg(feature = "solana")]
impl fmt::Display for SolanaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.key)
    }
}

/// Enum wrapper for different public key types
#[typeshare::typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum PublicKeyEnum {
    /// Ethereum key (address or uncompressed public key)
    #[cfg(feature = "ethereum")]
    Ethereum(EthereumKey),
    /// Solana public key
    #[cfg(feature = "solana")]
    Solana(SolanaPublicKey),
}

impl PublicKeyEnum {
    /// Create an Ethereum public key
    #[cfg(feature = "ethereum")]
    pub fn ethereum(key: impl Into<String>) -> SiwxResult<Self> {
        Ok(Self::Ethereum(EthereumKey::from_string(key)?))
    }

    /// Create a Solana public key
    #[cfg(feature = "solana")]
    pub fn solana(key: impl Into<String>) -> Self {
        Self::Solana(SolanaPublicKey::new(key))
    }

    /// Create a public key from string based on chain
    pub fn from_string(key: impl Into<String>, chain: Chain) -> SiwxResult<Self> {
        match chain {
            Chain::Ethereum | Chain::EthereumTestnet => {
                #[cfg(feature = "ethereum")]
                {
                    Self::ethereum(key)
                }
                #[cfg(not(feature = "ethereum"))]
                {
                    Err(SiwxError::InvalidPublicKey(
                        "Ethereum feature not enabled".into(),
                    ))
                }
            }
            Chain::Solana | Chain::SolanaTestnet => {
                #[cfg(feature = "solana")]
                {
                    Ok(Self::solana(key))
                }
                #[cfg(not(feature = "solana"))]
                {
                    Err(SiwxError::InvalidPublicKey(
                        "Solana feature not enabled".into(),
                    ))
                }
            }
        }
    }

    /// Try to detect the chain from the key format
    pub fn detect_chain(key: &str) -> Option<Chain> {
        if cfg!(feature = "ethereum")
            && key.starts_with("0x")
            && (key.len() == 132 || key.len() == 42)
        {
            return Some(Chain::Ethereum);
        }
        if cfg!(feature = "solana")
            && key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l'))
            && key.len() >= 32
            && key.len() <= 44
        {
            return Some(Chain::Solana);
        }
        None
    }
}

#[cfg(all(feature = "ethereum", feature = "solana"))]
impl PublicKey for PublicKeyEnum {
    fn chain(&self) -> Chain {
        match self {
            PublicKeyEnum::Ethereum(_) => Chain::Ethereum,
            PublicKeyEnum::Solana(_) => Chain::Solana,
        }
    }

    fn as_string(&self) -> String {
        match self {
            PublicKeyEnum::Ethereum(pk) => pk.as_string(),
            PublicKeyEnum::Solana(pk) => pk.as_string(),
        }
    }

    fn as_bytes(&self) -> SiwxResult<Vec<u8>> {
        match self {
            PublicKeyEnum::Ethereum(pk) => pk.as_bytes(),
            PublicKeyEnum::Solana(pk) => pk.as_bytes(),
        }
    }

    fn validate(&self) -> SiwxResult<()> {
        match self {
            PublicKeyEnum::Ethereum(pk) => pk.validate(),
            PublicKeyEnum::Solana(pk) => pk.validate(),
        }
    }

    fn address(&self) -> SiwxResult<String> {
        match self {
            PublicKeyEnum::Ethereum(pk) => pk.address(),
            PublicKeyEnum::Solana(pk) => pk.address(),
        }
    }

    fn supports_signature_type(&self, signature_type: &crate::SignatureType) -> bool {
        match self {
            PublicKeyEnum::Ethereum(pk) => pk.supports_signature_type(signature_type),
            PublicKeyEnum::Solana(pk) => pk.supports_signature_type(signature_type),
        }
    }

    fn key_type(&self) -> &'static str {
        match self {
            PublicKeyEnum::Ethereum(pk) => pk.key_type(),
            PublicKeyEnum::Solana(pk) => pk.key_type(),
        }
    }
}

#[cfg(all(not(feature = "ethereum"), feature = "solana"))]
impl PublicKey for PublicKeyEnum {
    fn chain(&self) -> Chain {
        match self {
            PublicKeyEnum::Solana(_) => Chain::Solana,
        }
    }

    fn as_string(&self) -> String {
        match self {
            PublicKeyEnum::Solana(pk) => pk.as_string(),
        }
    }

    fn as_bytes(&self) -> SiwxResult<Vec<u8>> {
        match self {
            PublicKeyEnum::Solana(pk) => pk.as_bytes(),
        }
    }

    fn validate(&self) -> SiwxResult<()> {
        match self {
            PublicKeyEnum::Solana(pk) => pk.validate(),
        }
    }

    fn address(&self) -> SiwxResult<String> {
        match self {
            PublicKeyEnum::Solana(pk) => pk.address(),
        }
    }

    fn supports_signature_type(&self, signature_type: &crate::SignatureType) -> bool {
        match self {
            PublicKeyEnum::Solana(pk) => pk.supports_signature_type(signature_type),
        }
    }

    fn key_type(&self) -> &'static str {
        match self {
            PublicKeyEnum::Solana(pk) => pk.key_type(),
        }
    }
}

#[cfg(all(feature = "ethereum", feature = "solana"))]
impl fmt::Display for PublicKeyEnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicKeyEnum::Ethereum(pk) => write!(f, "{}", pk),
            PublicKeyEnum::Solana(pk) => write!(f, "{}", pk),
        }
    }
}

#[cfg(all(feature = "ethereum", not(feature = "solana")))]
impl PublicKey for PublicKeyEnum {
    fn chain(&self) -> Chain {
        match self {
            PublicKeyEnum::Ethereum(_) => Chain::Ethereum,
        }
    }

    fn as_string(&self) -> String {
        match self {
            PublicKeyEnum::Ethereum(pk) => pk.as_string(),
        }
    }

    fn as_bytes(&self) -> SiwxResult<Vec<u8>> {
        match self {
            PublicKeyEnum::Ethereum(pk) => pk.as_bytes(),
        }
    }

    fn validate(&self) -> SiwxResult<()> {
        match self {
            PublicKeyEnum::Ethereum(pk) => pk.validate(),
        }
    }

    fn address(&self) -> SiwxResult<String> {
        match self {
            PublicKeyEnum::Ethereum(pk) => pk.address(),
        }
    }

    fn supports_signature_type(&self, signature_type: &crate::SignatureType) -> bool {
        match self {
            PublicKeyEnum::Ethereum(pk) => pk.supports_signature_type(signature_type),
        }
    }

    fn key_type(&self) -> &'static str {
        match self {
            PublicKeyEnum::Ethereum(pk) => pk.key_type(),
        }
    }
}

#[cfg(all(feature = "ethereum", not(feature = "solana")))]
impl fmt::Display for PublicKeyEnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicKeyEnum::Ethereum(pk) => write!(f, "{}", pk),
        }
    }
}
#[cfg(all(not(feature = "ethereum"), feature = "solana"))]
impl fmt::Display for PublicKeyEnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicKeyEnum::Solana(pk) => write!(f, "{}", pk),
        }
    }
}

#[cfg(feature = "ethereum")]
impl From<EthereumKey> for PublicKeyEnum {
    fn from(pk: EthereumKey) -> Self {
        Self::Ethereum(pk)
    }
}

#[cfg(feature = "solana")]
impl From<SolanaPublicKey> for PublicKeyEnum {
    fn from(pk: SolanaPublicKey) -> Self {
        Self::Solana(pk)
    }
}

/// Factory for creating public keys
pub struct PublicKeyFactory;

impl PublicKeyFactory {
    /// Create a public key for Ethereum
    #[cfg(feature = "ethereum")]
    pub fn ethereum(key: impl Into<String>) -> SiwxResult<PublicKeyEnum> {
        PublicKeyEnum::ethereum(key)
    }

    /// Create a public key for Solana
    #[cfg(feature = "solana")]
    pub fn solana(key: impl Into<String>) -> PublicKeyEnum {
        PublicKeyEnum::solana(key)
    }

    /// Create a public key for a specific chain
    pub fn for_chain(key: impl Into<String>, chain: Chain) -> SiwxResult<PublicKeyEnum> {
        PublicKeyEnum::from_string(key, chain)
    }

    /// Try to create a public key by auto-detecting the chain
    pub fn auto_detect(key: impl Into<String>) -> SiwxResult<PublicKeyEnum> {
        let key_str = key.into();
        match PublicKeyEnum::detect_chain(&key_str) {
            Some(chain) => PublicKeyEnum::from_string(key_str, chain),
            None => Err(SiwxError::InvalidPublicKey(
                "Could not detect chain from public key format".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "ethereum", feature = "solana"))]
    use super::{Chain, EthereumAddress, EthereumPublicKey, SolanaPublicKey};
    #[cfg(all(feature = "ethereum", not(feature = "solana")))]
    use super::{Chain, EthereumPublicKey};
    #[cfg(all(not(feature = "ethereum"), feature = "solana"))]
    use super::{Chain, SolanaPublicKey};
    use super::{PublicKey, PublicKeyEnum, PublicKeyFactory};

    #[cfg(feature = "ethereum")]
    #[test]
    fn test_ethereum_public_key_creation() {
        let pk = EthereumPublicKey::new("0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
        assert_eq!(pk.chain(), Chain::Ethereum);
        assert_eq!(pk.key_type(), "secp256k1");
        assert!(pk.validate().is_ok());
    }

    #[cfg(feature = "solana")]
    #[test]
    fn test_solana_public_key_creation() {
        let pk = SolanaPublicKey::new("11111111111111111111111111111112");
        assert_eq!(pk.chain(), Chain::Solana);
        assert_eq!(pk.key_type(), "ed25519");
        assert!(pk.validate().is_ok());
    }

    #[cfg(all(feature = "ethereum", feature = "solana"))]
    #[test]
    fn test_public_key_enum() {
        let eth_pk = PublicKeyEnum::ethereum("0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890").unwrap();
        assert_eq!(eth_pk.chain(), Chain::Ethereum);

        let sol_pk = PublicKeyEnum::solana("11111111111111111111111111111112");
        assert_eq!(sol_pk.chain(), Chain::Solana);
    }

    #[cfg(all(feature = "ethereum", feature = "solana"))]
    #[test]
    fn test_chain_detection() {
        assert_eq!(
            PublicKeyEnum::detect_chain("0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"),
            Some(Chain::Ethereum)
        );
        assert_eq!(
            PublicKeyEnum::detect_chain("0x1234567890123456789012345678901234567890"),
            Some(Chain::Ethereum)
        );
        assert_eq!(
            PublicKeyEnum::detect_chain("11111111111111111111111111111112"),
            Some(Chain::Solana)
        );
        assert_eq!(PublicKeyEnum::detect_chain("invalid"), None);
    }

    #[cfg(all(not(feature = "ethereum"), feature = "solana"))]
    #[test]
    fn test_chain_detection_solana_only() {
        assert_eq!(
            PublicKeyEnum::detect_chain("11111111111111111111111111111112"),
            Some(Chain::Solana)
        );
        assert_eq!(PublicKeyEnum::detect_chain("invalid"), None);
    }

    #[cfg(all(feature = "ethereum", feature = "solana"))]
    #[test]
    fn test_factory() {
        let pk = PublicKeyFactory::ethereum("0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890").unwrap();
        assert_eq!(pk.chain(), Chain::Ethereum);

        let pk = PublicKeyFactory::solana("11111111111111111111111111111112");
        assert_eq!(pk.chain(), Chain::Solana);
    }

    #[cfg(all(feature = "ethereum", feature = "solana"))]
    #[test]
    fn test_signature_type_support() {
        let eth_pk = EthereumPublicKey::new("0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
        assert!(eth_pk.supports_signature_type(&crate::SignatureType::Eip191));
        assert!(eth_pk.supports_signature_type(&crate::SignatureType::Eip1271));
        assert!(!eth_pk.supports_signature_type(&crate::SignatureType::Ed25519));

        let eth_addr = EthereumAddress::new("0x1234567890123456789012345678901234567890").unwrap();
        assert!(eth_addr.supports_signature_type(&crate::SignatureType::Eip191));
        assert!(eth_addr.supports_signature_type(&crate::SignatureType::Eip1271));
        assert!(!eth_addr.supports_signature_type(&crate::SignatureType::Ed25519));

        let sol_pk = SolanaPublicKey::new("11111111111111111111111111111112");
        assert!(!sol_pk.supports_signature_type(&crate::SignatureType::Eip191));
        assert!(!sol_pk.supports_signature_type(&crate::SignatureType::Eip1271));
        assert!(sol_pk.supports_signature_type(&crate::SignatureType::Ed25519));
    }
}
