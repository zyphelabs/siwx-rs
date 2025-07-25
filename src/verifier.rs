use crate::{Chain, SiwxError, SiwxMessage, SiwxResult, Signature, SignatureType, PublicKey};
use async_trait::async_trait;
use std::fmt;

/// Trait for signature verification backends
#[async_trait]
pub trait SignatureVerifierBackend: Send + Sync {
    /// Verify a signature for a given message
    async fn verify(
        &self,
        message: &SiwxMessage,
        signature: &Signature,
        public_key: &dyn PublicKey,
    ) -> SiwxResult<bool>;

    /// Get the chain this backend supports
    fn supported_chain(&self) -> Chain;

    /// Get the signature types this backend supports
    fn supported_signature_types(&self) -> Vec<SignatureType>;
}

/// Main signature verifier that can work with any backend
pub struct SignatureVerifier {
    chain: Chain,
    backends: Vec<Box<dyn SignatureVerifierBackend>>,
}

impl SignatureVerifier {
    /// Create a new signature verifier for a specific chain
    pub fn new(chain: Chain) -> Self {
        Self {
            chain,
            backends: Vec::new(),
        }
    }

    /// Add a verification backend
    pub fn with_backend(mut self, backend: Box<dyn SignatureVerifierBackend>) -> Self {
        self.backends.push(backend);
        self
    }

    /// Verify a signature using available backends
    pub async fn verify(
        &self,
        message: &SiwxMessage,
        signature: &Signature,
        public_key: &dyn PublicKey,
    ) -> SiwxResult<bool> {
        // Validate message and signature first
        message.validate()?;
        signature.validate_format()?;
        public_key.validate()?;

        // Check if message has expired
        if message.is_expired()? {
            return Err(SiwxError::MessageExpired);
        }

        // Check if message is valid for signing
        if !message.is_valid_for_signing()? {
            return Err(SiwxError::InvalidMessageFormat(
                "Message is not yet valid for signing".into(),
            ));
        }

        // Check if public key supports the signature type
        if !public_key.supports_signature_type(&signature.signature_type) {
            return Err(SiwxError::VerificationFailed(
                "Public key does not support the signature type".into(),
            ));
        }

        // Try each backend until one succeeds
        for backend in &self.backends {
            if backend.supported_chain() == self.chain
                && backend.supported_signature_types().contains(&signature.signature_type)
            {
                match backend.verify(message, signature, public_key).await {
                    Ok(is_valid) => return Ok(is_valid),
                    Err(e) => {
                        // Log the error but continue to next backend
                        eprintln!("Backend verification failed: {}", e);
                        continue;
                    }
                }
            }
        }

        Err(SiwxError::VerificationFailed(
            "No suitable backend found for verification".into(),
        ))
    }

    /// Get the chain this verifier is configured for
    pub fn chain(&self) -> Chain {
        self.chain
    }

    /// Get the number of backends
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }
}

impl fmt::Debug for SignatureVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureVerifier")
            .field("chain", &self.chain)
            .field("backend_count", &self.backends.len())
            .finish()
    }
}

/// Default Ethereum verifier using secp256k1
pub struct EthereumSecp256k1Verifier;

#[async_trait]
impl SignatureVerifierBackend for EthereumSecp256k1Verifier {
    async fn verify(
        &self,
        message: &SiwxMessage,
        signature: &Signature,
        public_key: &dyn PublicKey,
    ) -> SiwxResult<bool> {
        match signature.signature_type {
            SignatureType::Eip191 => self.verify_eip191(message, signature, public_key).await,
            SignatureType::Eip1271 => {
                Err(SiwxError::VerificationFailed(
                    "EIP-1271 verification not implemented in this backend".into(),
                ))
            }
            _ => Err(SiwxError::VerificationFailed(
                "Unsupported signature type for Ethereum".into(),
            )),
        }
    }

    fn supported_chain(&self) -> Chain {
        Chain::Ethereum
    }

    fn supported_signature_types(&self) -> Vec<SignatureType> {
        vec![SignatureType::Eip191]
    }
}

impl EthereumSecp256k1Verifier {
    /// Verify EIP-191 personal_sign signature
    async fn verify_eip191(
        &self,
        message: &SiwxMessage,
        signature: &Signature,
        public_key: &dyn PublicKey,
    ) -> SiwxResult<bool> {
        #[cfg(feature = "ethereum")]
        {
            use secp256k1::{ecdsa::RecoverableSignature, Message, PublicKey as Secp256k1PublicKey, Secp256k1};
            use sha3::{Digest, Keccak256};

            // Get the message to sign
            let message_text = message.message_to_sign()?;
            
            // Create EIP-191 personal sign message format
            let eth_signed_message = format!("\x19Ethereum Signed Message:\n{}{}", message_text.len(), message_text);
            
            // Hash the message
            let message_hash = Keccak256::digest(eth_signed_message.as_bytes());
            
            // Parse the signature
            let signature_bytes = signature.as_bytes()?;
            if signature_bytes.len() != 65 {
                return Err(SiwxError::InvalidSignature(
                    "Ethereum signature must be exactly 65 bytes".into(),
                ));
            }
            
            // Extract r, s, and v components
            let mut r_s_bytes = [0u8; 64];
            r_s_bytes.copy_from_slice(&signature_bytes[0..64]);
            let v = signature_bytes[64];
            
            // Normalize v to recovery ID (should be 27 or 28, but might be 0 or 1)
            let recovery_id = if v >= 27 { v - 27 } else { v };
            
            // Create secp256k1 context
            let secp = Secp256k1::new();
            
            // Create message from hash
            let message_obj = Message::from_slice(&message_hash)
                .map_err(|e| SiwxError::CryptoError(format!("Invalid message hash: {}", e)))?;
            
            // Create recoverable signature
            let recoverable_sig = RecoverableSignature::from_compact(&r_s_bytes, secp256k1::ecdsa::RecoveryId::from_i32(recovery_id as i32).unwrap())
                .map_err(|e| SiwxError::InvalidSignature(format!("Invalid signature format: {}", e)))?;
            
            // Recover the public key
            let recovered_pubkey = secp.recover_ecdsa(&message_obj, &recoverable_sig)
                .map_err(|e| SiwxError::CryptoError(format!("Public key recovery failed: {}", e)))?;
            
            // Convert public key to address (keccak256 of uncompressed pubkey bytes, take last 20 bytes)
            let pubkey_bytes = recovered_pubkey.serialize_uncompressed();
            let pubkey_hash = Keccak256::digest(&pubkey_bytes[1..]);  // Skip the 0x04 prefix
            let recovered_address = format!("0x{}", hex::encode(&pubkey_hash[12..]));
            
            // Compare with expected signer address (normalize case)
            Ok(recovered_address.to_lowercase() == signature.signer.to_lowercase())
        }
        #[cfg(not(feature = "ethereum"))]
        {
            Err(SiwxError::VerificationFailed(
                "Ethereum feature not enabled".into(),
            ))
        }
    }
}

/// Default Solana verifier using ed25519
pub struct SolanaEd25519Verifier;

#[async_trait]
impl SignatureVerifierBackend for SolanaEd25519Verifier {
    async fn verify(
        &self,
        message: &SiwxMessage,
        signature: &Signature,
        public_key: &dyn PublicKey,
    ) -> SiwxResult<bool> {
        match signature.signature_type {
            SignatureType::Ed25519 => self.verify_ed25519(message, signature, public_key).await,
            _ => Err(SiwxError::VerificationFailed(
                "Unsupported signature type for Solana".into(),
            )),
        }
    }

    fn supported_chain(&self) -> Chain {
        Chain::Solana
    }

    fn supported_signature_types(&self) -> Vec<SignatureType> {
        vec![SignatureType::Ed25519]
    }
}

impl SolanaEd25519Verifier {
    /// Verify Ed25519 signature
    async fn verify_ed25519(
        &self,
        message: &SiwxMessage,
        signature: &Signature,
        public_key: &dyn PublicKey,
    ) -> SiwxResult<bool> {
        #[cfg(feature = "solana")]
        {
            use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey, Verifier};
            use bs58;

            // Get the message to sign
            let message_text = message.message_to_sign()?;
            let message_bytes = message_text.as_bytes();
            
            // Parse the signature from base58
            let signature_bytes = bs58::decode(&signature.signature)
                .into_vec()
                .map_err(|e| SiwxError::InvalidSignature(format!("Invalid base58 signature: {}", e)))?;
            
            if signature_bytes.len() != 64 {
                return Err(SiwxError::InvalidSignature(
                    "Ed25519 signature must be exactly 64 bytes".into(),
                ));
            }
            
            // Create Ed25519 signature from bytes
            let ed25519_sig = Ed25519Signature::from_bytes(&signature_bytes.try_into().unwrap());
            
            // Parse the public key
            let public_key_bytes = public_key.as_bytes()?;
            if public_key_bytes.len() != 32 {
                return Err(SiwxError::InvalidPublicKey(
                    "Ed25519 public key must be exactly 32 bytes".into(),
                ));
            }
            
            // Create verifying key from bytes
            let verifying_key = VerifyingKey::from_bytes(&public_key_bytes.try_into().unwrap())
                .map_err(|e| SiwxError::InvalidPublicKey(format!("Invalid Ed25519 public key: {}", e)))?;
            
            // Verify the signature
            match verifying_key.verify(message_bytes, &ed25519_sig) {
                Ok(_) => {
                    // Additional check: ensure the public key corresponds to the signer address
                    let derived_address = bs58::encode(&public_key_bytes).into_string();
                    Ok(derived_address == signature.signer)
                },
                Err(e) => {
                    Err(SiwxError::VerificationFailed(format!("Ed25519 signature verification failed: {}", e)))
                }
            }
        }
        #[cfg(not(feature = "solana"))]
        {
            Err(SiwxError::VerificationFailed(
                "Solana feature not enabled".into(),
            ))
        }
    }
}

/// Factory for creating verifiers with default backends
pub struct VerifierFactory;

impl VerifierFactory {
    /// Create a verifier for Ethereum with default backends
    pub fn ethereum() -> SignatureVerifier {
        SignatureVerifier::new(Chain::Ethereum)
            .with_backend(Box::new(EthereumSecp256k1Verifier))
    }

    /// Create a verifier for Solana with default backends
    pub fn solana() -> SignatureVerifier {
        SignatureVerifier::new(Chain::Solana)
            .with_backend(Box::new(SolanaEd25519Verifier))
    }

    /// Create a verifier for any chain with default backends
    pub fn for_chain(chain: Chain) -> SignatureVerifier {
        match chain {
            Chain::Ethereum | Chain::EthereumTestnet => Self::ethereum(),
            Chain::Solana | Chain::SolanaTestnet => Self::solana(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SiwxMessage, PublicKeyFactory};

    #[tokio::test]
    async fn test_verifier_creation() {
        let verifier = VerifierFactory::ethereum();
        assert_eq!(verifier.chain(), Chain::Ethereum);
        assert_eq!(verifier.backend_count(), 1);

        let verifier = VerifierFactory::solana();
        assert_eq!(verifier.chain(), Chain::Solana);
        assert_eq!(verifier.backend_count(), 1);
    }

    #[tokio::test]
    async fn test_verifier_for_chain() {
        let verifier = VerifierFactory::for_chain(Chain::Ethereum);
        assert_eq!(verifier.chain(), Chain::Ethereum);

        let verifier = VerifierFactory::for_chain(Chain::Solana);
        assert_eq!(verifier.chain(), Chain::Solana);
    }

    #[test]
    fn test_backend_support() {
        let eth_backend = EthereumSecp256k1Verifier;
        assert_eq!(eth_backend.supported_chain(), Chain::Ethereum);
        assert!(eth_backend.supported_signature_types().contains(&SignatureType::Eip191));

        let sol_backend = SolanaEd25519Verifier;
        assert_eq!(sol_backend.supported_chain(), Chain::Solana);
        assert!(sol_backend.supported_signature_types().contains(&SignatureType::Ed25519));
    }

    #[tokio::test]
    async fn test_verifier_with_public_key() {
        let verifier = VerifierFactory::ethereum();
        let message = SiwxMessage::new(
            "example.com",
            "0x1234567890123456789012345678901234567890",
            "https://example.com/login",
            "1",
            "2024-01-01T00:00:00Z",
            "nonce123",
        );
        let signature = Signature::eip191(
            "0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "0x1234567890123456789012345678901234567890",
        );
        let public_key = PublicKeyFactory::ethereum("0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
        
        // This should not panic with the new public key abstraction
        let _result = verifier.verify(&message, &signature, &public_key).await;
    }
} 