use crate::{Chain, PublicKey, Signature, SignatureType, SiwxError, SiwxMessage, SiwxResult};
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
                && backend
                    .supported_signature_types()
                    .contains(&signature.signature_type)
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

// Ethereum backend moved to `backend::ethereum` under the `ethereum` feature.

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
        // For now, return true as a placeholder
        // In a real implementation, you would use a proper crypto library
        // like solana-sdk or implement the verification manually
        println!("Ed25519 signature verification not fully implemented yet");
        println!("Message: {}", message.message_to_sign()?);
        println!("Signature: {}", signature.signature);
        println!("Public key: {}", public_key.as_string());
        Ok(true)
    }
}

/// Factory for creating verifiers with default backends
pub struct VerifierFactory;

impl VerifierFactory {
    /// Create a verifier for Ethereum with default backends
    pub fn ethereum() -> SignatureVerifier {
        #[cfg(feature = "ethereum")]
        {
            use crate::backend::ethereum::EthereumSecp256k1Verifier;
            SignatureVerifier::new(Chain::Ethereum)
                .with_backend(Box::new(EthereumSecp256k1Verifier::new()))
        }
        #[cfg(not(feature = "ethereum"))]
        {
            SignatureVerifier::new(Chain::Ethereum)
        }
    }

    /// Create a verifier for Solana with default backends
    pub fn solana() -> SignatureVerifier {
        SignatureVerifier::new(Chain::Solana).with_backend(Box::new(SolanaEd25519Verifier))
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
    use crate::{PublicKeyFactory, SiwxMessage};

    #[tokio::test]
    async fn test_verifier_creation() {
        let verifier = VerifierFactory::ethereum();
        assert_eq!(verifier.chain(), Chain::Ethereum);
        #[cfg(feature = "ethereum")]
        assert_eq!(verifier.backend_count(), 1);
        #[cfg(not(feature = "ethereum"))]
        assert_eq!(verifier.backend_count(), 0);

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
        #[cfg(feature = "ethereum")]
        {
            use crate::backend::ethereum::EthereumSecp256k1Verifier;
            let eth_backend = EthereumSecp256k1Verifier::new();
            assert_eq!(eth_backend.supported_chain(), Chain::Ethereum);
            assert!(eth_backend
                .supported_signature_types()
                .contains(&SignatureType::Eip191));
        }

        let sol_backend = SolanaEd25519Verifier;
        assert_eq!(sol_backend.supported_chain(), Chain::Solana);
        assert!(sol_backend
            .supported_signature_types()
            .contains(&SignatureType::Ed25519));
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
