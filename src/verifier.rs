use crate::{Chain, Signature, SignatureType, SiwxError, SiwxMessage, SiwxResult};
use async_trait::async_trait;
use std::fmt;

/// Trait for signature verification backends
#[async_trait]
pub trait SignatureVerifierBackend: Send + Sync {
    /// Verify a signature for a given message
    async fn verify(&self, message: &SiwxMessage, signature: &Signature) -> SiwxResult<bool>;

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
    pub async fn verify(&self, message: &SiwxMessage, signature: &Signature) -> SiwxResult<bool> {
        // Validate message and signature first
        message.validate()?;
        signature.validate_format()?;

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

        // Try each backend until one validates successfully
        let mut found_applicable_backend = false;
        for backend in &self.backends {
            if backend.supported_chain() == self.chain
                && backend
                    .supported_signature_types()
                    .contains(&signature.signature_type)
            {
                found_applicable_backend = true;
                match backend.verify(message, signature).await {
                    Ok(true) => return Ok(true),
                    Ok(false) => {
                        // Try the next applicable backend
                        continue;
                    }
                    Err(e) => {
                        // Log the error but continue to next backend
                        eprintln!("Backend verification failed: {}", e);
                        continue;
                    }
                }
            }
        }

        if found_applicable_backend {
            // At least one backend could handle this, but none validated successfully
            Ok(false)
        } else {
            Err(SiwxError::VerificationFailed(
                "No suitable backend found for verification".into(),
            ))
        }
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

// VerifierFactory removed; build verifiers manually.

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "ethereum")]
    use crate::backend::ethereum::EthereumSecp256k1Verifier;
    #[cfg(feature = "solana")]
    use crate::backend::solana::SolanaEd25519Verifier;
    use crate::utils::generate_mock_hex_string;
    use crate::SiwxMessage;

    #[tokio::test]
    async fn test_verifier_creation() {
        // Ethereum
        let verifier_eth = SignatureVerifier::new(Chain::Ethereum);
        #[cfg(feature = "ethereum")]
        let verifier_eth =
            verifier_eth.with_backend(Box::new(EthereumSecp256k1Verifier::new(None)));
        assert_eq!(verifier_eth.chain(), Chain::Ethereum);
        #[cfg(feature = "ethereum")]
        assert_eq!(verifier_eth.backend_count(), 1);
        #[cfg(not(feature = "ethereum"))]
        assert_eq!(verifier_eth.backend_count(), 0);

        // Solana
        let verifier_sol = SignatureVerifier::new(Chain::Solana);
        #[cfg(feature = "solana")]
        let verifier_sol = verifier_sol.with_backend(Box::new(SolanaEd25519Verifier));
        assert_eq!(verifier_sol.chain(), Chain::Solana);
        #[cfg(feature = "solana")]
        assert_eq!(verifier_sol.backend_count(), 1);
        #[cfg(not(feature = "solana"))]
        assert_eq!(verifier_sol.backend_count(), 0);
    }

    #[tokio::test]
    async fn test_verifier_for_chain() {
        // Ethereum
        let verifier_eth = SignatureVerifier::new(Chain::Ethereum);
        #[cfg(feature = "ethereum")]
        let verifier_eth =
            verifier_eth.with_backend(Box::new(EthereumSecp256k1Verifier::new(None)));
        assert_eq!(verifier_eth.chain(), Chain::Ethereum);

        // Solana
        let verifier_sol = SignatureVerifier::new(Chain::Solana);
        #[cfg(feature = "solana")]
        let verifier_sol = verifier_sol.with_backend(Box::new(SolanaEd25519Verifier));
        assert_eq!(verifier_sol.chain(), Chain::Solana);
    }

    #[test]
    fn test_backend_support() {
        #[cfg(feature = "ethereum")]
        {
            let eth_backend = EthereumSecp256k1Verifier::new(None);
            assert_eq!(eth_backend.supported_chain(), Chain::Ethereum);
            assert!(eth_backend
                .supported_signature_types()
                .contains(&SignatureType::Eip191));
        }

        #[cfg(feature = "solana")]
        {
            use crate::backend::solana::SolanaEd25519Verifier;
            let sol_backend = SolanaEd25519Verifier;
            assert_eq!(sol_backend.supported_chain(), Chain::Solana);
            assert!(sol_backend
                .supported_signature_types()
                .contains(&SignatureType::Ed25519));
        }
    }

    #[cfg(feature = "ethereum")]
    #[tokio::test]
    async fn test_verifier_with_public_key() {
        let verifier = SignatureVerifier::new(Chain::Ethereum)
            .with_backend(Box::new(EthereumSecp256k1Verifier::new(None)));
        let message = SiwxMessage::new(
            "example.com",
            "0x1234567890123456789012345678901234567890",
            "https://example.com/login",
            "1",
            "2024-01-01T00:00:00Z",
            "nonce123",
        );
        let signature = Signature::eip191(generate_mock_hex_string(65, 0x00, true));
        // This should not panic
        let _result = verifier.verify(&message, &signature).await;
    }
}
