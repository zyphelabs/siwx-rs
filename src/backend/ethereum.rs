#![cfg(feature = "ethereum")]

use crate::{
    verifier::SignatureVerifierBackend, Chain, PublicKey, Signature, SignatureType, SiwxError,
    SiwxMessage, SiwxResult,
};
use alloy::primitives::{keccak256, Address, Signature as AlloySignature};
use alloy::{providers::ProviderBuilder, sol};
use async_trait::async_trait;
use std::env;
use std::str::FromStr;

/// Default Ethereum verifier using secp256k1
pub struct EthereumSecp256k1Verifier {
    rpc_url: Option<String>,
}

impl EthereumSecp256k1Verifier {
    pub fn new() -> Self {
        Self { rpc_url: None }
    }

    pub fn with_rpc_url(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: Some(rpc_url.into()),
        }
    }
}

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
            SignatureType::Eip1271 => self.verify_eip1271(message, signature, public_key).await,
            _ => Err(SiwxError::VerificationFailed(
                "Unsupported signature type for Ethereum".into(),
            )),
        }
    }

    fn supported_chain(&self) -> Chain {
        Chain::Ethereum
    }

    fn supported_signature_types(&self) -> Vec<SignatureType> {
        vec![SignatureType::Eip191, SignatureType::Eip1271]
    }
}

impl EthereumSecp256k1Verifier {
    /// Verify EIP-191 personal_sign signature
    async fn verify_eip191(
        &self,
        message: &SiwxMessage,
        signature: &Signature,
        _public_key: &dyn PublicKey,
    ) -> SiwxResult<bool> {
        // 1) Get raw message to sign (without EIP-191 prefix here)
        let msg = message.message_to_sign()?;

        // 3) Parse signature bytes (65 bytes r|s|v)
        let sig_bytes = signature.as_bytes()?;
        if sig_bytes.len() != 65 {
            return Err(SiwxError::InvalidSignature(
                "Ethereum signature must be 65 bytes".into(),
            ));
        }

        // Construct Signature from raw bytes.
        let alloy_sig = AlloySignature::try_from(&sig_bytes[..])
            .map_err(|e| SiwxError::InvalidSignature(format!("Invalid signature: {e}")))?;

        // 4) Recover address from message (method applies the EIP-191 prefix internally)
        let recovered: Address =
            alloy_sig
                .recover_address_from_msg(msg.as_bytes())
                .map_err(|e| {
                    SiwxError::VerificationFailed(format!(
                        "Failed to recover address from signature: {e}"
                    ))
                })?;

        // 5) Determine the expected address from the message/signature (addresses, not public keys)
        // Ensure the signature's signer matches the message address to prevent mismatches/replay.
        let message_addr = Address::from_str(message.address.as_str())
            .map_err(|e| SiwxError::InvalidAddress(format!("Invalid message address: {e}")))?;
        let signer_addr = Address::from_str(signature.signer.as_str())
            .map_err(|e| SiwxError::InvalidAddress(format!("Invalid signer address: {e}")))?;

        if message_addr != signer_addr {
            return Ok(false);
        }

        Ok(recovered == message_addr)
    }

    /// Verify EIP-1271 smart contract signature by calling isValidSignature on the contract
    async fn verify_eip1271(
        &self,
        message: &SiwxMessage,
        signature: &Signature,
        _public_key: &dyn PublicKey,
    ) -> SiwxResult<bool> {
        // Load provider URL from self, then .env (ETHEREUM_RPC_URL/ETH_RPC_URL),
        // and finally fallback to a default public mainnet provider
        // Safe to call multiple times; dotenvy is idempotent.
        let _ = dotenvy::dotenv();
        const DEFAULT_PROVIDER_URL: &str =
            "https://mainnet.infura.io/v3/84842078b09946638c03157f83405213";

        let effective_url = self
            .rpc_url
            .as_ref()
            .cloned()
            .or_else(|| env::var("ETHEREUM_RPC_URL").ok())
            .or_else(|| env::var("ETH_RPC_URL").ok())
            .unwrap_or_else(|| DEFAULT_PROVIDER_URL.to_string());

        // Build provider (http or ws based on URL scheme)
        let provider = ProviderBuilder::new()
            .connect(&effective_url)
            .await
            .map_err(|e| {
                SiwxError::VerificationFailed(format!("Failed to connect provider: {e}"))
            })?;

        // Compute EIP-191 hash of the message
        let msg = message.message_to_sign()?;
        let eth_signed_msg = format!("\x19Ethereum Signed Message:\n{}{}", msg.len(), msg);
        let hash = keccak256(eth_signed_msg.as_bytes());

        // Parse contract address (the signer field should be the contract wallet address)
        let contract_addr = Address::from_str(signature.signer.as_str()).map_err(|e| {
            SiwxError::InvalidAddress(format!("Invalid contract address for EIP-1271: {e}"))
        })?;

        // Parse message address and ensure it matches the contract address to prevent
        // cross-contract signature replay attacks.
        let message_addr = Address::from_str(message.address.as_str()).map_err(|e| {
            SiwxError::InvalidAddress(format!("Invalid message address for EIP-1271: {e}"))
        })?;
        if message_addr != contract_addr {
            return Err(SiwxError::VerificationFailed(
                "Signer does not match message address".into(),
            ));
        }

        // Use a minimal IERC1271 interface via sol! macro
        sol! {
            #[sol(rpc)]
            contract IERC1271 {
                function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4 magicValue);
            }
        }

        let contract = IERC1271::new(contract_addr, provider);
        let sig_bytes = signature.as_bytes()?;
        let magic: alloy::primitives::FixedBytes<4> = contract
            .isValidSignature(hash, sig_bytes.into())
            .call()
            .await
            .map_err(|e| {
                SiwxError::VerificationFailed(format!("EIP-1271 contract call failed: {e}"))
            })?;

        // Magic value as per EIP-1271
        let expected_magic: [u8; 4] = [0x16, 0x26, 0xBA, 0x7E];
        Ok(magic.0 == expected_magic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        public_key::{EthereumAddress, EthereumPublicKey},
        verifier::SignatureVerifier,
        VerifierFactory,
    };
    use alloy::signers::{local::PrivateKeySigner, Signer};
    use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
    use std::env;

    fn uncompressed_pubkey_hex_from_privkey_hex(priv_hex: &str) -> String {
        let bytes = hex::decode(priv_hex.trim_start_matches("0x")).unwrap();
        let secret_key = SecretKey::from_slice(&bytes).unwrap();
        let public_key = secret_key.public_key();
        let encoded = public_key.to_encoded_point(false); // uncompressed
        let bytes = encoded.as_bytes();
        format!("0x{}", hex::encode(bytes))
    }

    #[tokio::test]
    async fn test_eip191_verify_success() {
        // Use a known private key (Anvil default #0)
        let priv_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer: PrivateKeySigner = priv_key.parse().unwrap();
        let addr = format!("0x{:x}", signer.address());

        // Derive uncompressed public key hex
        let pubkey_hex = uncompressed_pubkey_hex_from_privkey_hex(priv_key);
        let pk = EthereumPublicKey::with_address(pubkey_hex, addr.clone());

        // Build SIWX message referencing the signer address
        let message = crate::SiwxMessage::new(
            "example.com",
            &addr,
            "https://example.com/login",
            "1",
            "2024-01-01T00:00:00Z",
            "nonce123",
        );

        let msg_to_sign = message.message_to_sign().unwrap();
        let sig = signer.sign_message(msg_to_sign.as_bytes()).await.unwrap();
        let sig_hex = format!("0x{}", hex::encode(sig.as_bytes()));
        let signature = crate::Signature::eip191(sig_hex, addr.clone());

        let verifier = VerifierFactory::ethereum();
        let result = verifier.verify(&message, &signature, &pk).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_eip191_verify_failure_wrong_address() {
        // Same key
        let priv_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer: PrivateKeySigner = priv_key.parse().unwrap();
        let addr = format!("0x{:x}", signer.address());

        // Derive uncompressed public key hex (unused for verification, but provided)
        let pubkey_hex = uncompressed_pubkey_hex_from_privkey_hex(priv_key);
        let pk = EthereumPublicKey::new(pubkey_hex);

        // Intentionally use a mismatching address in the message vs signer
        let wrong_addr = "0x0000000000000000000000000000000000000001".to_string();
        let message = crate::SiwxMessage::new(
            "example.com",
            &wrong_addr,
            "https://example.com/login",
            "1",
            "2024-01-01T00:00:00Z",
            "nonce123",
        );

        let msg_to_sign = message.message_to_sign().unwrap();
        let sig = signer.sign_message(msg_to_sign.as_bytes()).await.unwrap();
        let sig_hex = format!("0x{}", hex::encode(sig.as_bytes()));
        let signature = crate::Signature::eip191(sig_hex, addr.clone());

        let verifier = VerifierFactory::ethereum();
        let result = verifier.verify(&message, &signature, &pk).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_eip191_verify_success_with_address_only() {
        // Use a known private key (Anvil default #0)
        let priv_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer: PrivateKeySigner = priv_key.parse().unwrap();
        let addr = format!("0x{:x}", signer.address());

        // Build SIWX message referencing the signer address
        let message = crate::SiwxMessage::new(
            "example.com",
            &addr,
            "https://example.com/login",
            "1",
            "2024-01-01T00:00:00Z",
            "nonce123",
        );

        let msg_to_sign = message.message_to_sign().unwrap();
        let sig = signer.sign_message(msg_to_sign.as_bytes()).await.unwrap();
        let sig_hex = format!("0x{}", hex::encode(sig.as_bytes()));
        let signature = crate::Signature::eip191(sig_hex, addr.clone());

        // Provide only an address as the "public key"
        let pk = EthereumAddress::new(addr.clone()).unwrap();

        let verifier = VerifierFactory::ethereum();
        let result = verifier.verify(&message, &signature, &pk).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_eip191_verify_ignores_mismatched_public_key() {
        // Use a known private key (Anvil default #0)
        let priv_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer: PrivateKeySigner = priv_key.parse().unwrap();
        let addr = format!("0x{:x}", signer.address());

        // Message addressed to the signer
        let message = crate::SiwxMessage::new(
            "example.com",
            &addr,
            "https://example.com/login",
            "1",
            "2024-01-01T00:00:00Z",
            "nonce123",
        );

        // Sign correctly
        let msg_to_sign = message.message_to_sign().unwrap();
        let sig = signer.sign_message(msg_to_sign.as_bytes()).await.unwrap();
        let sig_hex = format!("0x{}", hex::encode(sig.as_bytes()));
        let signature = crate::Signature::eip191(sig_hex, addr.clone());

        // Provide a mismatched uncompressed pubkey hex (65 bytes starting with 0x04)
        // Here we just use an arbitrary value that validates as hex length but doesn't match signer
        let bogus_pubkey = "0x04".to_string() + &"11".repeat(64);
        let pk = EthereumPublicKey::new(bogus_pubkey);

        let verifier = VerifierFactory::ethereum();
        // Should still verify true because verification is address-based
        let result = verifier.verify(&message, &signature, &pk).await.unwrap();
        assert!(result);
    }

    // Mainnet vectors for EIP-1271 using a default provider.
    const DEFAULT_PROVIDER_URL: &str =
        "https://mainnet.infura.io/v3/84842078b09946638c03157f83405213";

    fn test_provider_url() -> String {
        let _ = dotenvy::dotenv();
        env::var("ETHEREUM_RPC_URL")
            .or_else(|_| env::var("ETH_RPC_URL"))
            .unwrap_or_else(|_| DEFAULT_PROVIDER_URL.to_string())
    }

    // Ignored network tests; run with: cargo test --features ethereum -- --ignored --test-threads=1
    #[ignore]
    #[tokio::test]
    async fn test_eip1271_argent() {
        let message_text = "localhost:4361 wants you to sign in with your Ethereum account:\n0xa5b3A53800cD49669F34DE80f2C569c6D4Ca3009\n\nSIWE Notepad Example\n\nURI: http://localhost:4361\nVersion: 1\nChain ID: 1\nNonce: FbYd6TNB4m0IUHDG7\nIssued At: 2022-04-19T18:55:04.444Z";
        let signature_hex = "0x00193f8bb87a8bd4a8367a47ee477c62aec984830ec59e730b28d1ec54669eab450b9f3108a5c435648691c5766b35e2f13b8fb29f46298bb378ac34597d7e271c";
        let contract_address = "0xa5b3A53800cD49669F34DE80f2C569c6D4Ca3009";

        let message = crate::SiwxMessage::new(
            "localhost:4361",
            contract_address,
            "http://localhost:4361",
            "1",
            "2022-04-19T18:55:04.444Z",
            "FbYd6TNB4m0IUHDG7",
        )
        .with_statement("SIWE Notepad Example");
        assert_eq!(message.message_to_sign().unwrap(), message_text);

        let sig = crate::Signature::eip1271(signature_hex, contract_address);
        let dummy_pubkey = EthereumPublicKey::new("0x04".to_string() + &"11".repeat(64));
        let verifier = SignatureVerifier::new(Chain::Ethereum).with_backend(Box::new(
            EthereumSecp256k1Verifier::with_rpc_url(test_provider_url()),
        ));
        let ok = verifier
            .verify(&message, &sig, &dummy_pubkey)
            .await
            .unwrap();
        assert!(ok);
    }

    #[ignore]
    #[tokio::test]
    async fn test_eip1271_loopring() {
        let message_text = "localhost:4361 wants you to sign in with your Ethereum account:\n0x0e565A6dFc43DE21455a67bbF196f7F7b15447A7\n\nSIWE Notepad Example\n\nURI: http://localhost:4361\nVersion: 1\nChain ID: 1\nNonce: b19JyMHnM0Jdm20as\nIssued At: 2022-04-19T18:57:09.490Z";
        let signature_hex = "0x2f280385ebd550309197c4c892c5a8eb1a6e743d5c90c8036dea6f05c3e8cb321f90210a567ee88461733731a9c4e177140a969784c0421c09897e161f17bf331c02";
        let contract_address = "0x0e565A6dFc43DE21455a67bbF196f7F7b15447A7";

        let message = crate::SiwxMessage::new(
            "localhost:4361",
            contract_address,
            "http://localhost:4361",
            "1",
            "2022-04-19T18:57:09.490Z",
            "b19JyMHnM0Jdm20as",
        )
        .with_statement("SIWE Notepad Example");
        assert_eq!(message.message_to_sign().unwrap(), message_text);

        let sig = crate::Signature::eip1271(signature_hex, contract_address);
        let dummy_pubkey = EthereumPublicKey::new("0x04".to_string() + &"11".repeat(64));
        let verifier = SignatureVerifier::new(Chain::Ethereum).with_backend(Box::new(
            EthereumSecp256k1Verifier::with_rpc_url(test_provider_url()),
        ));
        let ok = verifier
            .verify(&message, &sig, &dummy_pubkey)
            .await
            .unwrap();
        assert!(ok);
    }
}
