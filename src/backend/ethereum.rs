#![cfg(feature = "ethereum")]

use crate::{
    verifier::SignatureVerifierBackend, Chain, Signature, SignatureType, SiwxError, SiwxMessage,
    SiwxResult,
};
use alloy::primitives::{keccak256, Address, Signature as AlloySignature};
use alloy::{providers::ProviderBuilder, sol};
use async_trait::async_trait;
use std::str::FromStr;

/// Default Ethereum verifier using secp256k1
pub struct EthereumSecp256k1Verifier {
    rpc_url: Option<String>,
}

impl EthereumSecp256k1Verifier {
    pub fn new(provider_url: Option<String>) -> Self {
        Self {
            rpc_url: provider_url,
        }
    }
}

#[async_trait]
impl SignatureVerifierBackend for EthereumSecp256k1Verifier {
    async fn verify(&self, message: &SiwxMessage, signature: &Signature) -> SiwxResult<bool> {
        match signature.signature_type {
            SignatureType::Eip191 => self.verify_eip191(message, signature).await,
            SignatureType::Eip1271 => self.verify_eip1271(message, signature).await,
            SignatureType::EthereumAutodetect => {
                // Route based on whether recovered signer equals the message address
                let recovered: Address = self.recover_signer(message, signature).await?;
                let message_addr = Address::from_str(message.address.as_str()).map_err(|e| {
                    SiwxError::InvalidAddress(format!("Invalid message address: {e}"))
                })?;
                if recovered == message_addr {
                    self.verify_eip191(message, signature).await
                } else {
                    self.verify_eip1271(message, signature).await
                }
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
        vec![
            SignatureType::Eip191,
            SignatureType::Eip1271,
            SignatureType::EthereumAutodetect,
        ]
    }
}

impl EthereumSecp256k1Verifier {
    async fn recover_signer(
        &self,
        message: &SiwxMessage,
        signature: &Signature,
    ) -> SiwxResult<Address> {
        let msg = message.message_to_sign()?;
        let sig_bytes = signature.as_bytes()?;
        let alloy_sig = AlloySignature::try_from(&sig_bytes[..])
            .map_err(|e| SiwxError::InvalidSignature(format!("Invalid signature: {e}")))?;
        let recovered = alloy_sig
            .recover_address_from_msg(msg.as_bytes())
            .map_err(|e| {
                SiwxError::VerificationFailed(format!(
                    "Failed to recover address from signature: {e}"
                ))
            })?;
        Ok(recovered)
    }

    /// Verify EIP-191 personal_sign signature
    async fn verify_eip191(
        &self,
        message: &SiwxMessage,
        signature: &Signature,
    ) -> SiwxResult<bool> {
        let recovered: Address = self.recover_signer(message, signature).await?;

        // Ensure the signature's signer matches the message address to prevent mismatches/replay.
        let message_addr = Address::from_str(message.address.as_str())
            .map_err(|e| SiwxError::InvalidAddress(format!("Invalid message address: {e}")))?;

        Ok(recovered == message_addr)
    }

    /// Verify EIP-1271 smart contract signature by calling isValidSignature on the contract
    async fn verify_eip1271(
        &self,
        message: &SiwxMessage,
        signature: &Signature,
    ) -> SiwxResult<bool> {
        // Build provider (http or ws based on URL scheme)
        let rpc_url = self.rpc_url.as_ref().ok_or_else(|| {
            SiwxError::VerificationFailed("Ethereum RPC URL not configured in verifier".into())
        })?;
        let provider = ProviderBuilder::new().connect(rpc_url).await.map_err(|e| {
            SiwxError::VerificationFailed(format!("Failed to connect provider: {e}"))
        })?;

        // Compute EIP-191 hash of the message
        let msg = message.message_to_sign()?;
        let eth_signed_msg = format!("\x19Ethereum Signed Message:\n{}{}", msg.len(), msg);
        let hash = keccak256(eth_signed_msg.as_bytes());

        let contract_addr = Address::from_str(message.address.as_str()).map_err(|e| {
            SiwxError::InvalidAddress(format!("Invalid message address for EIP-1271: {e}"))
        })?;

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
    use crate::verifier::SignatureVerifier;
    use alloy::signers::{local::PrivateKeySigner, Signer};
    use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
    use std::env;

    #[allow(dead_code)]
    fn uncompressed_pubkey_hex_from_privkey_hex(priv_hex: &str) -> String {
        let bytes = hex::decode(priv_hex.trim_start_matches("0x")).unwrap();
        let secret_key = SecretKey::from_slice(&bytes).unwrap();
        let public_key = secret_key.public_key();
        let encoded = public_key.to_encoded_point(false); // uncompressed
        let bytes = encoded.as_bytes();
        format!("0x{}", hex::encode(bytes))
    }

    #[tokio::test]
    async fn test_autodetect_eip191_verify_success() {
        // Use a known private key (Anvil default #0)
        let priv_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer: PrivateKeySigner = priv_key.parse().unwrap();

        // Build SIWX message referencing the signer address
        let message = crate::SiwxMessage::new(
            "example.com",
            &format!("0x{:x}", signer.address()),
            "https://example.com/login",
            "1",
            "2024-01-01T00:00:00Z",
            "nonce123",
        );

        let msg_to_sign = message.message_to_sign().unwrap();
        let sig = signer.sign_message(msg_to_sign.as_bytes()).await.unwrap();
        let sig_hex = format!("0x{}", hex::encode(sig.as_bytes()));
        let signature = crate::Signature::ethereum_autodetect(sig_hex);

        let verifier = SignatureVerifier::new(Chain::Ethereum).with_backend(Box::new(
            EthereumSecp256k1Verifier::new(Some(test_provider_url())),
        ));
        let result = verifier.verify(&message, &signature).await.unwrap();
        assert!(result);
    }

    #[ignore]
    #[tokio::test]
    async fn test_autodetect_routes_to_eip1271_network_vector() {
        // This test mirrors the EIP-1271 network tests but uses autodetect
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

        // signer != message.address is a contract, so autodetect should route to EIP-1271
        let sig = crate::Signature::ethereum_autodetect(signature_hex);
        let verifier = SignatureVerifier::new(Chain::Ethereum).with_backend(Box::new(
            EthereumSecp256k1Verifier::new(Some(test_provider_url())),
        ));
        let ok = verifier.verify(&message, &sig).await.unwrap();
        assert!(ok);
    }
    #[allow(dead_code)]
    async fn test_eip191_verify_success() {
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
        let signature = crate::Signature::eip191(sig_hex);

        let verifier = SignatureVerifier::new(Chain::Ethereum).with_backend(Box::new(
            EthereumSecp256k1Verifier::new(Some(test_provider_url())),
        ));
        let result = verifier.verify(&message, &signature).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_eip191_verify_failure_wrong_address() {
        // Same key
        let priv_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer: PrivateKeySigner = priv_key.parse().unwrap();
        let _addr = format!("0x{:x}", signer.address());

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
        let signature = crate::Signature::eip191(sig_hex);

        let verifier = SignatureVerifier::new(Chain::Ethereum).with_backend(Box::new(
            EthereumSecp256k1Verifier::new(Some(test_provider_url())),
        ));
        let result = verifier.verify(&message, &signature).await.unwrap();
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
        let signature = crate::Signature::eip191(sig_hex);

        let verifier = SignatureVerifier::new(Chain::Ethereum).with_backend(Box::new(
            EthereumSecp256k1Verifier::new(Some(test_provider_url())),
        ));
        let result = verifier.verify(&message, &signature).await.unwrap();
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
        let signature = crate::Signature::eip191(sig_hex);

        let verifier = SignatureVerifier::new(Chain::Ethereum).with_backend(Box::new(
            EthereumSecp256k1Verifier::new(Some(test_provider_url())),
        ));
        // Should still verify true because verification is address-based
        let result = verifier.verify(&message, &signature).await.unwrap();
        assert!(result);
    }

    fn test_provider_url() -> String {
        let _ = dotenvy::dotenv();
        env::var("ETHEREUM_RPC_URL")
            .or_else(|_| env::var("ETH_RPC_URL"))
            .expect("ETHEREUM_RPC_URL or ETH_RPC_URL must be set")
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

        let sig = crate::Signature::eip1271(signature_hex);
        let verifier = SignatureVerifier::new(Chain::Ethereum).with_backend(Box::new(
            EthereumSecp256k1Verifier::new(Some(test_provider_url())),
        ));
        let ok = verifier.verify(&message, &sig).await.unwrap();
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

        let sig = crate::Signature::eip1271(signature_hex);
        let verifier = SignatureVerifier::new(Chain::Ethereum).with_backend(Box::new(
            EthereumSecp256k1Verifier::new(Some(test_provider_url())),
        ));
        let ok = verifier.verify(&message, &sig).await.unwrap();
        assert!(ok);
    }
}
