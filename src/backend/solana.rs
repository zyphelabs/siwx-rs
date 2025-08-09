#![cfg(feature = "solana")]

use crate::{
    verifier::SignatureVerifierBackend, Chain, PublicKey, Signature, SignatureType, SiwxError,
    SiwxMessage, SiwxResult,
};
use async_trait::async_trait;
use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

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
    async fn verify_ed25519(
        &self,
        message: &SiwxMessage,
        signature: &Signature,
        public_key: &dyn PublicKey,
    ) -> SiwxResult<bool> {
        // Message bytes (UTF-8)
        let message_bytes = message.message_to_sign()?.into_bytes();

        // Decode signature (base58 → 64 bytes)
        let sig_bytes = bs58::decode(&signature.signature)
            .into_vec()
            .map_err(|e| SiwxError::InvalidSignature(format!("Invalid base58 signature: {e}")))?;
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            SiwxError::InvalidSignature(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                sig_bytes.len()
            ))
        })?;
        let sig = DalekSignature::from_bytes(&sig_arr);

        // Determine the verifying key
        let account_pubkey_str = public_key.as_string();
        let signer_pubkey_str = signature.signer.clone();

        // If the signer equals the account, treat as EOA
        if signer_pubkey_str == account_pubkey_str {
            let verify_key = self.verifying_key_from_base58(&signer_pubkey_str)?;
            return Ok(verify_key.verify(&message_bytes, &sig).is_ok());
        }

        // Otherwise, attempt smart account verification using PDA derivation
        // Expect metadata to include `program_id` and `pda_seeds` (JSON array of base58 strings)
        let program_id = signature.metadata.get("program_id").ok_or_else(|| {
            SiwxError::VerificationFailed(
                "Smart account signature requires `program_id` metadata".into(),
            )
        })?;
        let seeds_json = signature.metadata.get("pda_seeds").ok_or_else(|| {
            SiwxError::VerificationFailed(
                "Smart account signature requires `pda_seeds` metadata (JSON array)".into(),
            )
        })?;

        let derived_pda = self.derive_pda(program_id, seeds_json)?;
        let target_pubkey = Pubkey::from_str(&account_pubkey_str).map_err(|e| {
            SiwxError::InvalidPublicKey(format!("Invalid Solana account address: {e}"))
        })?;
        if derived_pda != target_pubkey {
            return Err(SiwxError::VerificationFailed(
                "PDA derived from seeds does not match target account".into(),
            ));
        }

        // Verify signature against signer (authority) key
        let authority_key = self.verifying_key_from_base58(&signer_pubkey_str)?;
        Ok(authority_key.verify(&message_bytes, &sig).is_ok())
    }

    fn verifying_key_from_base58(&self, key_b58: &str) -> SiwxResult<VerifyingKey> {
        let key_bytes = bs58::decode(key_b58)
            .into_vec()
            .map_err(|e| SiwxError::InvalidPublicKey(format!("Invalid base58 public key: {e}")))?;
        if key_bytes.len() != 32 {
            return Err(SiwxError::InvalidPublicKey(format!(
                "Ed25519 public key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }
        VerifyingKey::from_bytes(&key_bytes.try_into().unwrap())
            .map_err(|e| SiwxError::InvalidPublicKey(format!("Invalid ed25519 public key: {e}")))
    }

    fn derive_pda(&self, program_id_str: &str, seeds_json: &str) -> SiwxResult<Pubkey> {
        let program_id = Pubkey::from_str(program_id_str)
            .map_err(|e| SiwxError::InvalidPublicKey(format!("Invalid program_id pubkey: {e}")))?;

        // Expect JSON array of base58 strings, e.g.: ["seed1_b58", "seed2_b58", ...]
        let seed_b58_list: Vec<String> = serde_json::from_str(seeds_json).map_err(|e| {
            SiwxError::InvalidMessageFormat(format!(
                "pda_seeds must be a JSON array of base58 strings: {e}"
            ))
        })?;

        let mut seed_slices: Vec<Vec<u8>> = Vec::with_capacity(seed_b58_list.len());
        for s in seed_b58_list {
            let bytes = bs58::decode(s).into_vec().map_err(|e| {
                SiwxError::InvalidMessageFormat(format!("Failed to decode PDA seed (base58): {e}"))
            })?;
            seed_slices.push(bytes);
        }

        let seed_refs: Vec<&[u8]> = seed_slices.iter().map(|v| v.as_slice()).collect();
        let (pda, _bump) = Pubkey::find_program_address(&seed_refs, &program_id);
        Ok(pda)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{prelude::*, PublicKeyFactory, Signature as SiwxSignature};
    use ed25519::signature::Signer;
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::system_program;

    fn now_rfc3339() -> String {
        chrono::Utc::now().to_rfc3339()
    }

    fn b58_encode(input: impl AsRef<[u8]>) -> String {
        bs58::encode(input).into_string()
    }

    fn signing_key_from_tag(tag: u8) -> SigningKey {
        let mut seed = [0u8; 32];
        for i in 0..32 {
            seed[i] = tag.wrapping_add(i as u8);
        }
        SigningKey::from_bytes(&seed)
    }

    #[tokio::test]
    async fn test_solana_eoa_verify_success() {
        // Deterministic ed25519 keypair
        let signing_key = signing_key_from_tag(1);
        let verifying_key = signing_key.verifying_key();
        let account_b58 = b58_encode(verifying_key.to_bytes());

        // Build message
        let message = SiwxMessage::new_with_chain(
            "example.com",
            account_b58.clone(),
            "https://example.com/login",
            "1",
            now_rfc3339(),
            SiwxMessage::generate_nonce(),
            Chain::Solana,
        )
        .with_statement("Sign in to Example App");

        let msg_bytes = message.message_to_sign().unwrap().into_bytes();

        // Sign message
        let sig = signing_key.sign(&msg_bytes);
        let sig_b58 = b58_encode(sig.to_bytes());

        // Build SIWX signature (signer equals account)
        let siwx_sig = SiwxSignature::ed25519(sig_b58, account_b58.clone());

        // Public key and verifier
        let public_key = PublicKeyFactory::solana(account_b58);
        let verifier = VerifierFactory::solana();

        let is_valid = verifier
            .verify(&message, &siwx_sig, &public_key)
            .await
            .unwrap();
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_solana_pda_verify_success() {
        // Authority keypair (signer)
        let authority_sk = signing_key_from_tag(2);
        let authority_vk = authority_sk.verifying_key();
        let authority_b58 = b58_encode(authority_vk.to_bytes());

        // Program id and seeds used to derive PDA
        let program_id = system_program::id();
        let seed1 = b"siwx".to_vec();
        let seed2 = vec![1u8, 2, 3, 4, 5];
        let seed1_b58 = b58_encode(&seed1);
        let seed2_b58 = b58_encode(&seed2);

        // Derive PDA to use as the account address in the message
        let (pda, _bump) = Pubkey::find_program_address(&[&seed1, &seed2], &program_id);
        let account_b58 = pda.to_string();

        // Build message addressed to the PDA
        let message = SiwxMessage::new_with_chain(
            "example.com",
            account_b58.clone(),
            "https://example.com/login",
            "1",
            now_rfc3339(),
            SiwxMessage::generate_nonce(),
            Chain::Solana,
        )
        .with_statement("Sign in to Example App");

        let msg_bytes = message.message_to_sign().unwrap().into_bytes();

        // Sign with authority key
        let sig = authority_sk.sign(&msg_bytes);
        let sig_b58 = b58_encode(sig.to_bytes());

        // Signature metadata for PDA verification
        let metadata_program_id = program_id.to_string();
        let metadata_pda_seeds = json!([seed1_b58, seed2_b58]).to_string();

        let siwx_sig = SiwxSignature::ed25519(sig_b58, authority_b58)
            .with_metadata("program_id", metadata_program_id)
            .with_metadata("pda_seeds", metadata_pda_seeds);

        // Public key is the account (PDA)
        let public_key = PublicKeyFactory::solana(account_b58);
        let verifier = VerifierFactory::solana();

        let is_valid = verifier
            .verify(&message, &siwx_sig, &public_key)
            .await
            .unwrap();
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_solana_eoa_verify_failure_wrong_signature() {
        let signer = signing_key_from_tag(10);
        let verifying_key = signer.verifying_key();
        let account_b58 = b58_encode(verifying_key.to_bytes());

        // Message A (addressed to signer)
        let message_a = SiwxMessage::new_with_chain(
            "example.com",
            account_b58.clone(),
            "https://example.com/login",
            "1",
            now_rfc3339(),
            SiwxMessage::generate_nonce(),
            Chain::Solana,
        );

        // Sign different message B so signature won't verify for A
        let message_b = SiwxMessage::new_with_chain(
            "example.com",
            account_b58.clone(),
            "https://example.com/other",
            "1",
            now_rfc3339(),
            SiwxMessage::generate_nonce(),
            Chain::Solana,
        );

        let sig_b = signer.sign(&message_b.message_to_sign().unwrap().into_bytes());
        let sig_b58 = b58_encode(sig_b.to_bytes());

        let siwx_sig = SiwxSignature::ed25519(sig_b58, account_b58.clone());
        let public_key = PublicKeyFactory::solana(account_b58);
        let verifier = VerifierFactory::solana();

        let is_valid = verifier
            .verify(&message_a, &siwx_sig, &public_key)
            .await
            .unwrap();
        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_solana_eoa_verify_failure_signer_mismatch_no_metadata() {
        let signer = signing_key_from_tag(11);
        let verifying_key = signer.verifying_key();
        let signer_b58 = b58_encode(verifying_key.to_bytes());

        // Different account address in message
        let other_account = signing_key_from_tag(12).verifying_key();
        let account_b58 = b58_encode(other_account.to_bytes());

        let message = SiwxMessage::new_with_chain(
            "example.com",
            account_b58.clone(),
            "https://example.com/login",
            "1",
            now_rfc3339(),
            SiwxMessage::generate_nonce(),
            Chain::Solana,
        );
        let sig = signer.sign(&message.message_to_sign().unwrap().into_bytes());
        let sig_b58 = b58_encode(sig.to_bytes());

        // Signer != account, and no PDA metadata → should fail
        let siwx_sig = SiwxSignature::ed25519(sig_b58, signer_b58);
        let public_key = PublicKeyFactory::solana(account_b58);
        let verifier = VerifierFactory::solana();
        let is_valid = verifier
            .verify(&message, &siwx_sig, &public_key)
            .await
            .unwrap();
        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_solana_pda_verify_failure_wrong_seeds() {
        let authority = signing_key_from_tag(20);
        let auth_b58 = b58_encode(authority.verifying_key().to_bytes());
        let program_id = system_program::id();

        // Real PDA is derived from seeds ["siwx", [1,2,3]]
        let seed_ok1 = b58_encode(b"siwx");
        let seed_ok2 = b58_encode([1u8, 2, 3]);
        let (real_pda, _bump) = Pubkey::find_program_address(&[b"siwx", &[1, 2, 3]], &program_id);
        let account_b58 = real_pda.to_string();

        // Message addressed to real PDA
        let message = SiwxMessage::new_with_chain(
            "example.com",
            account_b58.clone(),
            "https://example.com/login",
            "1",
            now_rfc3339(),
            SiwxMessage::generate_nonce(),
            Chain::Solana,
        );
        let sig = authority.sign(&message.message_to_sign().unwrap().into_bytes());
        let sig_b58 = b58_encode(sig.to_bytes());

        // Provide wrong seeds so derived PDA won't match
        let wrong_seed1 = b58_encode(b"bad");
        let wrong_seed2 = b58_encode([9u8, 9, 9]);
        let siwx_sig = SiwxSignature::ed25519(sig_b58, auth_b58)
            .with_metadata("program_id", program_id.to_string())
            .with_metadata(
                "pda_seeds",
                serde_json::json!([wrong_seed1, wrong_seed2]).to_string(),
            );

        let public_key = PublicKeyFactory::solana(account_b58);
        let verifier = VerifierFactory::solana();
        let is_valid = verifier
            .verify(&message, &siwx_sig, &public_key)
            .await
            .unwrap();
        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_solana_pda_verify_failure_wrong_program_id() {
        let authority = signing_key_from_tag(21);
        let auth_b58 = b58_encode(authority.verifying_key().to_bytes());
        let program_id = system_program::id();

        // Real PDA
        let (real_pda, _bump) = Pubkey::find_program_address(&[b"siwx"], &program_id);
        let account_b58 = real_pda.to_string();

        let message = SiwxMessage::new_with_chain(
            "example.com",
            account_b58.clone(),
            "https://example.com/login",
            "1",
            now_rfc3339(),
            SiwxMessage::generate_nonce(),
            Chain::Solana,
        );
        let sig = authority.sign(&message.message_to_sign().unwrap().into_bytes());
        let sig_b58 = b58_encode(sig.to_bytes());

        // Use wrong program id (flip a byte)
        let mut wrong_prog_bytes = program_id.to_bytes();
        wrong_prog_bytes[0] ^= 0xFF;
        let wrong_program_id = Pubkey::new_from_array(wrong_prog_bytes);

        let siwx_sig = SiwxSignature::ed25519(sig_b58, auth_b58)
            .with_metadata("program_id", wrong_program_id.to_string())
            .with_metadata(
                "pda_seeds",
                serde_json::json!([b58_encode(b"siwx")]).to_string(),
            );

        let public_key = PublicKeyFactory::solana(account_b58);
        let verifier = VerifierFactory::solana();
        let is_valid = verifier
            .verify(&message, &siwx_sig, &public_key)
            .await
            .unwrap();
        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_solana_pda_verify_failure_wrong_authority_signature() {
        // Authority referenced in signature metadata
        let authority = signing_key_from_tag(22);
        let auth_b58 = b58_encode(authority.verifying_key().to_bytes());
        let program_id = system_program::id();
        let (real_pda, _bump) = Pubkey::find_program_address(&[b"siwx"], &program_id);
        let account_b58 = real_pda.to_string();

        let message = SiwxMessage::new_with_chain(
            "example.com",
            account_b58.clone(),
            "https://example.com/login",
            "1",
            now_rfc3339(),
            SiwxMessage::generate_nonce(),
            Chain::Solana,
        );

        // Sign with a different key than the advertised authority
        let wrong_signer = signing_key_from_tag(23);
        let sig = wrong_signer.sign(&message.message_to_sign().unwrap().into_bytes());
        let sig_b58 = b58_encode(sig.to_bytes());

        let siwx_sig = SiwxSignature::ed25519(sig_b58, auth_b58)
            .with_metadata("program_id", program_id.to_string())
            .with_metadata(
                "pda_seeds",
                serde_json::json!([b58_encode(b"siwx")]).to_string(),
            );

        let public_key = PublicKeyFactory::solana(account_b58);
        let verifier = VerifierFactory::solana();
        let is_valid = verifier
            .verify(&message, &siwx_sig, &public_key)
            .await
            .unwrap();
        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_solana_pda_verify_failure_missing_metadata() {
        let authority = signing_key_from_tag(24);
        let auth_b58 = b58_encode(authority.verifying_key().to_bytes());
        let program_id = system_program::id();
        let (real_pda, _bump) = Pubkey::find_program_address(&[b"siwx"], &program_id);
        let account_b58 = real_pda.to_string();

        let message = SiwxMessage::new_with_chain(
            "example.com",
            account_b58.clone(),
            "https://example.com/login",
            "1",
            now_rfc3339(),
            SiwxMessage::generate_nonce(),
            Chain::Solana,
        );
        let sig = authority.sign(&message.message_to_sign().unwrap().into_bytes());
        let sig_b58 = b58_encode(sig.to_bytes());

        // No program_id/pda_seeds metadata
        let siwx_sig = SiwxSignature::ed25519(sig_b58, auth_b58);
        let public_key = PublicKeyFactory::solana(account_b58);
        let verifier = VerifierFactory::solana();
        let is_valid = verifier
            .verify(&message, &siwx_sig, &public_key)
            .await
            .unwrap();
        assert!(!is_valid);
    }
}
