use siwx_rs::prelude::*;

#[tokio::main]
async fn main() -> SiwxResult<()> {
    println!("=== SIWX Public Key Abstraction Example ===\n");

    // Example 1: Ethereum Public Key
    println!("1. Ethereum Public Key Example:");
    let eth_public_key = PublicKeyFactory::ethereum(
        "0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    );
    
    println!("   Chain: {}", eth_public_key.chain());
    println!("   Key Type: {}", eth_public_key.key_type());
    println!("   String representation: {}", eth_public_key.as_string());
    println!("   Supports EIP-191: {}", eth_public_key.supports_signature_type(&SignatureType::Eip191));
    println!("   Supports Ed25519: {}", eth_public_key.supports_signature_type(&SignatureType::Ed25519));
    println!();

    // Example 2: Solana Public Key
    println!("2. Solana Public Key Example:");
    let sol_public_key = PublicKeyFactory::solana("11111111111111111111111111111112");
    
    println!("   Chain: {}", sol_public_key.chain());
    println!("   Key Type: {}", sol_public_key.key_type());
    println!("   String representation: {}", sol_public_key.as_string());
    println!("   Supports EIP-191: {}", sol_public_key.supports_signature_type(&SignatureType::Eip191));
    println!("   Supports Ed25519: {}", sol_public_key.supports_signature_type(&SignatureType::Ed25519));
    println!();

    // Example 3: Auto-detection
    println!("3. Auto-detection Example:");
    let auto_detected_eth = PublicKeyFactory::auto_detect(
        "0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    )?;
    println!("   Auto-detected Ethereum: {}", auto_detected_eth.chain());

    let auto_detected_sol = PublicKeyFactory::auto_detect("11111111111111111111111111111112")?;
    println!("   Auto-detected Solana: {}", auto_detected_sol.chain());
    println!();

    // Example 4: Using with verifier
    println!("4. Verification Example:");
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

    let verifier = VerifierFactory::ethereum();
    let result = verifier.verify(&message, &signature, &eth_public_key).await;
    println!("   Verification result: {:?}", result);
    println!();

    // Example 5: Chain-specific creation
    println!("5. Chain-specific Creation:");
    let eth_for_chain = PublicKeyFactory::for_chain(
        "0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
        Chain::Ethereum
    );
    println!("   Ethereum for chain: {}", eth_for_chain.chain());

    let sol_for_chain = PublicKeyFactory::for_chain("11111111111111111111111111111112", Chain::Solana);
    println!("   Solana for chain: {}", sol_for_chain.chain());
    println!();

    // Example 6: Validation
    println!("6. Validation Example:");
    println!("   Ethereum key validation: {:?}", eth_public_key.validate());
    println!("   Solana key validation: {:?}", sol_public_key.validate());
    
    // Try with invalid key
    let invalid_key = PublicKeyFactory::ethereum("invalid_key");
    println!("   Invalid key validation: {:?}", invalid_key.validate());
    println!();

    // Example 7: Address derivation
    println!("7. Address Derivation:");
    let eth_with_address = EthereumPublicKey::with_address(
        "0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "0x1234567890123456789012345678901234567890"
    );
    println!("   Ethereum address: {:?}", eth_with_address.address());
    
    let sol_with_address = SolanaPublicKey::with_address(
        "11111111111111111111111111111112",
        "11111111111111111111111111111112"
    );
    println!("   Solana address: {:?}", sol_with_address.address());
    println!();

    println!("=== Example completed successfully! ===");
    Ok(())
} 