use siwx_rs::{
    Chain, SiwxMessage, Signature, SignatureType, 
    VerifierFactory, PublicKeyFactory
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("SIWX Signature Verification Example");
    println!("====================================");

    // Example message
    let message = SiwxMessage::new(
        "example.com",
        "0x742d35Cc6690C6E7f3bC285e2038f014E6e7C1F5", // Example Ethereum address
        "https://example.com/login",
        "1",
        "2024-01-01T00:00:00Z",
        "abcd1234",
    );

    println!("\nMessage to sign:");
    println!("{}", message);

    // Ethereum Example
    println!("\n--- Ethereum Signature Verification ---");
    
    #[cfg(feature = "ethereum")]
    {
        let eth_signature = Signature::eip191(
            // Example signature (this would come from a wallet)
            "0x1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "0x742d35Cc6690C6E7f3bC285e2038f014E6e7C1F5",
        );

        let eth_public_key = PublicKeyFactory::ethereum(
            "0x04242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424"
        );

        let verifier = VerifierFactory::ethereum();
        
        match verifier.verify(&message, &eth_signature, &eth_public_key).await {
            Ok(valid) => println!("Ethereum signature valid: {}", valid),
            Err(e) => println!("Ethereum verification error: {}", e),
        }
    }

    #[cfg(not(feature = "ethereum"))]
    {
        println!("Ethereum feature not enabled. Use '--features ethereum' to test Ethereum signature verification.");
    }

    // Solana Example
    println!("\n--- Solana Signature Verification ---");
    
    #[cfg(feature = "solana")]
    {
        let solana_message = SiwxMessage::new(
            "example.com",
            "11111111111111111111111111111112", // Example Solana address (base58)
            "https://example.com/login",
            "1",
            "2024-01-01T00:00:00Z",
            "abcd1234",
        );

        let solana_signature = Signature::ed25519(
            // Example base58 signature (this would come from a wallet)
            "2Th9g3M8gG7w4w8q7x8x8q7w8q7w8q7w8q7w8q7w8q7w8q7w8q7w8q7w8q7w8q7w8q",
            "11111111111111111111111111111112",
        );

        let solana_public_key = PublicKeyFactory::solana(
            "11111111111111111111111111111112"
        );

        let verifier = VerifierFactory::solana();
        
        match verifier.verify(&solana_message, &solana_signature, &solana_public_key).await {
            Ok(valid) => println!("Solana signature valid: {}", valid),
            Err(e) => println!("Solana verification error: {}", e),
        }
    }

    #[cfg(not(feature = "solana"))]
    {
        println!("Solana feature not enabled. Use '--features solana' to test Solana signature verification.");
    }

    println!("\n--- Testing with invalid signatures ---");
    
    // Test with invalid signature
    let invalid_signature = Signature::eip191(
        "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "0x742d35Cc6690C6E7f3bC285e2038f014E6e7C1F5",
    );

    #[cfg(feature = "ethereum")]
    {
        let eth_public_key = PublicKeyFactory::ethereum(
            "0x04242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424"
        );
        let verifier = VerifierFactory::ethereum();
        
        match verifier.verify(&message, &invalid_signature, &eth_public_key).await {
            Ok(valid) => println!("Invalid Ethereum signature result: {}", valid),
            Err(e) => println!("Invalid Ethereum signature error: {}", e),
        }
    }

    Ok(())
}