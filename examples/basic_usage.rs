use siwx_rs::prelude::*;

#[tokio::main]
async fn main() -> SiwxResult<()> {
    println!("=== SIWX Basic Usage Example ===\n");

    // Example 1: Ethereum SIWX
    println!("1. Ethereum SIWX Message:");
    let eth_message = SiwxMessage::new_with_current_time(
        "example.com",
        "0x1234567890123456789012345678901234567890",
        "https://example.com/login",
        "1",
        SiwxMessage::generate_nonce(),
    )
    .with_statement("Sign in to Example App")
    .with_expiration_time(
        (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
    );

    println!("Message to sign:");
    println!("{}", eth_message.message_to_sign()?);
    println!();

    // Example 2: Solana SIWX
    println!("2. Solana SIWX Message:");
    let sol_message = SiwxMessage::new_with_chain(
        "example.com",
        "11111111111111111111111111111112",
        "https://example.com/login",
        "1",
        chrono::Utc::now().to_rfc3339(),
        SiwxMessage::generate_nonce(),
        Chain::Solana,
    )
    .with_statement("Sign in to Example App");

    println!("Message to sign:");
    println!("{}", sol_message.message_to_sign()?);
    println!();

    // Example 3: Signature verification setup
    println!("3. Signature Verification Setup:");
    let eth_verifier = VerifierFactory::ethereum();
    let sol_verifier = VerifierFactory::solana();

    println!("Ethereum verifier created with {} backends", eth_verifier.backend_count());
    println!("Solana verifier created with {} backends", sol_verifier.backend_count());
    println!();

    // Example 4: Message validation
    println!("4. Message Validation:");
    println!("Ethereum message valid: {}", eth_message.validate().is_ok());
    println!("Solana message valid: {}", sol_message.validate().is_ok());
    println!("Ethereum message expired: {}", eth_message.is_expired()?);
    println!("Solana message expired: {}", sol_message.is_expired()?);

    Ok(())
} 