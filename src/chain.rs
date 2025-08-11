use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported blockchain networks
#[typeshare::typeshare]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Chain {
    /// Ethereum mainnet
    Ethereum,
    /// Ethereum testnets (Goerli, Sepolia, etc.)
    EthereumTestnet,
    /// Solana mainnet
    Solana,
    /// Solana testnet/devnet
    SolanaTestnet,
}

impl Chain {
    /// Get the chain ID for the blockchain
    pub fn chain_id(&self) -> u64 {
        match self {
            Chain::Ethereum => 1,
            Chain::EthereumTestnet => 11155111, // Sepolia
            Chain::Solana => 101,
            Chain::SolanaTestnet => 102,
        }
    }

    /// Get the human-readable name of the chain
    pub fn name(&self) -> &'static str {
        match self {
            Chain::Ethereum => "Ethereum",
            Chain::EthereumTestnet => "Ethereum Testnet",
            Chain::Solana => "Solana",
            Chain::SolanaTestnet => "Solana Testnet",
        }
    }

    /// Get the chain prefix for SIWX messages
    pub fn prefix(&self) -> &'static str {
        match self {
            Chain::Ethereum | Chain::EthereumTestnet => "Ethereum",
            Chain::Solana | Chain::SolanaTestnet => "Solana",
        }
    }

    /// Check if this chain supports EIP-191 personal signatures
    pub fn supports_eip191(&self) -> bool {
        matches!(self, Chain::Ethereum | Chain::EthereumTestnet)
    }

    /// Check if this chain supports smart contract wallets
    pub fn supports_smart_contracts(&self) -> bool {
        matches!(self, Chain::Ethereum | Chain::EthereumTestnet)
    }

    /// Get the address validation regex pattern
    pub fn address_pattern(&self) -> &'static str {
        match self {
            Chain::Ethereum | Chain::EthereumTestnet => r"^0x[a-fA-F0-9]{40}$",
            Chain::Solana | Chain::SolanaTestnet => r"^[1-9A-HJ-NP-Za-km-z]{32,44}$",
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Default for Chain {
    fn default() -> Self {
        Chain::Ethereum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_properties() {
        assert_eq!(Chain::Ethereum.chain_id(), 1);
        assert_eq!(Chain::Ethereum.name(), "Ethereum");
        assert_eq!(Chain::Ethereum.prefix(), "Ethereum");
        assert!(Chain::Ethereum.supports_eip191());
        assert!(Chain::Ethereum.supports_smart_contracts());

        assert_eq!(Chain::Solana.chain_id(), 101);
        assert_eq!(Chain::Solana.name(), "Solana");
        assert_eq!(Chain::Solana.prefix(), "Solana");
        assert!(!Chain::Solana.supports_eip191());
        assert!(!Chain::Solana.supports_smart_contracts());
    }

    #[test]
    fn test_chain_display() {
        assert_eq!(Chain::Ethereum.to_string(), "Ethereum");
        assert_eq!(Chain::Solana.to_string(), "Solana");
    }
}
