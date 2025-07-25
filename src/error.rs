use thiserror::Error;

/// Custom error type for SIWX operations
#[derive(Error, Debug)]
pub enum SiwxError {
    #[error("Invalid message format: {0}")]
    InvalidMessageFormat(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Unsupported chain: {0}")]
    UnsupportedChain(String),

    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("Message expired")]
    MessageExpired,

    #[error("Invalid nonce")]
    InvalidNonce,

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Other error: {0}")]
    Other(String),
}

/// Result type for SIWX operations
pub type SiwxResult<T> = Result<T, SiwxError>;

impl From<String> for SiwxError {
    fn from(err: String) -> Self {
        SiwxError::Other(err)
    }
}

impl From<&str> for SiwxError {
    fn from(err: &str) -> Self {
        SiwxError::Other(err.to_string())
    }
}
