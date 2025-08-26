use crate::{Chain, SiwxError, SiwxResult};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// SIWX message following EIP-4361 standard
#[cfg_attr(feature = "typeshare", typeshare::typeshare)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiwxMessage {
    /// The domain requesting the signing
    pub domain: String,
    /// The Ethereum/Solana address performing the signing
    pub address: String,
    /// A human-readable ASCII assertion that the user will sign
    pub statement: Option<String>,
    /// A URI that identifies the resource that is the subject of the signing
    pub uri: String,
    /// The current version of the message
    pub version: String,
    /// The EIP-155 chain ID to which the session is bound
    pub chain_id: u64,
    /// A randomized token used to prevent replay attacks
    pub nonce: String,
    /// The ISO 8601 datetime string of when the message was issued
    pub issued_at: String,
    /// The ISO 8601 datetime string that indicates when the signed message is no longer valid
    pub expiration_time: Option<String>,
    /// The ISO 8601 datetime string of when the message was not before valid
    pub not_before: Option<String>,
    /// A system-specific identifier that may be used to uniquely refer to the sign-in request
    pub request_id: Option<String>,
    /// A list of information or references to information the user wishes to have resolved
    pub resources: Option<Vec<String>>,
    /// Additional fields specific to the chain
    #[serde(flatten)]
    pub chain_specific: HashMap<String, String>,
}

impl SiwxMessage {
    /// Create a new SIWX message
    pub fn new(
        domain: impl Into<String>,
        address: impl Into<String>,
        uri: impl Into<String>,
        version: impl Into<String>,
        issued_at: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            domain: domain.into(),
            address: address.into(),
            statement: None,
            uri: uri.into(),
            version: version.into(),
            chain_id: Chain::Ethereum.chain_id(),
            nonce: nonce.into(),
            issued_at: issued_at.into(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: None,
            chain_specific: HashMap::new(),
        }
    }

    /// Create a new SIWX message with chain specification
    pub fn new_with_chain(
        domain: impl Into<String>,
        address: impl Into<String>,
        uri: impl Into<String>,
        version: impl Into<String>,
        issued_at: impl Into<String>,
        nonce: impl Into<String>,
        chain: Chain,
    ) -> Self {
        Self {
            domain: domain.into(),
            address: address.into(),
            statement: None,
            uri: uri.into(),
            version: version.into(),
            chain_id: chain.chain_id(),
            nonce: nonce.into(),
            issued_at: issued_at.into(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: None,
            chain_specific: HashMap::new(),
        }
    }

    /// Set the statement field
    pub fn with_statement(mut self, statement: impl Into<String>) -> Self {
        self.statement = Some(statement.into());
        self
    }

    /// Set the expiration time
    pub fn with_expiration_time(mut self, expiration_time: impl Into<String>) -> Self {
        self.expiration_time = Some(expiration_time.into());
        self
    }

    /// Set the not before time
    pub fn with_not_before(mut self, not_before: impl Into<String>) -> Self {
        self.not_before = Some(not_before.into());
        self
    }

    /// Set the request ID
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Add resources
    pub fn with_resources(mut self, resources: Vec<String>) -> Self {
        self.resources = Some(resources);
        self
    }

    /// Add a chain-specific field
    pub fn with_chain_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.chain_specific.insert(key.into(), value.into());
        self
    }

    /// Validate the message format
    pub fn validate(&self) -> SiwxResult<()> {
        // Validate domain
        if self.domain.is_empty() {
            return Err(SiwxError::InvalidMessageFormat(
                "Domain cannot be empty".into(),
            ));
        }

        // Validate address format based on chain
        let chain = self.detect_chain();
        self.validate_address(&chain)?;

        // Validate URI
        if self.uri.is_empty() {
            return Err(SiwxError::InvalidMessageFormat(
                "URI cannot be empty".into(),
            ));
        }

        // Validate version
        if self.version.is_empty() {
            return Err(SiwxError::InvalidMessageFormat(
                "Version cannot be empty".into(),
            ));
        }

        // Validate nonce
        if self.nonce.is_empty() {
            return Err(SiwxError::InvalidMessageFormat(
                "Nonce cannot be empty".into(),
            ));
        }

        // Validate issued_at
        self.validate_timestamp(&self.issued_at)?;

        // Validate expiration_time if present
        if let Some(ref exp) = self.expiration_time {
            self.validate_timestamp(exp)?;
        }

        // Validate not_before if present
        if let Some(ref nb) = self.not_before {
            self.validate_timestamp(nb)?;
        }

        Ok(())
    }

    /// Detect the chain from the chain_id
    pub fn detect_chain(&self) -> Chain {
        match self.chain_id {
            1 => Chain::Ethereum,
            11155111 => Chain::EthereumTestnet, // Sepolia
            101 => Chain::Solana,
            102 => Chain::SolanaTestnet,
            _ => Chain::Ethereum, // Default fallback
        }
    }

    /// Get the message to sign based on the chain
    pub fn message_to_sign(&self) -> SiwxResult<String> {
        self.validate()?;
        let chain = self.detect_chain();

        match chain {
            Chain::Ethereum | Chain::EthereumTestnet => self.to_ethereum_format(),
            Chain::Solana | Chain::SolanaTestnet => self.to_solana_format(),
        }
    }

    /// Format message for Ethereum (EIP-191 personal_sign)
    fn to_ethereum_format(&self) -> SiwxResult<String> {
        let mut lines = Vec::new();

        // Header
        lines.push(format!(
            "{} wants you to sign in with your Ethereum account:",
            self.domain
        ));
        lines.push(self.address.clone());
        lines.push("".to_string());

        // Statement if present
        if let Some(ref statement) = self.statement {
            lines.push(statement.clone());
            lines.push("".to_string());
        }

        // URI
        lines.push(format!("URI: {}", self.uri));

        // Version
        lines.push(format!("Version: {}", self.version));

        // Chain ID
        lines.push(format!("Chain ID: {}", self.chain_id));

        // Nonce
        lines.push(format!("Nonce: {}", self.nonce));

        // Issued At
        lines.push(format!("Issued At: {}", self.issued_at));

        // Expiration Time
        if let Some(ref exp) = self.expiration_time {
            lines.push(format!("Expiration Time: {}", exp));
        }

        // Not Before
        if let Some(ref nb) = self.not_before {
            lines.push(format!("Not Before: {}", nb));
        }

        // Request ID
        if let Some(ref rid) = self.request_id {
            lines.push(format!("Request ID: {}", rid));
        }

        // Resources
        if let Some(ref resources) = self.resources {
            lines.push("Resources:".to_string());
            for resource in resources {
                lines.push(format!("- {}", resource));
            }
        }

        Ok(lines.join("\n"))
    }

    /// Format message for Solana
    fn to_solana_format(&self) -> SiwxResult<String> {
        let mut lines = Vec::new();

        // Header
        lines.push(format!(
            "{} wants you to sign in with your Solana account:",
            self.domain
        ));
        lines.push(self.address.clone());
        lines.push("".to_string());

        // Statement if present
        if let Some(ref statement) = self.statement {
            lines.push(statement.clone());
            lines.push("".to_string());
        }

        // URI
        lines.push(format!("URI: {}", self.uri));

        // Version
        lines.push(format!("Version: {}", self.version));

        // Chain ID
        lines.push(format!("Chain ID: {}", self.chain_id));

        // Nonce
        lines.push(format!("Nonce: {}", self.nonce));

        // Issued At
        lines.push(format!("Issued At: {}", self.issued_at));

        // Expiration Time
        if let Some(ref exp) = self.expiration_time {
            lines.push(format!("Expiration Time: {}", exp));
        }

        // Not Before
        if let Some(ref nb) = self.not_before {
            lines.push(format!("Not Before: {}", nb));
        }

        // Request ID
        if let Some(ref rid) = self.request_id {
            lines.push(format!("Request ID: {}", rid));
        }

        // Resources
        if let Some(ref resources) = self.resources {
            lines.push("Resources:".to_string());
            for resource in resources {
                lines.push(format!("- {}", resource));
            }
        }

        Ok(lines.join("\n"))
    }

    /// Validate address format
    fn validate_address(&self, chain: &Chain) -> SiwxResult<()> {
        let pattern = chain.address_pattern();
        let regex = Regex::new(pattern).map_err(|e| {
            SiwxError::InvalidMessageFormat(format!("Invalid regex pattern: {}", e))
        })?;

        if !regex.is_match(&self.address) {
            return Err(SiwxError::InvalidAddress(format!(
                "Address {} does not match pattern for chain {}",
                self.address, chain
            )));
        }

        Ok(())
    }

    /// Validate timestamp format
    fn validate_timestamp(&self, timestamp: &str) -> SiwxResult<()> {
        DateTime::parse_from_rfc3339(timestamp)
            .map_err(|e| SiwxError::InvalidTimestamp(format!("Invalid timestamp format: {}", e)))?;
        Ok(())
    }

    /// Check if the message has expired
    pub fn is_expired(&self) -> SiwxResult<bool> {
        if let Some(ref expiration_time) = self.expiration_time {
            let expiration = DateTime::parse_from_rfc3339(expiration_time).map_err(|e| {
                SiwxError::InvalidTimestamp(format!("Invalid expiration time: {}", e))
            })?;
            let now = Utc::now();
            Ok(now > expiration.with_timezone(&Utc))
        } else {
            Ok(false)
        }
    }

    /// Check if the message is valid for signing (not before time)
    pub fn is_valid_for_signing(&self) -> SiwxResult<bool> {
        if let Some(ref not_before) = self.not_before {
            let not_before_time = DateTime::parse_from_rfc3339(not_before).map_err(|e| {
                SiwxError::InvalidTimestamp(format!("Invalid not_before time: {}", e))
            })?;
            let now = Utc::now();
            Ok(now >= not_before_time.with_timezone(&Utc))
        } else {
            Ok(true)
        }
    }

    /// Generate a random nonce
    pub fn generate_nonce() -> String {
        Uuid::new_v4().to_string()
    }

    /// Create a message with current timestamp
    pub fn new_with_current_time(
        domain: impl Into<String>,
        address: impl Into<String>,
        uri: impl Into<String>,
        version: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        let now = Utc::now().to_rfc3339();
        Self::new(domain, address, uri, version, now, nonce)
    }
}

impl fmt::Display for SiwxMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.message_to_sign().unwrap_or_else(|err| err.to_string())
        )
    }
}

impl Default for SiwxMessage {
    fn default() -> Self {
        Self::new_with_current_time(
            "example.com",
            "0x0000000000000000000000000000000000000000",
            "https://example.com/login",
            "1",
            Self::generate_nonce(),
        )
    }
}

impl FromStr for SiwxMessage {
    type Err = SiwxError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        // Helper to get next line safely
        fn next_line<'a>(
            lines: &mut std::iter::Peekable<std::str::Lines<'a>>,
        ) -> Result<&'a str, SiwxError> {
            lines
                .next()
                .ok_or_else(|| SiwxError::InvalidMessageFormat("Unexpected end of message".into()))
        }

        let mut lines = input.lines().peekable();

        // Header: "<domain> wants you to sign in with your <Chain> account:"
        let header = next_line(&mut lines)?;
        let wants_marker = " wants you to sign in with your ";
        let account_suffix = " account:";
        let (domain, chain_label) = {
            let domain_end = header.find(wants_marker).ok_or_else(|| {
                SiwxError::InvalidMessageFormat("Invalid header: missing marker".into())
            })?;
            let domain = &header[..domain_end];
            let after = &header[domain_end + wants_marker.len()..];
            let chain_end = after.rfind(account_suffix).ok_or_else(|| {
                SiwxError::InvalidMessageFormat("Invalid header: missing account suffix".into())
            })?;
            let chain = &after[..chain_end];
            (domain.trim().to_string(), chain.trim().to_string())
        };

        // Address line
        let address = next_line(&mut lines)?.trim().to_string();

        // Expect a blank line
        let maybe_blank = next_line(&mut lines)?;
        if !maybe_blank.trim().is_empty() {
            return Err(SiwxError::InvalidMessageFormat(
                "Expected blank line after address".into(),
            ));
        }

        // Optional statement (single-line), followed by a blank line
        let mut statement: Option<String> = None;
        if let Some(&peek) = lines.peek() {
            if !(peek.starts_with("URI:")
                || peek.starts_with("Version:")
                || peek.starts_with("Chain ID:")
                || peek.starts_with("Nonce:")
                || peek.starts_with("Issued At:")
                || peek.starts_with("Expiration Time:")
                || peek.starts_with("Not Before:")
                || peek.starts_with("Request ID:")
                || peek.starts_with("Resources:"))
            {
                // Treat as statement
                let stmt_line = next_line(&mut lines)?;
                statement = Some(stmt_line.to_string());

                // The generator adds a blank line after the statement
                let after_stmt_blank = next_line(&mut lines)?;
                if !after_stmt_blank.trim().is_empty() {
                    return Err(SiwxError::InvalidMessageFormat(
                        "Expected blank line after statement".into(),
                    ));
                }
            }
        }

        // Parse key/value lines
        let mut resources: Option<Vec<String>> = None;

        // Helper to parse a prefixed line
        let mut parse_prefixed = |prefix: &str| -> Option<String> {
            if let Some(&line) = lines.peek() {
                if let Some(rest) = line.strip_prefix(prefix) {
                    let _ = lines.next();
                    return Some(rest.trim().to_string());
                }
            }
            None
        };

        // Required in this order per generator output
        let uri = parse_prefixed("URI: ");
        let version = parse_prefixed("Version: ");
        let chain_id = if let Some(cid_str) = parse_prefixed("Chain ID: ") {
            Some(cid_str.parse::<u64>().map_err(|_| {
                SiwxError::InvalidMessageFormat("Chain ID must be a positive integer".into())
            })?)
        } else {
            None
        };
        let nonce = parse_prefixed("Nonce: ");
        let issued_at = parse_prefixed("Issued At: ");

        // Optional fields in the same order
        let expiration_time = parse_prefixed("Expiration Time: ");
        let not_before = parse_prefixed("Not Before: ");
        let request_id = parse_prefixed("Request ID: ");

        // Resources block
        if let Some(&line) = lines.peek() {
            if line.trim() == "Resources:" {
                let _ = lines.next();
                let mut list = Vec::new();
                while let Some(&res_line) = lines.peek() {
                    if let Some(item) = res_line.strip_prefix("- ") {
                        let _ = lines.next();
                        list.push(item.trim().to_string());
                    } else {
                        break;
                    }
                }
                resources = Some(list);
            }
        }

        // Ensure required fields are present
        let uri = uri.ok_or_else(|| SiwxError::InvalidMessageFormat("Missing URI".into()))?;
        let version =
            version.ok_or_else(|| SiwxError::InvalidMessageFormat("Missing Version".into()))?;
        let chain_id =
            chain_id.ok_or_else(|| SiwxError::InvalidMessageFormat("Missing Chain ID".into()))?;
        let nonce = nonce.ok_or_else(|| SiwxError::InvalidMessageFormat("Missing Nonce".into()))?;
        let issued_at =
            issued_at.ok_or_else(|| SiwxError::InvalidMessageFormat("Missing Issued At".into()))?;

        // Optionally, ensure header chain label broadly matches chain_id family (best-effort)
        let header_ok = match chain_label.as_str() {
            "Ethereum" => matches!(chain_id, 1 | 11155111),
            "Solana" => matches!(chain_id, 101 | 102),
            _ => true,
        };
        if !header_ok {
            return Err(SiwxError::InvalidMessageFormat(
                "Header chain does not match Chain ID".into(),
            ));
        }

        let msg = SiwxMessage {
            domain,
            address,
            statement,
            uri,
            version,
            chain_id,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
            chain_specific: HashMap::new(),
        };

        // Run validations to normalize errors
        msg.validate()?;
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn test_siwx_message_creation() {
        let message = SiwxMessage::new(
            "example.com",
            "0x1234567890123456789012345678901234567890",
            "https://example.com/login",
            "1",
            "2024-01-01T00:00:00Z",
            "nonce123",
        );

        assert_eq!(message.domain, "example.com");
        assert_eq!(
            message.address,
            "0x1234567890123456789012345678901234567890"
        );
        assert_eq!(message.uri, "https://example.com/login");
        assert_eq!(message.version, "1");
        assert_eq!(message.nonce, "nonce123");
    }

    #[test]
    fn test_ethereum_message_format() {
        let message = SiwxMessage::new(
            "example.com",
            "0x1234567890123456789012345678901234567890",
            "https://example.com/login",
            "1",
            "2024-01-01T00:00:00Z",
            "nonce123",
        );

        let formatted = message.message_to_sign().unwrap();
        assert!(formatted.contains("example.com wants you to sign in with your Ethereum account:"));
        assert!(formatted.contains("0x1234567890123456789012345678901234567890"));
        assert!(formatted.contains("URI: https://example.com/login"));
        assert!(formatted.contains("Nonce: nonce123"));
    }

    #[test]
    fn test_address_validation() {
        let valid_eth_message = SiwxMessage::new(
            "example.com",
            "0x1234567890123456789012345678901234567890",
            "https://example.com/login",
            "1",
            "2024-01-01T00:00:00Z",
            "nonce123",
        );
        assert!(valid_eth_message.validate().is_ok());

        let invalid_eth_message = SiwxMessage::new(
            "example.com",
            "invalid_address",
            "https://example.com/login",
            "1",
            "2024-01-01T00:00:00Z",
            "nonce123",
        );
        assert!(invalid_eth_message.validate().is_err());
    }

    #[test]
    fn test_expiration_check() {
        let now = Utc::now();
        let expired = now - Duration::hours(1);
        let future = now + Duration::hours(1);

        let expired_message = SiwxMessage::new(
            "example.com",
            "0x1234567890123456789012345678901234567890",
            "https://example.com/login",
            "1",
            expired.to_rfc3339(),
            "nonce123",
        )
        .with_expiration_time(expired.to_rfc3339());

        let future_message = SiwxMessage::new(
            "example.com",
            "0x1234567890123456789012345678901234567890",
            "https://example.com/login",
            "1",
            now.to_rfc3339(),
            "nonce123",
        )
        .with_expiration_time(future.to_rfc3339());

        assert!(expired_message.is_expired().unwrap());
        assert!(!future_message.is_expired().unwrap());
    }

    #[test]
    fn test_parse_plaintext_ethereum() {
        let message = SiwxMessage::new(
            "example.com",
            "0x1234567890123456789012345678901234567890",
            "https://example.com/login",
            "1",
            "2024-01-01T00:00:00Z",
            "nonce123",
        )
        .with_statement("Sign in to Example App")
        .with_expiration_time("2024-01-01T01:00:00Z");

        let text = message.message_to_sign().unwrap();
        let parsed: SiwxMessage = text.parse().unwrap();

        assert_eq!(parsed.domain, message.domain);
        assert_eq!(parsed.address, message.address);
        assert_eq!(parsed.statement, message.statement);
        assert_eq!(parsed.uri, message.uri);
        assert_eq!(parsed.version, message.version);
        assert_eq!(parsed.chain_id, message.chain_id);
        assert_eq!(parsed.nonce, message.nonce);
        assert_eq!(parsed.issued_at, message.issued_at);
        assert_eq!(parsed.expiration_time, message.expiration_time);
    }

    #[test]
    fn test_parse_plaintext_solana() {
        let message = SiwxMessage::new_with_chain(
            "example.com",
            "11111111111111111111111111111112",
            "https://example.com/login",
            "1",
            "2024-01-01T00:00:00Z",
            "nonce123",
            Chain::Solana,
        );

        let text = message.message_to_sign().unwrap();
        let parsed: SiwxMessage = text.parse().unwrap();

        assert_eq!(parsed.domain, message.domain);
        assert_eq!(parsed.address, message.address);
        assert_eq!(parsed.chain_id, message.chain_id);
    }
}
