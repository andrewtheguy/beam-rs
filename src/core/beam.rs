use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::time::{SystemTime, UNIX_EPOCH};

/// Current token format version
pub const CURRENT_VERSION: u8 = 7;

/// TTL for beam sessions in seconds (1 hour)
pub const SESSION_TTL_SECS: u64 = 3600;

/// Protocol identifier for iroh transport
pub const PROTOCOL_IROH: &str = "iroh";

/// Minimum base64url-encoded beam code length.
/// A minimal token payload is ~20+ bytes, which base64 encodes to ~30+ characters.
const MIN_CODE_LENGTH: usize = 30;

/// Minimal address for serialization - only contains node ID and relay URL.
/// Only one relay URL is kept (the endpoint's currently-selected best relay) to keep
/// tokens compact for copy/paste.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MinimalAddr {
    /// Node ID (hex-encoded public key)
    pub id: String,
    /// Best relay URL at token creation time (only the first/selected relay is kept
    /// to minimize token size for copy/paste usability)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// Custom relay URLs the sender was configured with (via `--relay-url`).
    ///
    /// Empty when the sender used the default public relays. When non-empty, the
    /// receiver configures its own endpoint with these as a custom relay map
    /// (instead of the default relays), so a self-hosted relay deployment needs no
    /// relay configuration on the receiver side — the relays travel in the code.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_urls: Vec<String>,
}

/// Beam token containing all transfer metadata
/// This is a self-describing format that includes version, protocol, and encryption info
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeamToken {
    /// Token format version (for future compatibility checks)
    pub version: u8,
    /// Protocol identifier (currently always "iroh")
    pub protocol: String,
    /// Unix timestamp when this token was created (for TTL validation)
    pub created_at: u64,
    /// Base64-encoded 256-bit secret used to authorize the receiver and derive
    /// the content key.
    pub key: String,
    /// Minimal endpoint address for connection.
    /// Contains only node ID and relay URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<MinimalAddr>,
}

/// Get current Unix timestamp in seconds
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System clock is set before Unix epoch")
        .as_secs()
}

/// Validate beam code format without fully parsing it.
/// Performs lightweight checks (empty, invalid characters, minimum length)
/// without decoding. Returns Ok(()) if the format looks valid.
pub fn validate_code_format(code: &str) -> Result<()> {
    let code = code.trim();

    if code.is_empty() {
        anyhow::bail!("Beam code cannot be empty");
    }

    // Check for invalid characters (base64 URL-safe uses A-Z, a-z, 0-9, -, _)
    // Note: no padding (=) in URL_SAFE_NO_PAD
    if !code
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!(
            "Invalid beam code: contains invalid characters. Expected base64url-encoded string."
        );
    }

    // Minimum length check: minimal token data
    if code.len() < MIN_CODE_LENGTH {
        anyhow::bail!("Invalid beam code: too short. Make sure you copied the entire code.");
    }

    Ok(())
}

/// Parse a beam code to extract the token
/// Returns a BeamToken containing all transfer metadata
pub fn parse_code(code: &str) -> Result<BeamToken> {
    // Validate format first for better error messages
    validate_code_format(code)?;

    let serialized = URL_SAFE_NO_PAD
        .decode(code.trim())
        .context("Invalid beam code: not valid base64url encoding")?;

    if serialized.len() < 10 {
        anyhow::bail!("Invalid beam code: decoded data too short");
    }

    let token: BeamToken = serde_json::from_slice(&serialized)
        .context("Invalid beam code: failed to parse token. Make sure the code is correct.")?;

    // Validate version
    if token.version != CURRENT_VERSION {
        anyhow::bail!(
            "Unsupported token version {}. This receiver requires version {}.",
            token.version,
            CURRENT_VERSION
        );
    }

    // Validate protocol
    if token.protocol != PROTOCOL_IROH {
        anyhow::bail!(
            "Invalid protocol '{}'. Supported protocol: '{}'",
            token.protocol,
            PROTOCOL_IROH
        );
    }

    // Validate TTL
    let now = current_timestamp();
    if token.created_at > now + 60 {
        // Allow 60s clock skew into future
        anyhow::bail!("Invalid token: created_at is in the future. Check system clock.");
    }
    let age = now.saturating_sub(token.created_at);
    if age > SESSION_TTL_SECS {
        let minutes = age / 60;
        anyhow::bail!(
            "Token expired: code is {} minutes old (max {} minutes). \
             Please request a new code from the sender.",
            minutes,
            SESSION_TTL_SECS / 60
        );
    }

    // Validate the 256-bit secret/key format
    let key_bytes = URL_SAFE_NO_PAD
        .decode(&token.key)
        .context("Invalid key format: not valid base64")?;
    if key_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid key length: expected 32 bytes, got {}",
            key_bytes.len()
        );
    }

    // Ensure the endpoint address is present
    if token.addr.is_none() {
        anyhow::bail!("Invalid iroh token: missing endpoint address");
    }

    Ok(token)
}
