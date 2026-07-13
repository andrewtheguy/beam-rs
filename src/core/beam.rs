use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::time::{SystemTime, UNIX_EPOCH};

/// Current token format version
pub const CURRENT_VERSION: u8 = 5;

/// TTL for beam sessions in seconds (1 hour)
pub const SESSION_TTL_SECS: u64 = 3600;

/// Protocol identifier for iroh transport
pub const PROTOCOL_IROH: &str = "iroh";

/// Protocol identifier for tor transport
pub const PROTOCOL_TOR: &str = "tor";

/// Minimum base64url-encoded beam code length.
/// A minimal token payload is ~20+ bytes, which base64 encodes to ~30+ characters.
const MIN_CODE_LENGTH: usize = 30;

/// Validate a Tor v3 onion address format.
///
/// A valid v3 onion address:
/// - Ends with ".onion"
/// - Has exactly 56 base32 characters before the ".onion" suffix
/// - Uses only lowercase letters a-z and digits 2-7 (base32 alphabet)
///
/// # Returns
/// `Ok(())` if valid, `Err` with descriptive message if invalid.
fn validate_onion_address(addr: &str) -> Result<()> {
    if !addr.ends_with(".onion") {
        anyhow::bail!("Onion address must end with '.onion'");
    }

    let without_suffix = addr.strip_suffix(".onion").unwrap();

    // V3 onion addresses are exactly 56 base32 characters
    if without_suffix.len() != 56 {
        anyhow::bail!(
            "Invalid v3 onion address: expected 56 characters before '.onion', got {}",
            without_suffix.len()
        );
    }

    // Base32 alphabet for Tor: a-z and 2-7
    if !without_suffix
        .chars()
        .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
    {
        anyhow::bail!("Invalid v3 onion address: contains invalid characters (expected a-z, 2-7)");
    }

    Ok(())
}

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
    /// Protocol identifier (e.g., "iroh", "tor")
    pub protocol: String,
    /// Unix timestamp when this token was created (for TTL validation)
    pub created_at: u64,
    /// AES-256-GCM key as base64 string (always present for iroh/tor)
    pub key: String,
    /// Minimal endpoint address for connection (None for non-iroh transports)
    /// Contains only node ID and relay URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<MinimalAddr>,

    // Tor-specific fields:
    /// Onion address for Tor hidden service (e.g., "abc123...xyz.onion")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onion_address: Option<String>,
}

/// Get current Unix timestamp in seconds
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System clock is set before Unix epoch")
        .as_secs()
}

/// Generate a beam code for Tor transfer
/// Format: base64url(json(BeamToken))
///
/// # Arguments
/// * `onion_address` - The .onion address of the hidden service (v3 format)
/// * `key` - The encryption key (required)
///
/// # Errors
///
/// Returns an error if the onion address is not a valid v3 format.
pub fn generate_tor_code(onion_address: String, key: &[u8; 32]) -> Result<String> {
    // Validate onion address format early to fail fast
    validate_onion_address(&onion_address).context("Invalid onion address in generate_tor_code")?;

    let token = BeamToken {
        version: CURRENT_VERSION,
        protocol: PROTOCOL_TOR.to_string(),
        created_at: current_timestamp(),
        key: URL_SAFE_NO_PAD.encode(key),
        addr: None,
        onion_address: Some(onion_address),
    };

    let serialized = serde_json::to_vec(&token).context("Failed to serialize beam token")?;

    Ok(URL_SAFE_NO_PAD.encode(&serialized))
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
    if token.protocol != PROTOCOL_IROH && token.protocol != PROTOCOL_TOR {
        anyhow::bail!(
            "Invalid protocol '{}'. Supported protocols: '{}', '{}'",
            token.protocol,
            PROTOCOL_IROH,
            PROTOCOL_TOR
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

    // Validate key format (required for all current protocols)
    let key_bytes = URL_SAFE_NO_PAD
        .decode(&token.key)
        .context("Invalid key format: not valid base64")?;
    if key_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid key length: expected 32 bytes, got {}",
            key_bytes.len()
        );
    }

    // For iroh protocol, ensure addr is present
    if token.protocol == PROTOCOL_IROH && token.addr.is_none() {
        anyhow::bail!("Invalid iroh token: missing endpoint address");
    }

    // For tor protocol, ensure onion_address is present and valid
    if token.protocol == PROTOCOL_TOR {
        match &token.onion_address {
            None => anyhow::bail!("Invalid tor token: missing onion address"),
            Some(addr) => {
                validate_onion_address(addr).context("Invalid tor token")?;
            }
        }
    }

    Ok(token)
}

/// Helper function to decode a base64 key from BeamToken into a 32-byte array
pub fn decode_key(key_str: &str) -> Result<[u8; 32]> {
    let key_bytes = URL_SAFE_NO_PAD
        .decode(key_str)
        .context("Failed to decode base64 key")?;

    if key_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid key length: expected 32 bytes, got {}",
            key_bytes.len()
        );
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}
