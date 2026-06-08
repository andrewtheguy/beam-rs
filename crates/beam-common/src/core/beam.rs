use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::time::{SystemTime, UNIX_EPOCH};

/// Current token format version
pub const CURRENT_VERSION: u8 = 4;

/// TTL for beam sessions in seconds (1 hour)
pub const SESSION_TTL_SECS: u64 = 3600;

/// Protocol identifier for iroh transport
pub const PROTOCOL_IROH: &str = "iroh";

/// Protocol identifier for tor transport
pub const PROTOCOL_TOR: &str = "tor";

/// Protocol identifier for webrtc transport (WebRTC + Nostr signaling)
pub const PROTOCOL_WEBRTC: &str = "webrtc";

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
    /// Direct socket addresses (host:port) for the endpoint.
    ///
    /// Normally empty — direct addresses are discovered at connect time via the
    /// relay or mDNS. In local-only mode there is no relay and mDNS resolution
    /// can be unreliable across platforms (notably macOS), so the sender embeds
    /// its LAN addresses here to let the receiver connect directly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_addrs: Vec<String>,
}


/// Beam token containing all transfer metadata
/// This is a self-describing format that includes version, protocol, and encryption info
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeamToken {
    /// Token format version (for future compatibility checks)
    pub version: u8,
    /// Protocol identifier (e.g., "iroh", "tor", "webrtc")
    pub protocol: String,
    /// Unix timestamp when this token was created (for TTL validation)
    pub created_at: u64,
    /// AES-256-GCM key as base64 string (always present for iroh/tor/webrtc)
    pub key: String,
    /// Minimal endpoint address for connection (None for non-iroh transports)
    /// Contains only node ID and relay URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<MinimalAddr>,

    // Tor-specific fields:
    /// Onion address for Tor hidden service (e.g., "abc123...xyz.onion")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onion_address: Option<String>,

    // WebRTC-specific fields:
    /// Sender's ephemeral Nostr public key for signaling (hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webrtc_sender_pubkey: Option<String>,
    /// Unique transfer session ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webrtc_transfer_id: Option<String>,
    /// List of Nostr relay URLs for signaling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webrtc_relays: Option<Vec<String>>,
    /// Transfer type: "file" or "folder"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webrtc_transfer_type: Option<String>,
    /// Original filename for webrtc transfers
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webrtc_filename: Option<String>,
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
        webrtc_sender_pubkey: None,
        webrtc_transfer_id: None,
        webrtc_relays: None,
        webrtc_transfer_type: None,
        webrtc_filename: None,
    };

    let serialized = serde_json::to_vec(&token).context("Failed to serialize beam token")?;

    Ok(URL_SAFE_NO_PAD.encode(&serialized))
}

/// Generate a beam code for webrtc transfer (WebRTC + Nostr signaling)
/// Format: base64url(json(BeamToken))
///
/// # Arguments
/// * `key` - The AES-256-GCM encryption key (always required for webrtc)
/// * `sender_pubkey` - Sender's ephemeral Nostr public key for signaling (hex)
/// * `transfer_id` - Unique transfer session ID
/// * `relays` - List of Nostr relay URLs for signaling
/// * `filename` - Original filename
/// * `transfer_type` - "file" or "folder"
///
/// # Errors
///
/// Returns an error if `transfer_type` is not "file" or "folder".
pub fn generate_webrtc_code(
    key: &[u8; 32],
    sender_pubkey: String,
    transfer_id: String,
    relays: Option<Vec<String>>,
    filename: String,
    transfer_type: &str,
) -> Result<String> {
    // Validate transfer_type early to fail fast
    if transfer_type != "file" && transfer_type != "folder" {
        anyhow::bail!(
            "Invalid transfer_type: '{}' (expected 'file' or 'folder')",
            transfer_type
        );
    }

    // Validate sender_pubkey format (Nostr x-only Schnorr pubkey: 32 bytes = 64 hex chars)
    if sender_pubkey.len() != 64 || !sender_pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!(
            "Invalid sender_pubkey: expected 64-character hex string (32-byte Nostr pubkey), got {} chars",
            sender_pubkey.len()
        );
    }

    // Validate transfer_id is non-empty
    if transfer_id.trim().is_empty() {
        anyhow::bail!("Invalid transfer_id: cannot be empty");
    }

    // Validate filename is non-empty and doesn't contain path separators
    if filename.trim().is_empty() {
        anyhow::bail!("Invalid filename: cannot be empty");
    }
    if filename.contains('/') || filename.contains('\\') {
        anyhow::bail!("Invalid filename: cannot contain path separators");
    }

    // Validate relay URLs if provided
    if let Some(ref relay_list) = relays {
        if relay_list.is_empty() {
            anyhow::bail!("Invalid relays: list cannot be empty if provided");
        }
        for relay in relay_list {
            if !relay.starts_with("ws://") && !relay.starts_with("wss://") {
                anyhow::bail!(
                    "Invalid relay URL '{}': must start with ws:// or wss://",
                    relay
                );
            }
        }
    }

    let token = BeamToken {
        version: CURRENT_VERSION,
        protocol: PROTOCOL_WEBRTC.to_string(),
        created_at: current_timestamp(),
        key: URL_SAFE_NO_PAD.encode(key),
        addr: None,
        onion_address: None,
        webrtc_sender_pubkey: Some(sender_pubkey),
        webrtc_transfer_id: Some(transfer_id),
        webrtc_relays: relays,
        webrtc_transfer_type: Some(transfer_type.to_string()),
        webrtc_filename: Some(filename),
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
    if token.protocol != PROTOCOL_IROH
        && token.protocol != PROTOCOL_TOR
        && token.protocol != PROTOCOL_WEBRTC
    {
        anyhow::bail!(
            "Invalid protocol '{}'. Supported protocols: '{}', '{}', '{}'",
            token.protocol,
            PROTOCOL_IROH,
            PROTOCOL_TOR,
            PROTOCOL_WEBRTC
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

    // For webrtc protocol, ensure webrtc fields are present and valid
    if token.protocol == PROTOCOL_WEBRTC {
        if token.webrtc_sender_pubkey.is_none() {
            anyhow::bail!("Invalid webrtc token: missing sender pubkey");
        }
        if token.webrtc_transfer_id.is_none() {
            anyhow::bail!("Invalid webrtc token: missing transfer ID");
        }
        if token.webrtc_filename.is_none() {
            anyhow::bail!("Invalid webrtc token: missing filename");
        }
        match token.webrtc_transfer_type.as_deref() {
            Some("file") | Some("folder") => {}
            Some(invalid) => {
                anyhow::bail!(
                    "Invalid webrtc token: unsupported transfer type '{}' (expected 'file' or 'folder')",
                    invalid
                );
            }
            None => {
                anyhow::bail!("Invalid webrtc token: missing transfer type");
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
