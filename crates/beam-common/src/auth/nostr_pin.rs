//! PIN-based beam code exchange for Nostr transport.
//!
//! This module provides functions for:
//! - Deriving encryption keys from PINs using Argon2id
//! - Creating and parsing PIN exchange events (kind 24243)
//! - Encrypting/decrypting beam codes with PIN-derived keys
//!
//! # Security Notes
//!
//! ## PIN Hint Design
//!
//! The PIN hint is `Argon2id(PIN, salt = PIN_HINT_SALT || time_bucket)[0..16]` — a
//! 128-bit value that rotates every hour. It is published on the relay as a filter tag
//! so a receiver can locate the matching event without revealing the PIN. This design
//! prevents relay operators from correlating PIN usage across time windows, since the
//! same PIN produces a different hint each hour.
//!
//! Both the sender and receiver must derive the hint from the PIN alone (the receiver
//! has no other shared secret before it queries), so the hint cannot use the per-event
//! random Argon2id salt that protects the ciphertext. Instead it is **salted** with a
//! fixed, non-secret application constant (`PIN_HINT_SALT`) concatenated with the time
//! bucket, and **stretched** with the same Argon2id cost parameters used for key
//! derivation. The salt provides domain separation and defeats precomputed/cross-app
//! rainbow tables; the stretch makes each brute-force guess expensive.
//!
//! - **Time-based rotation**: Hint changes every hour (1-hour bucket size)
//! - **Ephemeral nature**: Events expire after 2 hours (2x bucket for boundary padding)
//! - **PIN entropy**: The PIN is 12 characters — 11 random characters drawn from a
//!   60-character unambiguous set plus 1 deterministic checksum character. The 11 random
//!   characters give `60^11 ≈ 2^65` (~65 bits) of entropy; the checksum adds none.
//! - **Salted + stretched**: An attacker holding the public hint must run Argon2id
//!   (64 MiB, t=3) once per candidate PIN, so brute-forcing the ~2^65 space is
//!   computationally infeasible. The fixed salt blocks precomputation.
//! - **Per-event KDF for the ciphertext**: Recovering the beam code additionally needs
//!   the per-event random salt plus another expensive Argon2id derivation.
//! - **Single-use**: Each transfer generates a new PIN, no rainbow table benefit
//!
//! The receiver queries with hints for both the current and previous time bucket to
//! handle transitions at bucket boundaries. The 128-bit hint provides high filtering
//! precision while the PIN's entropy and Argon2id stretching provide the actual security.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result};
use argon2::{Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use nostr_sdk::prelude::*;
use rand::RngCore;
use tokio::time::Duration;

use crate::auth::pin::{PIN_LENGTH, generate_pin};
use crate::core::beam::SESSION_TTL_SECS;

/// Result of fetching a beam code via PIN exchange.
pub struct PinExchangeResult {
    /// The decrypted beam code
    pub code: String,
    /// The transfer ID from the Nostr event's "t" tag
    pub transfer_id: String,
}

/// Default public Nostr relays for PIN exchange
/// These should match the relays used in signaling for consistency
pub const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://nos.lol",
    //"wss://relay.damus.io", // acceptable for index queries; not recommended for high-volume operations due to rate limiting
    //"wss://relay.nostr.band",
    "wss://relay.nostr.net",
    "wss://relay.primal.net",
    "wss://relay.snort.social",
];

/// Nostr event kind for PIN exchange (24243)
pub const PIN_EXCHANGE_KIND: u16 = 24243;

/// Salt length for Argon2id
pub const ARGON2_SALT_LEN: usize = 16;

/// PIN hint length in bytes (128 bits = 32 hex chars).
const PIN_HINT_LEN: usize = 16;

/// Fixed, non-secret application salt for PIN-hint derivation.
///
/// The hint must be derivable from the PIN alone (the receiver shares no other secret
/// before it queries), so it cannot use the per-event random salt that protects the
/// ciphertext. This constant is concatenated with the time bucket to form the Argon2id
/// salt: the bucket rotates the hint hourly, and the constant provides domain separation
/// and defeats precomputed/cross-application rainbow tables. It is NOT secret — the
/// security comes from the PIN entropy and the Argon2id stretch.
const PIN_HINT_SALT: &[u8] = b"beam-rs:nostr-pin-hint:v1";

/// AES-GCM nonce length
const AES_NONCE_LEN: usize = 12;

// Argon2id parameters
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_MEMORY_COST: u32 = 65536; // 64 MiB
const ARGON2_PARALLELISM: u32 = 4;

/// PIN exchange event expiration (2 hours).
///
/// Set to `2 * SESSION_TTL_SECS` so events survive across the bucket boundary.
/// Without this padding, events published early in bucket T would expire before
/// a receiver in bucket T+1 can query with the previous bucket's hint.
const PIN_EVENT_EXPIRATION_SECS: u64 = 2 * SESSION_TTL_SECS;

/// Timeout for waiting for relay connections
const RELAY_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Connect to Nostr relays for PIN operations.
///
/// Creates a client, adds the default relays, connects, and waits for at least
/// one successful connection. Returns the connected client or an error.
///
/// # Arguments
/// * `keys` - Optional signing keys. If provided, client is created with these keys.
///   If None, a default client is created.
/// * `purpose` - Description for log messages (e.g., "PIN exchange", "PIN lookup")
async fn connect_to_relays(keys: Option<&Keys>, purpose: &str) -> Result<Client> {
    let client = match keys {
        Some(k) => Client::new(k.clone()),
        None => Client::default(),
    };

    let mut relays_added = 0;
    for relay in DEFAULT_NOSTR_RELAYS {
        match client.add_relay(relay.to_string()).await {
            Ok(_) => {
                relays_added += 1;
                log::debug!("Added relay: {}", relay);
            }
            Err(e) => {
                log::warn!("Failed to add relay {}: {}", relay, e);
            }
        }
    }

    if relays_added == 0 {
        anyhow::bail!("Failed to add any relays for {}", purpose);
    }

    // Initiate connections to all added relays
    client.connect().await;

    // Wait for at least one relay to establish connection
    client.wait_for_connection(RELAY_CONNECTION_TIMEOUT).await;

    // Check connection status for each relay
    let relay_statuses = client.relays().await;
    let mut connected_relays = Vec::new();
    let mut failed_relays = Vec::new();

    for (url, relay) in &relay_statuses {
        if relay.is_connected() {
            connected_relays.push(url.to_string());
        } else {
            failed_relays.push(url.to_string());
        }
    }

    if connected_relays.is_empty() {
        client.disconnect().await;
        anyhow::bail!(
            "Failed to connect to any relays after {:?}. Tried: {}",
            RELAY_CONNECTION_TIMEOUT,
            failed_relays.join(", ")
        );
    }

    log::debug!(
        "Connected to {}/{} relays for {}: {}",
        connected_relays.len(),
        relays_added,
        purpose,
        connected_relays.join(", ")
    );

    if !failed_relays.is_empty() {
        log::debug!("Failed to connect to: {}", failed_relays.join(", "));
    }

    Ok(client)
}

/// Timeout for verifying event was published
const EVENT_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval for polling event verification
const EVENT_VERIFICATION_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Get the current time bucket index.
fn current_time_bucket() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_secs()
        / SESSION_TTL_SECS
}

/// Compute PIN hint for a specific time bucket.
///
/// The hint is `Argon2id(PIN, salt = PIN_HINT_SALT || bucket)[0..16]` — 128 bits
/// (16 bytes = 32 hex chars). The PIN is salted with a fixed application constant plus
/// the time bucket and stretched with Argon2id so that an attacker holding the public
/// hint must pay the full KDF cost per candidate PIN. See module docs for the rationale.
fn compute_pin_hint_for_bucket(pin: &str, bucket: u64) -> String {
    // Salt = fixed application salt || time bucket. The bucket rotates the hint hourly;
    // the constant provides domain separation and blocks precomputed tables.
    let mut salt = Vec::with_capacity(PIN_HINT_SALT.len() + 8);
    salt.extend_from_slice(PIN_HINT_SALT);
    salt.extend_from_slice(&bucket.to_be_bytes());

    let argon2 =
        argon2id_instance(PIN_HINT_LEN).expect("static Argon2 hint params are always valid");

    let mut hint = [0u8; PIN_HINT_LEN];
    argon2
        .hash_password_into(pin.as_bytes(), &salt, &mut hint)
        .expect("Argon2 hint derivation failed");

    hex::encode(hint) // 128 bits = 32 hex chars
}

/// Compute PIN hint for the current time bucket (used by sender).
///
/// The hint is `Argon2id(PIN, salt = PIN_HINT_SALT || time_bucket)[0..16]` — a 128-bit
/// value that rotates every hour, preventing relay operators from correlating PIN usage
/// across time windows. See module docs for full security analysis.
pub fn compute_pin_hint(pin: &str) -> String {
    compute_pin_hint_for_bucket(pin, current_time_bucket())
}

/// Compute PIN hints for both current and previous time bucket (used by receiver).
///
/// Returns two hints to handle bucket-boundary transitions: if the sender published
/// near the end of one bucket, the receiver may be in the next bucket by the time
/// they query.
pub fn compute_pin_hints_for_lookup(pin: &str) -> Vec<String> {
    let bucket = current_time_bucket();
    vec![
        compute_pin_hint_for_bucket(pin, bucket),
        compute_pin_hint_for_bucket(pin, bucket.saturating_sub(1)),
    ]
}

/// Build an Argon2id instance with the shared cost parameters and a given output length.
///
/// The same `(memory, time, parallelism)` cost is used for both the ciphertext key
/// (32-byte output) and the PIN hint (16-byte output); only the output length differs.
fn argon2id_instance(output_len: usize) -> Result<Argon2<'static>> {
    let params = Params::new(
        ARGON2_MEMORY_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(output_len),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create Argon2 params: {}", e))?;

    Ok(Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        params,
    ))
}

/// Derive a 256-bit key from PIN using Argon2id.
pub fn derive_key_from_pin(pin: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = argon2id_instance(32)?;

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(pin.as_bytes(), salt, &mut output)
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {}", e))?;

    Ok(output)
}

/// Generate a random salt for Argon2id.
pub fn generate_salt() -> [u8; ARGON2_SALT_LEN] {
    let mut salt = [0u8; ARGON2_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Encrypt beam code with PIN-derived key.
///
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt_beam_code(beam_code: &str, pin: &str, salt: &[u8]) -> Result<Vec<u8>> {
    let key = derive_key_from_pin(pin, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    // Generate random nonce
    let mut nonce_bytes = [0u8; AES_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, beam_code.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Format: nonce || ciphertext || tag (tag is included in ciphertext by aes-gcm)
    let mut result = Vec::with_capacity(AES_NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt beam code with PIN-derived key.
///
/// Input format: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn decrypt_beam_code(encrypted: &[u8], pin: &str, salt: &[u8]) -> Result<String> {
    if encrypted.len() < AES_NONCE_LEN + 16 {
        anyhow::bail!("Encrypted data too short");
    }

    let key = derive_key_from_pin(pin, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let nonce = Nonce::from_slice(&encrypted[..AES_NONCE_LEN]);
    let ciphertext = &encrypted[AES_NONCE_LEN..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed - invalid PIN or corrupted data"))?;

    String::from_utf8(plaintext).context("Decrypted data is not valid UTF-8")
}

/// Nostr event kind for PIN exchange.
pub fn pin_exchange_kind() -> Kind {
    Kind::from_u16(PIN_EXCHANGE_KIND)
}

/// Create a PIN exchange event containing the encrypted beam code.
///
/// Event structure:
/// - kind: 24243
/// - content: base64(encrypted_beam_code)
/// - tags:
///   - ["h", "<pin_hint>"] - 128-bit time-bucketed PIN hint for filtering
///   - ["s", "<base64(salt)>"] - Argon2id salt
///   - ["t", "<transfer_id>"] - Transfer ID
///   - ["type", "pin_exchange"] - Event type marker
///   - ["expiration", "<unix_timestamp>"] - NIP-40 expiration
pub fn create_pin_exchange_event(
    keys: &Keys,
    beam_code: &str,
    transfer_id: &str,
    pin: &str,
) -> Result<Event> {
    // Generate salt and encrypt beam code
    let salt = generate_salt();
    let encrypted = encrypt_beam_code(beam_code, pin, &salt)?;

    // Compute PIN hint for filtering
    let pin_hint = compute_pin_hint(pin);

    // Base64 encode encrypted data and salt
    let content = STANDARD.encode(&encrypted);
    let salt_b64 = STANDARD.encode(salt);

    // Calculate expiration timestamp
    let expiration = Timestamp::now().as_secs() + PIN_EVENT_EXPIRATION_SECS;

    // Build event
    let event = EventBuilder::new(pin_exchange_kind(), content)
        .tags(vec![
            Tag::custom(TagKind::Custom("h".into()), vec![pin_hint]),
            Tag::custom(TagKind::Custom("s".into()), vec![salt_b64]),
            Tag::custom(TagKind::Custom("t".into()), vec![transfer_id.to_string()]),
            Tag::custom(
                TagKind::Custom("type".into()),
                vec!["pin_exchange".to_string()],
            ),
            Tag::expiration(Timestamp::from(expiration)),
        ])
        .sign_with_keys(keys)
        .context("Failed to sign PIN exchange event")?;

    Ok(event)
}

/// Parse a PIN exchange event and extract encrypted data and salt.
///
/// Returns: (encrypted_data, salt)
pub fn parse_pin_exchange_event(event: &Event) -> Result<(Vec<u8>, Vec<u8>)> {
    // Validate event kind
    if event.kind != pin_exchange_kind() {
        anyhow::bail!(
            "Invalid event kind: expected {}, got {}",
            PIN_EXCHANGE_KIND,
            event.kind.as_u16()
        );
    }

    // Validate event type tag
    let event_type = event
        .tags
        .iter()
        .find(|t| t.kind().to_string() == "type")
        .and_then(|t| t.content())
        .context("Missing type tag")?;

    if event_type != "pin_exchange" {
        anyhow::bail!(
            "Invalid event type: expected pin_exchange, got {}",
            event_type
        );
    }

    // Extract salt from "s" tag
    let salt_b64 = event
        .tags
        .iter()
        .find(|t| t.kind().to_string() == "s")
        .and_then(|t| t.content())
        .context("Missing salt tag")?;

    let salt = STANDARD.decode(salt_b64).context("Failed to decode salt")?;

    if salt.len() != ARGON2_SALT_LEN {
        anyhow::bail!(
            "Invalid salt length: expected {}, got {}",
            ARGON2_SALT_LEN,
            salt.len()
        );
    }

    // Decode encrypted content
    let encrypted = STANDARD
        .decode(&event.content)
        .context("Failed to decode encrypted content")?;

    Ok((encrypted, salt))
}

/// Extract PIN hint from a PIN exchange event.
pub fn get_pin_hint(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.kind().to_string() == "h")
        .and_then(|t| t.content())
        .map(|s| s.to_string())
}

/// Publish a beam code via PIN exchange.
///
/// Generates a PIN, encrypts the code, publishes the exchange event to default relays,
/// and returns the generated PIN.
pub async fn publish_beam_code_via_pin(
    keys: &Keys,
    beam_code: &str,
    transfer_id: &str,
) -> Result<String> {
    // Generate PIN
    let pin = generate_pin();

    // Create event
    let event = create_pin_exchange_event(keys, beam_code, transfer_id, &pin)
        .context("Failed to create PIN exchange event")?;

    eprintln!("Connecting to Nostr relays for PIN exchange...");

    // Connect to relays
    let client = connect_to_relays(Some(keys), "PIN exchange").await?;

    // Publish event
    let send_result = client.send_event(&event).await;

    // Handle send result before verification
    let output = match send_result {
        Ok(o) => o,
        Err(e) => {
            client.disconnect().await;
            return Err(anyhow::anyhow!(
                "Failed to publish PIN exchange event: {}",
                e
            ));
        }
    };

    // Verify event was published by querying for it
    let event_id = event.id;
    let pin_hints = compute_pin_hints_for_lookup(&pin);
    let verification_filter = Filter::new()
        .kind(pin_exchange_kind())
        .id(event_id)
        .custom_tags(SingleLetterTag::lowercase(Alphabet::H), pin_hints);

    let start = std::time::Instant::now();
    let mut verified = false;

    while start.elapsed() < EVENT_VERIFICATION_TIMEOUT {
        match client
            .fetch_events(verification_filter.clone(), Duration::from_secs(2))
            .await
        {
            Ok(events) if !events.is_empty() => {
                verified = true;
                log::debug!("PIN exchange event verified on relay");
                break;
            }
            _ => {
                tokio::time::sleep(EVENT_VERIFICATION_POLL_INTERVAL).await;
            }
        }
    }

    client.disconnect().await;

    if !verified {
        // Even though relays acknowledged the event, we couldn't verify it's actually
        // retrievable. This means the receiver likely won't be able to find it.
        anyhow::bail!(
            "PIN exchange event was acknowledged by {} relay(s) but could not be verified. \
             The receiver may not be able to retrieve the code. Please try again.",
            output.success.len()
        );
    }

    Ok(pin)
}

/// Fetch a beam code using a PIN.
///
/// Queries default relays for PIN exchange events matching the PIN,
/// and attempts to decrypt them. Returns both the code and the transfer ID.
pub async fn fetch_beam_code_via_pin(pin: &str) -> Result<PinExchangeResult> {
    if pin.len() != PIN_LENGTH {
        anyhow::bail!("Invalid PIN length");
    }

    let pin_hints = compute_pin_hints_for_lookup(pin);

    eprintln!("Connecting to Nostr relays...");

    // Connect to relays
    let client = connect_to_relays(None, "PIN lookup").await?;

    // Query with hints for current and previous time bucket (OR matching)
    let filter = Filter::new()
        .kind(pin_exchange_kind())
        .custom_tags(SingleLetterTag::lowercase(Alphabet::H), pin_hints)
        .since(Timestamp::now() - PIN_EVENT_EXPIRATION_SECS)
        .limit(10);

    let events_res = client.fetch_events(filter, Duration::from_secs(10)).await;

    // Disconnect (always, regardless of fetch result)
    client.disconnect().await;

    // Handle fetch result
    let events = events_res.context("Failed to fetch events")?;

    if events.is_empty() {
        anyhow::bail!("No PIN exchange event found. Check if sender is ready.");
    }

    // Try decrypting each event
    for (index, event) in events.iter().enumerate() {
        let event_id = event.id.to_hex();
        match parse_pin_exchange_event(event) {
            Ok((encrypted, salt)) => match decrypt_beam_code(&encrypted, pin, &salt) {
                Ok(code) => {
                    // Extract transfer_id from the "t" tag
                    let transfer_id = event
                        .tags
                        .iter()
                        .find(|t| t.kind().to_string() == "t")
                        .and_then(|t| t.content())
                        .context("Missing transfer ID tag in PIN exchange event")?
                        .to_string();
                    return Ok(PinExchangeResult { code, transfer_id });
                }
                Err(e) => {
                    log::debug!(
                        "Failed to decrypt event {} (index {}): {}",
                        event_id,
                        index,
                        e
                    );
                }
            },
            Err(e) => {
                log::debug!(
                    "Failed to parse event {} (index {}): {}",
                    event_id,
                    index,
                    e
                );
            }
        }
    }

    anyhow::bail!("Failed to decrypt beam code with the provided PIN.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_hint_consistency() {
        let pin = "ABC123456789";
        let hint1 = compute_pin_hint(pin);
        let hint2 = compute_pin_hint(pin);
        assert_eq!(hint1, hint2);
        // 32 hex chars = 128 bits
        assert_eq!(hint1.len(), 32);
    }

    #[test]
    fn test_pin_hint_different_pins() {
        let hint1 = compute_pin_hint("ABC123456789");
        let hint2 = compute_pin_hint("XYZ987654321");
        assert_ne!(hint1, hint2);
    }

    #[test]
    fn test_pin_hint_time_bucket() {
        let pin = "ABC123456789";
        let bucket1 = 100;
        let bucket2 = 101;
        let hint1 = compute_pin_hint_for_bucket(pin, bucket1);
        let hint2 = compute_pin_hint_for_bucket(pin, bucket2);
        // Same PIN with different time buckets produces different hints
        assert_ne!(hint1, hint2);
        assert_eq!(hint1.len(), 32);
        assert_eq!(hint2.len(), 32);
    }

    #[test]
    fn test_pin_hints_for_lookup() {
        let pin = "ABC123456789";
        let hints = compute_pin_hints_for_lookup(pin);
        assert_eq!(hints.len(), 2);
        // Current bucket hint should match compute_pin_hint
        assert_eq!(hints[0], compute_pin_hint(pin));
        // Both hints should be 32 hex chars
        assert_eq!(hints[0].len(), 32);
        assert_eq!(hints[1].len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let pin = "Te$t12345678";
        let salt = generate_salt();
        let beam_code = "eyJ2ZXJzaW9uIjoyLCJwcm90b2NvbCI6Im5vc3RyIn0";

        let encrypted = encrypt_beam_code(beam_code, pin, &salt).unwrap();
        let decrypted = decrypt_beam_code(&encrypted, pin, &salt).unwrap();

        assert_eq!(beam_code, decrypted);
    }

    #[test]
    fn test_wrong_pin_fails() {
        let pin = "Te$t12345678";
        let wrong_pin = "Wr0ng!234567";
        let salt = generate_salt();
        let beam_code = "eyJ2ZXJzaW9uIjoyLCJwcm90b2NvbCI6Im5vc3RyIn0";

        let encrypted = encrypt_beam_code(beam_code, pin, &salt).unwrap();
        let result = decrypt_beam_code(&encrypted, wrong_pin, &salt);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_salt_fails() {
        let pin = "Te$t12345678";
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        let beam_code = "iroh-beam-code-123";

        let encrypted = encrypt_beam_code(beam_code, pin, &salt1).unwrap();
        let result = decrypt_beam_code(&encrypted, pin, &salt2);

        assert!(result.is_err());
    }

    #[test]
    fn test_key_derivation_consistency() {
        let pin = "Te$t12345678";
        let salt = [1u8; ARGON2_SALT_LEN];

        let key1 = derive_key_from_pin(pin, &salt).unwrap();
        let key2 = derive_key_from_pin(pin, &salt).unwrap();

        assert_eq!(key1, key2);
    }
}
