// This module is a NIP-65/NIP-66 relay-discovery toolkit. Only a subset is wired
// into the binary today (e.g. `generate_transfer_id`); the rest is retained API
// surface, so suppress dead-code warnings that only surface in a binary crate.
#![allow(dead_code)]

use anyhow::{Context, Result};
use futures::future::join_all;
use nostr_sdk::prelude::*;
use rand::Rng;
use std::collections::HashSet;
use std::time::{Duration, Instant};

pub use crate::auth::nostr_pin::DEFAULT_NOSTR_RELAYS;

/// Nostr event kind for file transfer signaling (ephemeral range 20000-29999)
/// Ephemeral events are not stored permanently by relays
pub fn nostr_file_transfer_kind() -> Kind {
    Kind::from_u16(24242)
}

/// Timeout for fetching NIP-11 relay information
const RELAY_INFO_TIMEOUT_SECS: u64 = 5;

/// Timeout for WebSocket connectivity test
const RELAY_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Timeout for relay discovery queries
const RELAY_DISCOVERY_TIMEOUT_SECS: u64 = 10;

/// Number of top relays to use for file transfer
const TOP_RELAYS_COUNT: usize = 5;

/// Maximum number of relays to probe after discovery
const MAX_RELAYS_TO_PROBE: usize = 30;

/// Minimum max_message_length required (24KB: 16KB chunk + base64 overhead + tags)
const MIN_MESSAGE_LENGTH: i32 = 24 * 1024;

/// Minimum max_content_length required (22KB: base64 encoded 16KB chunk)
const MIN_CONTENT_LENGTH: i32 = 22 * 1024;

/// NIP-66 Relay Discovery event kind
fn relay_discovery_kind() -> Kind {
    Kind::from_u16(30166)
}

/// NIP-65 Relay List Metadata event kind
fn relay_list_kind() -> Kind {
    Kind::from_u16(10002)
}

/// Fetch NIP-11 relay information document from a relay
/// Returns the info document on success, or None if fetch fails
async fn fetch_relay_info(relay_url: &str) -> Option<RelayInformationDocument> {
    // Convert wss:// to https:// for HTTP request
    let http_url = relay_url
        .replace("wss://", "https://")
        .replace("ws://", "http://");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(RELAY_INFO_TIMEOUT_SECS))
        .build()
        .ok()?;

    let response = client
        .get(&http_url)
        .header("Accept", "application/nostr+json")
        .send()
        .await
        .ok()?;

    let json = response.text().await.ok()?;
    RelayInformationDocument::from_json(&json).ok()
}

/// Test WebSocket connectivity to a relay and measure response time
/// Returns (relay_url, response_time) on success
async fn test_relay_connectivity(relay_url: &str) -> Option<(String, Duration)> {
    let start = Instant::now();

    // Create a temporary client to test connectivity
    let client = Client::default();

    // Add the relay
    if client.add_relay(relay_url).await.is_err() {
        return None;
    }

    // Try to connect (spawns background task)
    client.connect().await;

    // Wait for connection with timeout
    let timeout = Duration::from_secs(RELAY_CONNECT_TIMEOUT_SECS);
    let relay = match client.relay(relay_url).await {
        Ok(r) => r,
        Err(_) => {
            // Clean up background tasks before returning
            client.disconnect().await;
            return None;
        }
    };

    // Wait for relay to connect or timeout
    relay.wait_for_connection(timeout).await;

    // Check if actually connected
    if !relay.is_connected() {
        client.disconnect().await;
        return None;
    }

    let elapsed = start.elapsed();

    // Disconnect after test
    client.disconnect().await;

    Some((relay_url.to_string(), elapsed))
}

/// Probe a relay: check NIP-11 capabilities and test WebSocket connectivity
/// Returns (relay_url, response_time) if relay passes all checks
async fn probe_relay(relay_url: &str) -> Option<(String, Duration)> {
    // First, fetch NIP-11 to check capabilities
    if let Some(info) = fetch_relay_info(relay_url).await
        && !is_relay_suitable(&info)
    {
        return None;
    }
    // If NIP-11 fetch fails, we still try connectivity
    // (some relays don't serve NIP-11 but still work fine)

    // Test actual WebSocket connectivity
    test_relay_connectivity(relay_url).await
}

/// Check if a relay has suitable capabilities for our file transfer use case
fn is_relay_suitable(info: &RelayInformationDocument) -> bool {
    if let Some(ref limitation) = info.limitation {
        // Check message length limit
        if let Some(max_msg) = limitation.max_message_length
            && max_msg < MIN_MESSAGE_LENGTH
        {
            return false;
        }

        // Check content length limit
        if let Some(max_content) = limitation.max_content_length
            && max_content < MIN_CONTENT_LENGTH
        {
            return false;
        }

        // Skip relays requiring payment (we want free public relays)
        if limitation.payment_required == Some(true) {
            return false;
        }

        // Skip relays requiring auth (ephemeral events shouldn't need auth)
        if limitation.auth_required == Some(true) {
            return false;
        }
    }

    true
}

/// Extract relay URL from a NIP-66 relay discovery event (kind 30166)
/// The relay URL is stored in the 'd' tag
fn extract_relay_from_nip66(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::d())
        .and_then(|t| t.content())
        .map(normalize_relay_url)
        .filter(|url| url.starts_with("wss://") || url.starts_with("ws://"))
}

/// Extract relay URLs from a NIP-65 relay list event (kind 10002)
/// Relay URLs are stored in 'r' tags (single letter tags per NIP-65)
fn extract_relays_from_nip65(event: &Event) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|t| {
            // NIP-65 uses ["r", "<url>", "<marker>"] tags (single letter 'r')
            t.single_letter_tag()
                .map(|slt| slt.character == Alphabet::R)
                .unwrap_or(false)
        })
        .filter_map(|t| t.content())
        .map(normalize_relay_url)
        .filter(|url| url.starts_with("wss://") || url.starts_with("ws://"))
        .collect()
}

// Trim trailing slashes from relay URLs without breaking scheme-only inputs like "wss://".
fn normalize_relay_url(url: &str) -> String {
    if !url.ends_with('/') {
        return url.to_string();
    }

    let trimmed = url.trim_end_matches('/');
    if trimmed.ends_with("ws:") || trimmed.ends_with("wss:") {
        url.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Discover relays by querying seed relays for NIP-66 and NIP-65 events
async fn discover_relays_from_seeds() -> HashSet<String> {
    let mut discovered: HashSet<String> = HashSet::new();

    // Add seed relays to discovered set
    for relay in DEFAULT_NOSTR_RELAYS {
        discovered.insert(normalize_relay_url(relay));
    }

    // Create a temporary client to query seed relays
    let client = Client::default();

    // Add seed relays
    for relay_url in DEFAULT_NOSTR_RELAYS {
        let _ = client.add_relay(relay_url.to_string()).await;
    }

    // Connect to relays
    client.connect().await;

    // Query for NIP-66 relay discovery events (kind 30166)
    // These are published by relay monitors
    let nip66_filter = Filter::new().kind(relay_discovery_kind()).limit(100);

    // Query for NIP-65 relay list events (kind 10002)
    // These are published by users listing their preferred relays
    let nip65_filter = Filter::new().kind(relay_list_kind()).limit(100);

    let timeout = Duration::from_secs(RELAY_DISCOVERY_TIMEOUT_SECS);

    // Fetch NIP-66 events
    if let Ok(nip66_events) = client.fetch_events(nip66_filter, timeout).await {
        for event in nip66_events.iter() {
            if let Some(relay_url) = extract_relay_from_nip66(event) {
                discovered.insert(relay_url);
            }
        }
    }

    // Fetch NIP-65 events
    if let Ok(nip65_events) = client.fetch_events(nip65_filter, timeout).await {
        for event in nip65_events.iter() {
            for relay_url in extract_relays_from_nip65(event) {
                discovered.insert(relay_url);
            }
        }
    }

    // Disconnect from seed relays
    client.disconnect().await;

    discovered
}

/// Discover best relays by querying seed relays and probing
/// 1. Query seed relays for NIP-66/NIP-65 events to discover more relays
/// 2. Probe discovered relays: check NIP-11 capabilities + test WebSocket connectivity
/// 3. Sort by WebSocket response time and return top relays
async fn discover_best_relays() -> Vec<String> {
    // Discover relays from seed relays via NIP-66 and NIP-65
    let discovered = discover_relays_from_seeds().await;

    let relay_count = discovered.len();
    if relay_count > DEFAULT_NOSTR_RELAYS.len() {
        eprintln!(
            "📡 Discovered {} relays from {} seeds",
            relay_count,
            DEFAULT_NOSTR_RELAYS.len()
        );
    }

    // Limit number of relays to probe to avoid too many connections
    // Reserve space for default relays, then fill remaining slots with random discovered relays
    let default_relay_set: std::collections::HashSet<_> =
        DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect();

    // Remove default relays from discovered set to avoid duplicates
    let mut discovered_relays: Vec<_> = discovered
        .into_iter()
        .filter(|r| !default_relay_set.contains(r))
        .collect();

    // Shuffle randomly to avoid alphabetic bias (which would favor relays starting with numbers/early letters)
    use rand::seq::SliceRandom;
    discovered_relays.shuffle(&mut rand::thread_rng());

    // Reserve slots for default relays
    let discovered_slots = MAX_RELAYS_TO_PROBE.saturating_sub(DEFAULT_NOSTR_RELAYS.len());
    discovered_relays.truncate(discovered_slots);

    // Combine: discovered relays + default relays
    let mut relays_to_probe = discovered_relays;
    for default_relay in DEFAULT_NOSTR_RELAYS {
        relays_to_probe.push(default_relay.to_string());
    }

    // Probe relays in parallel: NIP-11 capability check + WebSocket connectivity test
    let futures: Vec<_> = relays_to_probe.iter().map(|url| probe_relay(url)).collect();

    let results = join_all(futures).await;

    // Filter successful probes
    let mut responsive_relays: Vec<_> = results.into_iter().flatten().collect();

    // Sort by WebSocket response time (faster = better)
    responsive_relays.sort_by(|a, b| a.1.cmp(&b.1));

    // Take top relays
    responsive_relays
        .into_iter()
        .take(TOP_RELAYS_COUNT)
        .map(|(url, _)| url)
        .collect()
}

/// Get best relays for file transfer
/// Discovers relays via NIP-65/NIP-66, probes them, falls back to defaults if none respond
pub async fn get_best_relays() -> Vec<String> {
    let relays = discover_best_relays().await;

    if !relays.is_empty() {
        eprintln!("📡 Using {} fastest responding relays", relays.len());
        relays
    } else {
        eprintln!("📡 Using default relays (discovery failed)");
        DEFAULT_NOSTR_RELAYS
            .iter()
            .take(TOP_RELAYS_COUNT)
            .map(|s| s.to_string())
            .collect()
    }
}

/// Event type tag values for signaling
pub const EVENT_TYPE_COMPLETION: &str = "completion";

/// Tag names for file transfer metadata
pub const TAG_TRANSFER_ID: &str = "t";
pub const TAG_TYPE: &str = "type";

/// Generate a random transfer ID (16 bytes, hex encoded)
pub fn generate_transfer_id() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.r#gen();
    hex::encode(bytes)
}

/// Extract transfer ID from an event
///
/// The transfer ID is stored in a single-letter "t" tag per Nostr convention.
pub fn get_transfer_id(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| {
            // Use single_letter_tag() for reliable detection of single-letter tags
            t.single_letter_tag()
                .map(|slt| slt.character == Alphabet::T)
                .unwrap_or(false)
        })
        .and_then(|t| t.content())
        .map(|s| s.to_string())
}

/// Get event type from an event
///
/// The type is stored in a custom "type" tag.
fn get_event_type(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| {
            // Use as_vec() to reliably get the tag name for custom tags
            // Tag structure is ["tag_name", "value", ...]
            t.as_slice()
                .first()
                .map(|name| name == TAG_TYPE)
                .unwrap_or(false)
        })
        .and_then(|t| t.content())
        .map(|s| s.to_string())
}

/// Create a completion event (receiver confirms download complete)
///
/// # Arguments
/// * `keys` - Receiver's keys for signing
/// * `sender_pubkey` - Sender's public key
/// * `transfer_id` - Unique transfer session ID
pub fn create_completion_event(
    keys: &Keys,
    sender_pubkey: &PublicKey,
    transfer_id: &str,
) -> Result<Event> {
    let event = EventBuilder::new(nostr_file_transfer_kind(), "")
        .tags(vec![
            Tag::public_key(*sender_pubkey),
            Tag::custom(
                TagKind::Custom(TAG_TRANSFER_ID.into()),
                vec![transfer_id.to_string()],
            ),
            Tag::custom(
                TagKind::Custom(TAG_TYPE.into()),
                vec![EVENT_TYPE_COMPLETION.to_string()],
            ),
        ])
        .sign_with_keys(keys)
        .context("Failed to sign completion event")?;

    Ok(event)
}

/// Check if event is a completion event
pub fn is_completion_event(event: &Event) -> bool {
    get_event_type(event).as_deref() == Some(EVENT_TYPE_COMPLETION)
}

// ============================================================================
// NIP-65 Outbox Model Support
// ============================================================================

/// Timeout for NIP-65 discovery queries (seconds)
const NIP65_DISCOVERY_TIMEOUT_SECS: u64 = 15;

/// Create a NIP-65 relay list event (kind 10002)
///
/// # Arguments
/// * `keys` - Keys for signing the event
/// * `relays` - List of relay URLs to include in the relay list
///
/// # Errors
/// Returns an error if any relay URL fails to parse, or if no valid relays are provided.
pub fn create_relay_list_event(keys: &Keys, relays: &[String]) -> Result<Event> {
    if relays.is_empty() {
        anyhow::bail!("No relay URLs provided for NIP-65 relay list event");
    }

    let mut valid_tags: Vec<Tag> = Vec::with_capacity(relays.len());
    let mut malformed_urls: Vec<String> = Vec::new();

    for url in relays {
        match url.parse::<RelayUrl>() {
            Ok(relay_url) => {
                // Create relay tag with "write" marker per NIP-65
                valid_tags.push(Tag::relay_metadata(relay_url, Some(RelayMetadata::Write)));
            }
            Err(_) => {
                malformed_urls.push(url.clone());
            }
        }
    }

    if !malformed_urls.is_empty() {
        anyhow::bail!(
            "Failed to parse {} relay URL(s): {}",
            malformed_urls.len(),
            malformed_urls.join(", ")
        );
    }

    // Note: valid_tags cannot be empty here because:
    // 1. We already bailed if relays was empty (lines 428-430)
    // 2. We just bailed if any URLs were malformed
    // 3. Therefore all non-empty relay URLs parsed successfully into valid_tags

    EventBuilder::new(relay_list_kind(), "")
        .tags(valid_tags)
        .sign_with_keys(keys)
        .context("Failed to sign NIP-65 relay list event")
}

/// Publish sender's relay list as NIP-65 event to bridge relays
///
/// This allows receivers to discover which relays the sender uses for file transfer,
/// enabling sender and receiver to use different relays.
///
/// # Arguments
/// * `keys` - Sender's keys for signing
/// * `write_relays` - Relays where sender will publish file chunks
/// * `bridge_relays` - Well-known relays to publish NIP-65 event to
pub async fn publish_relay_list_event(
    keys: &Keys,
    write_relays: &[String],
    bridge_relays: &[String],
) -> Result<()> {
    let event = create_relay_list_event(keys, write_relays)?;

    let client = Client::default();
    let mut added_count = 0;
    for relay in bridge_relays {
        if client.add_relay(relay.clone()).await.is_ok() {
            added_count += 1;
        }
    }

    if added_count == 0 {
        anyhow::bail!("Failed to add any bridge relays for NIP-65 publishing");
    }

    client.connect().await;

    // Wait for relay connections to establish.
    // Note: wait_for_connection returns when at least one relay connects or timeout is reached,
    // so the event may only be published to a subset of bridge relays. This is acceptable for
    // NIP-65 since receivers only need to find the event from any one bridge relay, and the
    // event will propagate across relays over time.
    client.wait_for_connection(Duration::from_secs(5)).await;

    // Publish NIP-65 event to all connected bridge relays
    client
        .send_event(&event)
        .await
        .context("Failed to publish NIP-65 relay list event")?;

    client.disconnect().await;
    Ok(())
}

/// Discover sender's relay list by querying their NIP-65 event from well-known bridge relays
///
/// Uses DEFAULT_NOSTR_RELAYS as bridge relays for discovery.
///
/// # Arguments
/// * `sender_pubkey` - Sender's public key (from beam code)
///
/// # Returns
/// * `Ok(Vec<String>)` - List of relay URLs the sender uses
/// * `Err` - If NIP-65 event not found or discovery fails
pub async fn discover_sender_relays(sender_pubkey: &PublicKey) -> Result<Vec<String>> {
    let bridges: Vec<String> = DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect();

    let client = Client::default();
    let mut added_count = 0;
    for relay in &bridges {
        if client.add_relay(relay.clone()).await.is_ok() {
            added_count += 1;
        }
    }

    if added_count == 0 {
        anyhow::bail!("Failed to add any bridge relays for NIP-65 discovery");
    }

    client.connect().await;

    // Wait for relay connections to establish.
    // Note: wait_for_connection returns when at least one relay connects or timeout is reached,
    // so we may only query a subset of bridge relays. This is acceptable since we only need to
    // find the sender's NIP-65 event from any one relay.
    client.wait_for_connection(Duration::from_secs(5)).await;

    // Query for sender's NIP-65 event (kind 10002)
    let filter = Filter::new()
        .kind(relay_list_kind())
        .author(*sender_pubkey)
        .limit(1);

    let events = client
        .fetch_events(filter, Duration::from_secs(NIP65_DISCOVERY_TIMEOUT_SECS))
        .await
        .context("Failed to fetch NIP-65 events from bridge relays")?;

    client.disconnect().await;

    // Extract relay URLs from the most recent event (by created_at timestamp)
    let relays = events
        .iter()
        .max_by_key(|e| e.created_at)
        .map(extract_relays_from_nip65)
        .unwrap_or_default();

    if relays.is_empty() {
        anyhow::bail!("No NIP-65 relay list event found for sender");
    }

    Ok(relays)
}

#[cfg(test)]
mod tests {
    use super::normalize_relay_url;

    #[test]
    fn normalize_relay_url_trims_trailing_slash() {
        assert_eq!(
            normalize_relay_url("wss://relay.example.com/"),
            "wss://relay.example.com"
        );
    }

    #[test]
    fn normalize_relay_url_trims_multiple_trailing_slashes() {
        assert_eq!(
            normalize_relay_url("ws://relay.example.com////"),
            "ws://relay.example.com"
        );
    }

    #[test]
    fn normalize_relay_url_preserves_scheme_only() {
        assert_eq!(normalize_relay_url("wss://"), "wss://");
        assert_eq!(normalize_relay_url("wss:///"), "wss:///");
    }
}
