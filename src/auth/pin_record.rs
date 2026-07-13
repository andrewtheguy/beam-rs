//! Encrypted PIN rendezvous records shared by Nostr and LAN discovery.

use anyhow::{Context, Result};
use iroh::EndpointId;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use super::pin;

#[derive(Serialize, Deserialize)]
struct PinPayload {
    node_id: String,
}

pub fn pin_keys(canonical_pin: &str, bucket: u64) -> Result<Keys> {
    let material = pin::derive_key_material(canonical_pin, bucket)?;
    let secret = SecretKey::from_slice(&material).context("deriving record key from PIN")?;
    Ok(Keys::new(secret))
}

pub async fn candidate_keys(canonical_pin: &str) -> Result<Vec<Keys>> {
    let current = pin::current_bucket();
    let buckets = [current, current.wrapping_sub(1), current + 1];
    tokio::task::spawn_blocking({
        let pin = canonical_pin.to_string();
        move || buckets.iter().map(|bucket| pin_keys(&pin, *bucket)).collect()
    })
    .await
    .context("PIN key-derivation task failed")?
}

pub fn encrypt_pin_payload(keys: &Keys, node_id: &EndpointId) -> Result<String> {
    let payload = serde_json::to_string(&PinPayload {
        node_id: node_id.to_string(),
    })
    .context("serializing PIN payload")?;
    nip44::encrypt(
        keys.secret_key(),
        &keys.public_key(),
        payload,
        nip44::Version::V2,
    )
    .context("encrypting PIN payload")
}

pub fn decrypt_pin_payload(keys: &Keys, content: &str) -> Option<EndpointId> {
    let plaintext = nip44::decrypt(keys.secret_key(), &keys.public_key(), content).ok()?;
    let payload: PinPayload = serde_json::from_str(&plaintext).ok()?;
    payload.node_id.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_round_trips_and_wrong_key_fails() {
        let node_id = iroh::SecretKey::generate().public();
        let keys = pin_keys("AK7P29QXMT", 42).unwrap();
        let content = encrypt_pin_payload(&keys, &node_id).unwrap();
        assert!(!content.contains(&node_id.to_string()));
        assert_eq!(decrypt_pin_payload(&keys, &content), Some(node_id));
        let wrong = pin_keys("BK7P29QXMV", 42).unwrap();
        assert_eq!(decrypt_pin_payload(&wrong, &content), None);
    }
}
