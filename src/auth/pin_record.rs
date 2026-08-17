//! Encrypted PIN rendezvous records used by LAN discovery.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use super::pin;
use beam_rs::core::crypto;

#[derive(Serialize, Deserialize)]
struct PinPayload {
    node_id: String,
}

pub struct PinRecordKey {
    encryption_key: [u8; 32],
    instance_name: String,
}

impl PinRecordKey {
    pub fn instance_name(&self) -> &str {
        &self.instance_name
    }
}

pub fn record_key(canonical_pin: &str, bucket: u64) -> Result<PinRecordKey> {
    let material = pin::derive_key_material(canonical_pin, bucket)?;
    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&material[..32]);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let instance_name = material[32..]
        .iter()
        .flat_map(|byte| {
            [
                HEX[(byte >> 4) as usize] as char,
                HEX[(byte & 0x0f) as usize] as char,
            ]
        })
        .collect();
    Ok(PinRecordKey {
        encryption_key,
        instance_name,
    })
}

pub async fn candidate_keys(canonical_pin: &str) -> Result<Vec<PinRecordKey>> {
    let current = pin::current_bucket();
    let buckets = [current, current.wrapping_sub(1), current + 1];
    tokio::task::spawn_blocking({
        let pin = canonical_pin.to_string();
        move || {
            buckets
                .iter()
                .map(|bucket| record_key(&pin, *bucket))
                .collect()
        }
    })
    .await
    .context("PIN key-derivation task failed")?
}

pub fn encrypt_pin_payload(key: &PinRecordKey, node_id: &EndpointId) -> Result<String> {
    let payload = serde_json::to_string(&PinPayload {
        node_id: node_id.to_string(),
    })
    .context("serializing PIN payload")?;
    let encrypted = crypto::encrypt(&key.encryption_key, payload.as_bytes())
        .context("encrypting PIN payload")?;
    Ok(URL_SAFE_NO_PAD.encode(encrypted))
}

pub fn decrypt_pin_payload(key: &PinRecordKey, content: &str) -> Option<EndpointId> {
    let encrypted = URL_SAFE_NO_PAD.decode(content).ok()?;
    let plaintext = crypto::decrypt(&key.encryption_key, &encrypted).ok()?;
    let payload: PinPayload = serde_json::from_slice(&plaintext).ok()?;
    payload.node_id.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_round_trips_and_wrong_key_fails() {
        let node_id = iroh::SecretKey::generate().public();
        let key = record_key("7K7P29QXMT", 42).unwrap();
        let content = encrypt_pin_payload(&key, &node_id).unwrap();
        assert!(!content.contains(&node_id.to_string()));
        assert_eq!(decrypt_pin_payload(&key, &content), Some(node_id));
        let wrong = record_key("9K7P29QXMV", 42).unwrap();
        assert_eq!(decrypt_pin_payload(&wrong, &content), None);
    }
}
