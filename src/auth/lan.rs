//! mDNS transport for encrypted PIN rendezvous records.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::EndpointId;
use nostr_sdk::prelude::Keys;
use swarm_discovery::{Discoverer, DropGuard};

use super::pin_record;

const PIN_SERVICE_NAME: &str = "beam-rs-pin";
const TXT_KEY: &str = "e";
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

fn instance_name(keys: &Keys) -> String {
    keys.public_key().to_hex()[..32].to_string()
}

pub struct PinAdvert(#[allow(dead_code)] DropGuard);

pub fn advertise_pin_record(
    keys: &Keys,
    node_id: &EndpointId,
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> Result<PinAdvert> {
    let content = pin_record::encrypt_pin_payload(keys, node_id)?;
    let mut discoverer =
        Discoverer::new_interactive(PIN_SERVICE_NAME.to_string(), instance_name(keys))
            .with_txt_attributes([(TXT_KEY.to_string(), Some(content))])
            .context("PIN record does not fit an mDNS TXT attribute")?;
    for addr in addrs {
        discoverer = discoverer.with_addrs(addr.port(), [addr.ip()]);
    }
    let guard = discoverer
        .spawn(&tokio::runtime::Handle::current())
        .context("starting mDNS PIN advertisement")?;
    Ok(PinAdvert(guard))
}

pub async fn lookup_pin_record(candidates: &[Keys]) -> Result<Option<EndpointId>> {
    let by_instance: HashMap<String, &Keys> = candidates
        .iter()
        .map(|keys| (instance_name(keys), keys))
        .collect();
    let accepted: std::collections::HashSet<String> = by_instance.keys().cloned().collect();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, String)>(16);
    let _guard = Discoverer::new_interactive(
        PIN_SERVICE_NAME.to_string(),
        format!("lookup-{:08x}", rand::random::<u32>()),
    )
    .with_callback(move |peer_id, peer| {
        let peer_id = peer_id.to_string();
        if accepted.contains(&peer_id)
            && let Some(Some(content)) = peer.txt_attribute(TXT_KEY)
        {
            let _ = tx.try_send((peer_id, content.to_string()));
        }
    })
    .spawn(&tokio::runtime::Handle::current())
    .context("starting mDNS PIN lookup")?;

    let deadline = tokio::time::Instant::now() + LOOKUP_TIMEOUT;
    while let Ok(Some((peer_id, content))) = tokio::time::timeout_at(deadline, rx.recv()).await {
        let Some(keys) = by_instance.get(&peer_id) else {
            continue;
        };
        if let Some(node_id) = pin_record::decrypt_pin_payload(keys, &content) {
            return Ok(Some(node_id));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_is_a_valid_dns_label() {
        let keys = Keys::generate();
        let instance = instance_name(&keys);
        assert_eq!(instance.len(), 32);
        assert!(instance.chars().all(|character| character.is_ascii_hexdigit()));
    }

    #[test]
    fn record_fits_a_txt_attribute() {
        let keys = Keys::generate();
        let node_id = iroh::SecretKey::generate().public();
        let content = pin_record::encrypt_pin_payload(&keys, &node_id).unwrap();
        assert!(TXT_KEY.len() + content.len() < 254);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn advertised_record_can_be_found() {
        let pin = "BK7P29QXMV";
        let node_id = iroh::SecretKey::generate().public();
        let candidates = pin_record::candidate_keys(pin).await.unwrap();
        let _advert = advertise_pin_record(
            &candidates[0],
            &node_id,
            [SocketAddr::from(([127, 0, 0, 1], 4433))],
        )
        .unwrap();
        assert_eq!(lookup_pin_record(&candidates).await.unwrap(), Some(node_id));
    }
}
