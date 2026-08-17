//! mDNS transport for encrypted PIN rendezvous records.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::EndpointId;
use swarm_discovery::{Discoverer, DropGuard};

use super::pin_record::{self, PinRecordKey};

const PIN_SERVICE_NAME: &str = "beam-rs-pin";
const TXT_KEY: &str = "e";
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

pub struct PinAdvert(#[allow(dead_code)] DropGuard);

pub fn advertise_pin_record(
    key: &PinRecordKey,
    node_id: &EndpointId,
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> Result<PinAdvert> {
    let content = pin_record::encrypt_pin_payload(key, node_id)?;
    let mut discoverer =
        Discoverer::new_interactive(PIN_SERVICE_NAME.to_string(), key.instance_name().to_string())
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

pub async fn lookup_pin_record(candidates: &[PinRecordKey]) -> Result<Option<EndpointId>> {
    let by_instance: HashMap<String, &PinRecordKey> = candidates
        .iter()
        .map(|key| (key.instance_name().to_string(), key))
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
        let Some(key) = by_instance.get(&peer_id) else {
            continue;
        };
        if let Some(node_id) = pin_record::decrypt_pin_payload(key, &content) {
            return Ok(Some(node_id));
        }
    }
    Ok(None)
}

pub async fn resolve_pin(canonical_pin: &str) -> Result<EndpointId> {
    let candidates = pin_record::candidate_keys(canonical_pin).await?;
    lookup_pin_record(&candidates)
        .await
        .context("LAN PIN lookup failed")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no sender found for that PIN on this network; the PIN may have expired"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_is_a_valid_dns_label() {
        let key = pin_record::record_key("7K7P29QXMT", 42).unwrap();
        let instance = key.instance_name();
        assert_eq!(instance.len(), 32);
        assert!(instance.chars().all(|character| character.is_ascii_hexdigit()));
    }

    #[test]
    fn record_fits_a_txt_attribute() {
        let key = pin_record::record_key("7K7P29QXMT", 42).unwrap();
        let node_id = iroh::SecretKey::generate().public();
        let content = pin_record::encrypt_pin_payload(&key, &node_id).unwrap();
        assert!(TXT_KEY.len() + content.len() < 254);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn advertised_record_can_be_found() {
        let pin = "7K7P29QXMT";
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
