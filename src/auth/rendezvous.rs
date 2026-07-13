//! Nostr and LAN rendezvous for a single, 120-second PIN session.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::EndpointId;
use nostr_sdk::prelude::*;

use super::{lan, pin, pin_record};

pub const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://nos.lol",
    "wss://relay.nostr.net",
    "wss://relay.primal.net",
    "wss://relay.snort.social",
];

const PIN_KIND_U16: u16 = 9422;
const NOSTR_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const NOSTR_LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinChannel {
    NostrAndLan,
    LanOnly,
}

impl PinChannel {
    pub fn nostr(self) -> bool {
        self == Self::NostrAndLan
    }

    pub fn lan(self) -> bool {
        matches!(self, Self::NostrAndLan | Self::LanOnly)
    }
}

fn pin_kind() -> Kind {
    Kind::from_u16(PIN_KIND_U16)
}

async fn connect_client() -> Result<Client> {
    let client = Client::default();
    let mut added = 0;
    for relay in DEFAULT_NOSTR_RELAYS {
        if client.add_relay((*relay).to_string()).await.is_ok() {
            added += 1;
        }
    }
    if added == 0 {
        anyhow::bail!("no usable Nostr relays configured");
    }
    client.connect().await;
    client.wait_for_connection(NOSTR_CONNECT_TIMEOUT).await;
    let connected = client
        .relays()
        .await
        .values()
        .filter(|relay| relay.status() == RelayStatus::Connected)
        .count();
    if connected == 0 {
        client.disconnect().await;
        anyhow::bail!(
            "could not connect to any Nostr relay within {}s",
            NOSTR_CONNECT_TIMEOUT.as_secs()
        );
    }
    Ok(client)
}

pub async fn publish_nostr_record(
    keys: &Keys,
    node_id: &EndpointId,
    expires_at_unix: u64,
) -> Result<()> {
    let content = pin_record::encrypt_pin_payload(keys, node_id)?;
    let client = connect_client().await?;
    let event = EventBuilder::new(pin_kind(), content)
        .tag(Tag::expiration(Timestamp::from(expires_at_unix)))
        .sign_with_keys(keys)
        .context("signing PIN record")?;
    let result = client.send_event(&event).await;
    client.disconnect().await;
    result.context("publishing PIN record to Nostr relays")?;
    Ok(())
}

async fn lookup_nostr_record(candidates: &[Keys]) -> Result<Option<EndpointId>> {
    let by_pubkey: HashMap<PublicKey, &Keys> = candidates
        .iter()
        .map(|keys| (keys.public_key(), keys))
        .collect();
    let client = connect_client().await?;
    let filter = Filter::new()
        .kind(pin_kind())
        .authors(by_pubkey.keys().copied());
    let events = client.fetch_events(filter, NOSTR_LOOKUP_TIMEOUT).await;
    client.disconnect().await;
    let events = events.context("querying Nostr relays for the PIN record")?;
    let mut events: Vec<_> = events.iter().collect();
    events.sort_by_key(|event| std::cmp::Reverse(event.created_at));
    for event in events {
        let Some(keys) = by_pubkey.get(&event.pubkey) else {
            continue;
        };
        if let Some(node_id) = pin_record::decrypt_pin_payload(keys, &event.content) {
            return Ok(Some(node_id));
        }
    }
    Ok(None)
}

pub async fn resolve_pin(canonical_pin: &str, channel: PinChannel) -> Result<EndpointId> {
    let candidates = pin_record::candidate_keys(canonical_pin).await?;
    let miss = || match channel {
        PinChannel::LanOnly => anyhow::anyhow!(
            "no sender found for that PIN on this network; the PIN may have expired"
        ),
        PinChannel::NostrAndLan => anyhow::anyhow!(
            "no sender found for that PIN; it may have expired, or without internet both devices must be on the same network"
        ),
    };
    if channel == PinChannel::LanOnly {
        return lan::lookup_pin_record(&candidates)
            .await
            .context("LAN PIN lookup failed")?
            .ok_or_else(miss);
    }

    let lan_lookup = lan::lookup_pin_record(&candidates);
    let nostr_lookup = lookup_nostr_record(&candidates);
    tokio::pin!(lan_lookup);
    tokio::pin!(nostr_lookup);
    let (mut lan_done, mut nostr_done) = (false, false);
    let mut first_error = None;
    let mut error_count = 0;
    while !(lan_done && nostr_done) {
        let outcome = tokio::select! {
            result = &mut lan_lookup, if !lan_done => {
                lan_done = true;
                result.context("LAN PIN lookup failed")
            }
            result = &mut nostr_lookup, if !nostr_done => {
                nostr_done = true;
                result.context("Nostr PIN lookup failed")
            }
        };
        match outcome {
            Ok(Some(node_id)) => return Ok(node_id),
            Ok(None) => {}
            Err(error) => {
                log::warn!("{error:#}");
                error_count += 1;
                first_error.get_or_insert(error);
            }
        }
    }
    if error_count == 2 {
        Err(first_error.expect("two lookup errors were recorded"))
    } else {
        Err(miss())
    }
}

pub fn expires_at_unix() -> u64 {
    beam_rs::core::beam::current_timestamp() + pin::PIN_LIFETIME_SECS
}
