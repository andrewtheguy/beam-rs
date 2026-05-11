//! Common iroh endpoint setup and utilities shared between sender and receiver.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{
    Endpoint, EndpointAddr, RelayMap, RelayUrl, TransportAddr, Watcher,
    address_lookup::mdns::MdnsAddressLookup,
    endpoint::{Builder as EndpointBuilder, Connection, PathInfoList, RecvStream, RelayMode, SendStream},
};
use tokio::task::JoinHandle;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wormhole_common::core::wormhole::{
    CURRENT_VERSION, MinimalAddr, PROTOCOL_IROH, WormholeToken,
};

/// A duplex wrapper that combines separate send/recv streams into a single bidirectional stream.
///
/// This allows iroh's separate `SendStream` and `RecvStream` to be used with APIs that
/// expect a single stream implementing both `AsyncRead` and `AsyncWrite`.
pub struct IrohDuplex<'a> {
    pub send: &'a mut SendStream,
    pub recv: &'a mut RecvStream,
}

impl<'a> IrohDuplex<'a> {
    /// Create a new duplex wrapper from separate send and receive streams.
    pub fn new(send: &'a mut SendStream, recv: &'a mut RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for IrohDuplex<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for IrohDuplex<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.send)
            .poll_write(cx, buf)
            .map_err(io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.send)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.send)
            .poll_shutdown(cx)
            .map_err(io::Error::other)
    }
}

/// An owned duplex wrapper that takes ownership of send/recv streams.
///
/// This is needed for `run_receiver_transfer` which requires `'static` lifetime
/// due to spawn_blocking usage in folder transfers.
pub struct OwnedIrohDuplex {
    send: SendStream,
    recv: RecvStream,
}

impl OwnedIrohDuplex {
    /// Create a new owned duplex from separate send and receive streams.
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }

    /// Consume the duplex and return the underlying send stream.
    /// Used to call finish() after transfer completes.
    pub fn into_send_stream(self) -> SendStream {
        self.send
    }
}

impl AsyncRead for OwnedIrohDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for OwnedIrohDuplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(io::Error::other)
    }
}

/// Format connection path info for display.
fn format_paths(paths: &PathInfoList) -> String {
    if paths.is_empty() {
        return "establishing...".to_string();
    }
    let parts: Vec<String> = paths
        .iter()
        .filter(|p| p.is_selected())
        .map(|path| {
            let rtt_str = match path.rtt() {
                Some(rtt) => format!(" (rtt {rtt:.0?})"),
                None => String::new(),
            };
            match path.remote_addr() {
                TransportAddr::Ip(addr) => format!("Direct {addr}{rtt_str}"),
                TransportAddr::Relay(url) => format!("Relay {url}{rtt_str}"),
                other => format!("{other:?}{rtt_str}"),
            }
        })
        .collect();
    if parts.is_empty() {
        "no selected path".to_string()
    } else {
        parts.join(", ")
    }
}

/// RAII guard that aborts the background path watcher task on drop.
pub struct PathWatcherGuard(JoinHandle<()>);

impl Drop for PathWatcherGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Print the current connection paths and spawn a background task that
/// prints updates whenever the active path changes (e.g. relay -> direct).
///
/// The returned guard aborts the background task when dropped.
pub fn watch_connection_paths(conn: &Connection) -> PathWatcherGuard {
    let mut watcher = conn.paths();

    // Print initial snapshot
    let initial = watcher.get();
    eprintln!("   Connection: {}", format_paths(&initial));

    // Spawn background task that prints on changes
    let mut last = initial;
    PathWatcherGuard(tokio::spawn(async move {
        while let Ok(paths) = watcher.updated().await {
            if paths != last {
                eprintln!("   Connection: {}", format_paths(&paths));
                last = paths;
            }
        }
    }))
}

/// Application-Layer Protocol Negotiation identifier for wormhole transfers.
pub const ALPN: &[u8] = b"wormhole-transfer/1";

/// Parse relay URL strings into a RelayMode.
///
/// If URLs are provided, returns `RelayMode::Custom` with a RelayMap containing all URLs.
/// If no URLs are provided, returns `RelayMode::Default` to use iroh's public relays.
/// Multiple relays provide automatic failover - iroh selects the best one based on latency.
pub fn parse_relay_mode(relay_urls: Vec<String>) -> Result<RelayMode> {
    if relay_urls.is_empty() {
        Ok(RelayMode::Default)
    } else {
        let parsed_urls: Vec<RelayUrl> = relay_urls
            .iter()
            .map(|url| url.parse().with_context(|| format!("Invalid relay URL: {}", url)))
            .collect::<Result<Vec<_>>>()?;
        let relay_map = RelayMap::from_iter(parsed_urls);
        Ok(RelayMode::Custom(relay_map))
    }
}

/// Print info about custom relay servers being used.
fn print_relay_info(relay_urls: &[String]) {
    if relay_urls.is_empty() {
        return;
    }
    if relay_urls.len() == 1 {
        eprintln!("Using custom relay server");
    } else {
        eprintln!(
            "Using {} custom relay servers (with failover)",
            relay_urls.len()
        );
    }
}

/// Create an iroh endpoint configured for sending (accepts incoming connections).
///
/// Sets up local mDNS discovery.
/// The endpoint is configured with ALPN for wormhole transfers.
/// Multiple relay URLs provide automatic failover based on latency.
pub async fn create_sender_endpoint(relay_urls: Vec<String>) -> Result<Endpoint> {
    print_relay_info(&relay_urls);
    let relay_mode = parse_relay_mode(relay_urls)?;

    // iroh 0.98 (PR #3992) requires the crypto provider to be set explicitly
    // on the builder when starting from `EndpointBuilder::empty()` — the
    // `tls-ring` feature only makes the ring backend available, it does not
    // wire it in, and rustls' global `install_default()` is not consulted.
    let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());
    let endpoint = EndpointBuilder::empty()
        .crypto_provider(crypto_provider)
        .relay_mode(relay_mode)
        .alpns(vec![ALPN.to_vec()])
        .address_lookup(MdnsAddressLookup::builder())
        .bind()
        .await
        .context("Failed to create endpoint")?;

    // Wait for endpoint to be online (connected to relay)
    endpoint.online().await;

    Ok(endpoint)
}

/// Create an iroh endpoint configured for receiving (connects to sender).
///
/// Sets up local mDNS discovery.
/// Does not set ALPN as the receiver specifies it when connecting.
/// Multiple relay URLs provide automatic failover based on latency.
pub async fn create_receiver_endpoint(relay_urls: Vec<String>) -> Result<Endpoint> {
    print_relay_info(&relay_urls);
    let relay_mode = parse_relay_mode(relay_urls)?;

    // iroh 0.98 (PR #3992) requires the crypto provider to be set explicitly
    // on the builder when starting from `EndpointBuilder::empty()` — the
    // `tls-ring` feature only makes the ring backend available, it does not
    // wire it in, and rustls' global `install_default()` is not consulted.
    let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());
    let endpoint = EndpointBuilder::empty()
        .crypto_provider(crypto_provider)
        .relay_mode(relay_mode)
        .address_lookup(MdnsAddressLookup::builder())
        .bind()
        .await
        .context("Failed to create endpoint")?;

    Ok(endpoint)
}

/// Create a MinimalAddr from a full EndpointAddr, stripping IP addresses.
/// Only the first (currently-selected) relay URL is kept to minimize token size.
pub fn minimal_addr_from_endpoint(addr: &EndpointAddr) -> MinimalAddr {
    let relay = addr.relay_urls().next().map(|r| r.to_string());
    MinimalAddr {
        id: addr.id.to_string(),
        relay,
    }
}

/// Convert a MinimalAddr back to an EndpointAddr
pub fn minimal_addr_to_endpoint(addr: &MinimalAddr) -> Result<EndpointAddr> {
    let id = addr
        .id
        .parse()
        .context("Failed to parse endpoint ID from wormhole code")?;
    let mut endpoint_addr = EndpointAddr::new(id);
    if let Some(ref relay_str) = addr.relay {
        let relay_url: RelayUrl = relay_str
            .parse()
            .context("Failed to parse relay URL from wormhole code")?;
        endpoint_addr = endpoint_addr.with_relay_url(relay_url);
    }
    Ok(endpoint_addr)
}

/// Generate a wormhole code from endpoint address
/// Format: base64url(json(WormholeToken))
pub fn generate_code(addr: &EndpointAddr, key: &[u8; 32]) -> Result<String> {
    let minimal_addr = minimal_addr_from_endpoint(addr);

    let token = WormholeToken {
        version: CURRENT_VERSION,
        protocol: PROTOCOL_IROH.to_string(),
        created_at: wormhole_common::core::wormhole::current_timestamp(),
        key: URL_SAFE_NO_PAD.encode(key),
        addr: Some(minimal_addr),
        onion_address: None,
        webrtc_sender_pubkey: None,
        webrtc_transfer_id: None,
        webrtc_relays: None,
        webrtc_transfer_type: None,
        webrtc_filename: None,
    };

    let serialized = serde_json::to_vec(&token).context("Failed to serialize wormhole token")?;

    Ok(URL_SAFE_NO_PAD.encode(&serialized))
}
