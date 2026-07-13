//! Common iroh endpoint setup and utilities shared between sender and receiver.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::StreamExt;
use iroh::{
    Endpoint, EndpointAddr, RelayMap, RelayUrl, TransportAddr, Watcher,
    address_lookup::{DnsAddressLookup, PkarrPublisher},
    endpoint::{Connection, ConnectionError, PathList, RecvStream, RelayMode, SendStream, presets},
};
use iroh_mdns_address_lookup::MdnsAddressLookup;
use tokio::task::JoinHandle;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use beam_rs::core::beam::{
    CURRENT_VERSION, MinimalAddr, PROTOCOL_IROH, BeamToken,
};

/// Check if a quinn `ConnectionError` indicates a network-related issue.
///
/// Shared by the sender and receiver connect-error classifiers.
pub fn is_connection_error_network_related(e: &ConnectionError) -> bool {
    match e {
        ConnectionError::TimedOut => true,
        ConnectionError::Reset => true,
        ConnectionError::TransportError(te) => {
            // Transport errors can indicate network issues
            let msg = te.to_string().to_lowercase();
            msg.contains("no route")
                || msg.contains("unreachable")
                || msg.contains("network")
                || msg.contains("connection refused")
        }
        ConnectionError::VersionMismatch => false,
        ConnectionError::ConnectionClosed(_) => false,
        ConnectionError::ApplicationClosed(_) => false,
        ConnectionError::LocallyClosed => false,
        ConnectionError::CidsExhausted => false,
    }
}

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
fn format_paths(paths: &PathList<'_>) -> String {
    if paths.is_empty() {
        return "establishing...".to_string();
    }
    let parts: Vec<String> = paths
        .iter()
        .filter(|p| p.is_selected())
        .map(|path| {
            let rtt = path.rtt();
            match path.remote_addr() {
                TransportAddr::Ip(addr) => format!("Direct {addr} (rtt {rtt:.0?})"),
                TransportAddr::Relay(url) => format!("Relay {url} (rtt {rtt:.0?})"),
                other => format!("{other:?} (rtt {rtt:.0?})"),
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
pub struct PathWatcherGuard(Option<JoinHandle<()>>);

impl Drop for PathWatcherGuard {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
    }
}

/// Log the current connection paths and spawn a background task that logs
/// updates whenever the active path changes (e.g. relay -> direct).
///
/// Logging is the task's sole purpose, so when debug logging is disabled the
/// task is not spawned and the returned guard is inert.
///
/// The returned guard aborts the background task when dropped; callers must
/// keep it alive for the duration of the connection.
pub fn watch_connection_paths(conn: &Connection) -> PathWatcherGuard {
    if !log::log_enabled!(log::Level::Debug) {
        return PathWatcherGuard(None);
    }

    let conn = conn.clone();
    PathWatcherGuard(Some(tokio::spawn(async move {
        // The stream yields the current snapshot on the first poll, then a
        // fresh snapshot whenever the open or selected paths change; it ends
        // when the connection closes.
        let mut stream = conn.paths_stream();
        let mut last: Option<String> = None;
        while let Some(paths) = stream.next().await {
            let formatted = format_paths(&paths);
            if last.as_deref() != Some(formatted.as_str()) {
                log::debug!("Connection: {}", formatted);
                last = Some(formatted);
            }
        }
    })))
}

/// Application-Layer Protocol Negotiation identifier for beam transfers.
pub const ALPN: &[u8] = b"beam-transfer/1";

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
/// The endpoint is configured with ALPN for beam transfers.
/// Multiple relay URLs provide automatic failover based on latency.
///
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointReadiness {
    RelayOnline,
    RelayPreferred,
    LanDirect,
}

const ENDPOINT_READY_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn create_sender_endpoint(
    relay_urls: Vec<String>,
    readiness: EndpointReadiness,
) -> Result<Endpoint> {
    let relay_mode = if readiness == EndpointReadiness::LanDirect {
        RelayMode::Disabled
    } else {
        print_relay_info(&relay_urls);
        parse_relay_mode(relay_urls)?
    };

    // iroh 1.0 requires the crypto provider to be set explicitly on the
    // builder when starting from the `Empty` preset — the `tls-ring` feature
    // only makes the ring backend available, it does not wire it in, and
    // rustls' global `install_default()` is not consulted.
    let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = Endpoint::builder(presets::Empty)
        .crypto_provider(crypto_provider)
        .relay_mode(relay_mode)
        .alpns(vec![ALPN.to_vec()]);

    let builder = if readiness == EndpointReadiness::LanDirect {
        builder.address_lookup(MdnsAddressLookup::builder())
    } else {
        builder
            .address_lookup(PkarrPublisher::n0_dns())
            .address_lookup(DnsAddressLookup::n0_dns())
            .address_lookup(MdnsAddressLookup::builder())
    };

    let endpoint = builder
        .bind()
        .await
        .context("Failed to create endpoint")?;

    wait_for_endpoint_ready(&endpoint, readiness).await?;

    Ok(endpoint)
}

/// Wait until the endpoint has discovered at least one direct (IP) address.
///
async fn wait_for_direct_address(endpoint: &Endpoint) {
    let mut watcher = endpoint.watch_addr();
    loop {
        if watcher.get().ip_addrs().next().is_some() {
            break;
        }
        if watcher.updated().await.is_err() {
            break;
        }
    }
}

/// Give direct-address discovery a chance to populate a serverless pairing code.
/// The code remains usable through mDNS if the timeout is reached without an
/// address.
pub async fn wait_for_direct_address_hint(endpoint: &Endpoint) {
    if tokio::time::timeout(ENDPOINT_READY_TIMEOUT, wait_for_direct_address(endpoint))
        .await
        .is_err()
    {
        eprintln!(
            "Warning: no direct address was discovered within {}s; the beam code will rely on mDNS.",
            ENDPOINT_READY_TIMEOUT.as_secs()
        );
    }
}

async fn wait_for_endpoint_ready(
    endpoint: &Endpoint,
    readiness: EndpointReadiness,
) -> Result<()> {
    let ready = async {
        match readiness {
            EndpointReadiness::RelayOnline | EndpointReadiness::RelayPreferred => {
                endpoint.online().await
            }
            EndpointReadiness::LanDirect => wait_for_direct_address(endpoint).await,
        }
    };
    match tokio::time::timeout(ENDPOINT_READY_TIMEOUT, ready).await {
        Ok(()) => Ok(()),
        Err(_) if readiness == EndpointReadiness::RelayPreferred => {
            log::info!(
                "No relay came online after {}s; continuing with LAN discovery",
                ENDPOINT_READY_TIMEOUT.as_secs()
            );
            Ok(())
        }
        Err(_) => anyhow::bail!(
            "Endpoint failed to become ready after {}s",
            ENDPOINT_READY_TIMEOUT.as_secs()
        ),
    }
}

/// Create an iroh endpoint configured for receiving (connects to sender).
///
/// Sets up local mDNS discovery.
/// Does not set ALPN as the receiver specifies it when connecting.
/// Multiple relay URLs provide automatic failover based on latency.
///
pub async fn create_receiver_endpoint(
    relay_urls: Vec<String>,
    readiness: EndpointReadiness,
) -> Result<Endpoint> {
    let relay_mode = if readiness == EndpointReadiness::LanDirect {
        RelayMode::Disabled
    } else {
        print_relay_info(&relay_urls);
        parse_relay_mode(relay_urls)?
    };

    // iroh 1.0 requires the crypto provider to be set explicitly on the
    // builder when starting from the `Empty` preset — the `tls-ring` feature
    // only makes the ring backend available, it does not wire it in, and
    // rustls' global `install_default()` is not consulted.
    let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = Endpoint::builder(presets::Empty)
        .crypto_provider(crypto_provider)
        .relay_mode(relay_mode);

    let builder = if readiness == EndpointReadiness::LanDirect {
        builder.address_lookup(MdnsAddressLookup::builder())
    } else {
        builder
            .address_lookup(PkarrPublisher::n0_dns())
            .address_lookup(DnsAddressLookup::n0_dns())
            .address_lookup(MdnsAddressLookup::builder())
    };

    let endpoint = builder
        .bind()
        .await
        .context("Failed to create endpoint")?;

    wait_for_endpoint_ready(&endpoint, readiness).await?;
    Ok(endpoint)
}

/// Create a MinimalAddr from a full EndpointAddr.
///
/// The `relay` field keeps only the first (currently-selected) relay URL to
/// minimize token size — that's the address the receiver dials. The sender's
/// full set of configured custom relays (`relay_urls`, from `--relay-url`) is
/// embedded separately so the receiver can configure its own endpoint with the
/// same custom relay map instead of the default public relays; it is empty when
/// the sender used the defaults.
///
pub fn minimal_addr_from_endpoint(
    addr: &EndpointAddr,
    relay_urls: &[String],
) -> MinimalAddr {
    let relay = addr.relay_urls().next().map(|r| r.to_string());
    MinimalAddr {
        id: addr.id.to_string(),
        relay,
        relay_urls: relay_urls.to_vec(),
    }
}

/// Convert a MinimalAddr back to an EndpointAddr
pub fn minimal_addr_to_endpoint(addr: &MinimalAddr) -> Result<EndpointAddr> {
    let id = addr
        .id
        .parse()
        .context("Failed to parse endpoint ID from beam code")?;
    let mut endpoint_addr = EndpointAddr::new(id);
    if let Some(ref relay_str) = addr.relay {
        let relay_url: RelayUrl = relay_str
            .parse()
            .context("Failed to parse relay URL from beam code")?;
        endpoint_addr = endpoint_addr.with_relay_url(relay_url);
    }
    Ok(endpoint_addr)
}

/// Generate a beam code from endpoint address
/// Format: base64url(json(BeamToken))
///
/// `relay_urls` is the sender's configured custom relay set (from `--relay-url`,
/// empty for default relays); it is embedded so the receiver adopts the same
/// relays without needing them passed on its own command line.
pub fn generate_code(
    addr: &EndpointAddr,
    key: &[u8; 32],
    relay_urls: &[String],
) -> Result<String> {
    let minimal_addr = minimal_addr_from_endpoint(addr, relay_urls);

    let token = BeamToken {
        version: CURRENT_VERSION,
        protocol: PROTOCOL_IROH.to_string(),
        created_at: beam_rs::core::beam::current_timestamp(),
        key: URL_SAFE_NO_PAD.encode(key),
        addr: Some(minimal_addr),
        onion_address: None,
    };

    let serialized = serde_json::to_vec(&token).context("Failed to serialize beam token")?;

    Ok(URL_SAFE_NO_PAD.encode(&serialized))
}

#[cfg(test)]
mod tests {
    use super::*;
    use beam_rs::core::beam::parse_code;
    use iroh::SecretKey;

    #[test]
    fn relay_mode_code_uses_a_minimal_address() {
        let key = [42u8; 32];
        let addr = EndpointAddr::new(SecretKey::generate().public())
            .with_ip_addr("192.168.1.10:4444".parse().unwrap());

        let code = generate_code(&addr, &key, &[]).unwrap();
        let token = parse_code(&code).unwrap();
        let minimal_addr = token.addr.unwrap();

        assert_eq!(minimal_addr.id, addr.id.to_string());
    }

    #[test]
    fn custom_relay_urls_round_trip_through_code() {
        let key = [42u8; 32];
        let addr = EndpointAddr::new(SecretKey::generate().public());
        let relays = vec![
            "https://relay.example.com".to_string(),
            "https://relay2.example.com".to_string(),
        ];

        let code = generate_code(&addr, &key, &relays).unwrap();
        let token = parse_code(&code).unwrap();
        let minimal_addr = token.addr.unwrap();

        // The sender's configured custom relays travel in the code so the
        // receiver can adopt them without a CLI flag.
        assert_eq!(minimal_addr.relay_urls, relays);
    }

    #[test]
    fn default_relay_code_omits_relay_urls() {
        let key = [42u8; 32];
        let addr = EndpointAddr::new(SecretKey::generate().public());

        let code = generate_code(&addr, &key, &[]).unwrap();
        let token = parse_code(&code).unwrap();
        let minimal_addr = token.addr.unwrap();

        assert!(minimal_addr.relay_urls.is_empty());
        // The empty vec is skipped during serialization to keep tokens compact.
        let serialized = serde_json::to_value(&minimal_addr).unwrap();
        assert!(serialized.get("relay_urls").is_none());
    }
}
