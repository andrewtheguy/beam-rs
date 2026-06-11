//! Common iroh endpoint setup and utilities shared between sender and receiver.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::StreamExt;
use iroh::{
    dns::{DnsProtocol, DnsResolver},
    Endpoint, EndpointAddr, RelayMap, RelayUrl, TransportAddr, Watcher,
    endpoint::{Connection, PathList, RecvStream, RelayMode, SendStream, presets},
};
use iroh_mdns_address_lookup::MdnsAddressLookup;
use tokio::task::JoinHandle;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use beam_common::core::beam::{
    CURRENT_VERSION, MinimalAddr, PROTOCOL_IROH, BeamToken,
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
    let conn = conn.clone();
    PathWatcherGuard(tokio::spawn(async move {
        // The stream yields the current snapshot on the first poll, then a
        // fresh snapshot whenever the open or selected paths change; it ends
        // when the connection closes.
        let mut stream = conn.paths_stream();
        let mut last: Option<String> = None;
        while let Some(paths) = stream.next().await {
            let formatted = format_paths(&paths);
            if last.as_deref() != Some(formatted.as_str()) {
                beam_common::ui::sink().status(&format!("   Connection: {}", formatted));
                last = Some(formatted);
            }
        }
    }))
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
/// When `no_server` is set, relays are disabled entirely (no third-party server
/// is contacted): the endpoint's discovered direct addresses are embedded in the
/// beam code and mDNS is kept as a discovery fallback.
pub async fn create_sender_endpoint(relay_urls: Vec<String>, no_server: bool) -> Result<Endpoint> {
    let relay_mode = if no_server {
        eprintln!("No-server mode (direct connection, no relay)");
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
        .alpns(vec![ALPN.to_vec()])
        .address_lookup(MdnsAddressLookup::builder())
        .dns_resolver(beam_dns_resolver());

    let endpoint = builder
        .bind()
        .await
        .context("Failed to create endpoint")?;

    if no_server {
        // `online()` waits for a home relay to connect, which never happens
        // with relays disabled. Instead wait until we have at least one direct
        // address so the printed beam code embeds a reachable address (and mDNS
        // has an address to advertise).
        wait_for_direct_address(&endpoint).await;
    } else {
        // Wait for endpoint to be online (connected to relay)
        endpoint.online().await;
    }

    Ok(endpoint)
}

/// Wait until the endpoint has discovered at least one direct (IP) address.
///
/// Used in no-server mode where there is no relay to fall back on: the printed
/// beam code embeds the discovered addresses, so we wait for at least one. Gives
/// up after a short timeout, in which case the receiver may simply need a moment
/// longer for mDNS to propagate.
async fn wait_for_direct_address(endpoint: &Endpoint) {
    const ADDR_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
    let wait = async {
        let mut watcher = endpoint.watch_addr();
        loop {
            if watcher.get().ip_addrs().next().is_some() {
                break;
            }
            // Returns Err once the endpoint is dropped; stop waiting then.
            if watcher.updated().await.is_err() {
                break;
            }
        }
    };
    if tokio::time::timeout(ADDR_WAIT_TIMEOUT, wait).await.is_err() {
        eprintln!(
            "Warning: no local network address discovered within {:?}; \
             mDNS may not be able to advertise this sender yet.",
            ADDR_WAIT_TIMEOUT
        );
    }
}

/// Create an iroh endpoint configured for receiving (connects to sender).
///
/// Sets up local mDNS discovery.
/// Does not set ALPN as the receiver specifies it when connecting.
/// Multiple relay URLs provide automatic failover based on latency.
///
/// When `no_server` is set, relays are disabled entirely (no third-party server
/// is contacted): the sender is reached via the direct addresses embedded in the
/// beam code, with mDNS as a fallback.
pub async fn create_receiver_endpoint(
    relay_urls: Vec<String>,
    no_server: bool,
) -> Result<Endpoint> {
    let relay_mode = if no_server {
        eprintln!("No-server mode (direct connection, no relay)");
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
        .address_lookup(MdnsAddressLookup::builder())
        .dns_resolver(beam_dns_resolver());

    let endpoint = builder
        .bind()
        .await
        .context("Failed to create endpoint")?;

    Ok(endpoint)
}

/// Build a DNS resolver, preferring the host's system configuration and
/// falling back to public nameservers only when it cannot be read.
///
/// iroh's default resolver (`with_system_defaults`) reads the host resolver
/// config during endpoint binding. When that read fails it logs a warning
/// ("Failed to read the system's DNS config, using fallback DNS servers")
/// before falling back internally. On macOS the read can fail to parse a
/// scoped nameserver entry, producing that warning on every bind — and it is
/// not specific to no-server mode.
///
/// To keep the system config when it is valid while avoiding the spurious
/// warning, we probe the same `read_system_conf()` call iroh uses:
///   - on success, defer to `with_system_defaults()` (the subsequent read
///     inside iroh also succeeds, so no warning is emitted);
///   - on failure, build a resolver with explicit public nameservers — the
///     same Google servers iroh would otherwise fall back to — so iroh never
///     reads the system config and never warns.
///
/// In no-server mode DNS is never used (mDNS handles address lookup); in
/// relay mode this resolves relay hostnames and n0 discovery records. Note
/// that `DnsResolver::builder().build()` alone yields a resolver with *no*
/// nameservers (an empty `ResolverConfig::default()`), which is why the
/// fallback adds servers explicitly.
fn beam_dns_resolver() -> DnsResolver {
    if hickory_resolver::system_conf::read_system_conf().is_ok() {
        return DnsResolver::builder().with_system_defaults().build();
    }

    // System config could not be read/parsed: use Google public DNS, matching
    // iroh's own fallback nameservers.
    const NAMESERVERS: [IpAddr; 2] = [
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
    ];
    let mut builder = DnsResolver::builder();
    for ip in NAMESERVERS {
        let addr = SocketAddr::new(ip, 53);
        builder = builder.with_nameserver(addr, DnsProtocol::Udp);
        builder = builder.with_nameserver(addr, DnsProtocol::Tcp);
    }
    builder.build()
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
/// IP addresses are normally stripped (they're discovered at connect time via
/// relay or mDNS), but when `include_ip_addrs` is set — no-server mode — every
/// direct address iroh discovered (LAN and any public/port-mapped addresses) is
/// embedded so the receiver can attempt them all without relying on mDNS.
pub fn minimal_addr_from_endpoint(
    addr: &EndpointAddr,
    relay_urls: &[String],
    include_ip_addrs: bool,
) -> MinimalAddr {
    let relay = addr.relay_urls().next().map(|r| r.to_string());
    let ip_addrs = if include_ip_addrs {
        addr.ip_addrs().map(|a| a.to_string()).collect()
    } else {
        Vec::new()
    };
    MinimalAddr {
        id: addr.id.to_string(),
        relay,
        relay_urls: relay_urls.to_vec(),
        ip_addrs,
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
    for ip_str in &addr.ip_addrs {
        let socket_addr = ip_str
            .parse()
            .with_context(|| format!("Failed to parse IP address from beam code: {ip_str}"))?;
        endpoint_addr = endpoint_addr.with_ip_addr(socket_addr);
    }
    Ok(endpoint_addr)
}

/// Generate a beam code from endpoint address
/// Format: base64url(json(BeamToken))
///
/// In `no_server` mode the endpoint's discovered direct addresses are embedded
/// in the code so the receiver can connect without depending on mDNS resolution.
///
/// `relay_urls` is the sender's configured custom relay set (from `--relay-url`,
/// empty for default relays); it is embedded so the receiver adopts the same
/// relays without needing them passed on its own command line.
pub fn generate_code(
    addr: &EndpointAddr,
    key: &[u8; 32],
    relay_urls: &[String],
    no_server: bool,
) -> Result<String> {
    let minimal_addr = minimal_addr_from_endpoint(addr, relay_urls, no_server);

    let token = BeamToken {
        version: CURRENT_VERSION,
        protocol: PROTOCOL_IROH.to_string(),
        created_at: beam_common::core::beam::current_timestamp(),
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
    use beam_common::core::beam::parse_code;
    use iroh::SecretKey;

    #[test]
    fn no_server_code_embeds_direct_ip_addresses() {
        let key = [42u8; 32];
        let addr = EndpointAddr::new(SecretKey::generate().public())
            .with_ip_addr("192.168.1.10:4444".parse().unwrap());

        let code = generate_code(&addr, &key, &[], true).unwrap();
        let token = parse_code(&code).unwrap();
        let minimal_addr = token.addr.unwrap();

        assert_eq!(minimal_addr.ip_addrs, vec!["192.168.1.10:4444".to_string()]);
        // No-server codes carry no relay URL — that's how the receiver detects
        // the mode.
        assert!(minimal_addr.relay.is_none());
    }

    #[test]
    fn relay_mode_code_omits_direct_ip_addresses() {
        let key = [42u8; 32];
        let addr = EndpointAddr::new(SecretKey::generate().public())
            .with_ip_addr("192.168.1.10:4444".parse().unwrap());

        let code = generate_code(&addr, &key, &[], false).unwrap();
        let token = parse_code(&code).unwrap();
        let minimal_addr = token.addr.unwrap();

        assert!(minimal_addr.ip_addrs.is_empty());
        // The empty vec is skipped during serialization to keep tokens compact.
        let serialized = serde_json::to_value(&minimal_addr).unwrap();
        assert!(serialized.get("ip_addrs").is_none());
    }

    #[test]
    fn custom_relay_urls_round_trip_through_code() {
        let key = [42u8; 32];
        let addr = EndpointAddr::new(SecretKey::generate().public());
        let relays = vec![
            "https://relay.example.com".to_string(),
            "https://relay2.example.com".to_string(),
        ];

        let code = generate_code(&addr, &key, &relays, false).unwrap();
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

        let code = generate_code(&addr, &key, &[], false).unwrap();
        let token = parse_code(&code).unwrap();
        let minimal_addr = token.addr.unwrap();

        assert!(minimal_addr.relay_urls.is_empty());
        // The empty vec is skipped during serialization to keep tokens compact.
        let serialized = serde_json::to_value(&minimal_addr).unwrap();
        assert!(serialized.get("relay_urls").is_none());
    }
}
