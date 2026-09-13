use anyhow::{Context, Result};
use iroh::endpoint::{
    AuthenticationError, ConnectError, ConnectWithOptsError, ConnectingError, Connection,
};
use iroh::{Endpoint, EndpointAddr};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::timeout;

use super::common::{
    ALPN, EndpointReadiness, IrohDuplex, create_endpoint, is_connection_error_network_related,
    minimal_addr_to_endpoint, watch_connection_paths,
};
use crate::auth::spake2::handshake_as_initiator;
use beam_rs::core::beam::parse_code;
use beam_rs::core::transfer::run_receiver_transfer;
use beam_rs::ui;

/// Close an established connection with an error reason and shut down the endpoint.
async fn close_with_error(conn: &Connection, endpoint: &Endpoint, reason: &[u8]) {
    conn.close(2u32.into(), reason);
    endpoint.close().await;
}

/// Receive a file using a beam code.
pub async fn receive(code: &str, output_dir: Option<PathBuf>, no_resume: bool) -> Result<()> {
    ui::status("Parsing beam code...");

    let token = parse_code(code).context("Failed to parse beam code")?;
    let minimal_addr = token
        .addr
        .context("No iroh endpoint address in beam code")?;
    // The sender's configured custom relays travel in the code, so the receiver
    // adopts the same relay map with no CLI flag of its own. Empty when the
    // sender used the default public relays.
    let relay_urls = minimal_addr.relay_urls.clone();
    let addr = minimal_addr_to_endpoint(&minimal_addr)
        .context("Failed to parse endpoint address")?;

    receive_internal(
        addr,
        relay_urls,
        &token.key,
        EndpointReadiness::RelayOnline,
        output_dir,
        no_resume,
    )
    .await
}

/// Receive through a PIN or serverless pairing code. Relays and internet
/// discovery are disabled; the session secret is proven with SPAKE2 and its
/// result becomes the content-encryption key.
pub async fn receive_paired(
    addr: EndpointAddr,
    secret: &str,
    output_dir: Option<PathBuf>,
    no_resume: bool,
) -> Result<()> {
    receive_internal(
        addr,
        Vec::new(),
        secret,
        EndpointReadiness::LanDirect,
        output_dir,
        no_resume,
    )
    .await
}

async fn receive_internal(
    addr: EndpointAddr,
    relay_urls: Vec<String>,
    secret: &str,
    readiness: EndpointReadiness,
    output_dir: Option<PathBuf>,
    no_resume: bool,
) -> Result<()> {
    let session_id = addr.id.to_string();

    ui::status("Pairing data valid. Connecting to sender...");

    let endpoint = create_endpoint(relay_urls, readiness, false).await?;
    let local_id = endpoint.addr().id.to_string();

    let conn = endpoint.connect(addr, ALPN).await.map_err(|e| {
        if is_relay_or_network_error(&e) {
            anyhow::anyhow!(
                "Failed to connect to sender: {}\n\n\
                 Relay connection failed. Check network connectivity and firewall settings.",
                e
            )
        } else {
            anyhow::anyhow!(
                "Failed to connect to sender: {}\n\n\
                 Troubleshooting:\n  \
                 - Verify the beam code is correct\n  \
                 - Ensure the sender is still running\n  \
                 - Check network connectivity and firewall settings",
                e
            )
        }
    })?;

    ui::status("Connected!");
    ui::status(&format!("Remote ID: {}", conn.remote_id()));

    let path_watcher = watch_connection_paths(&conn);

    const ACCEPT_STREAM_TIMEOUT: Duration = Duration::from_secs(30);

    let accept_result = timeout(ACCEPT_STREAM_TIMEOUT, conn.accept_bi())
        .await
        .context("Timed out waiting for sender to open stream")
        .and_then(|r| r.context("Failed to accept stream"));
    let (mut send_stream, mut recv_stream) = match accept_result {
        Ok(streams) => streams,
        Err(e) => {
            drop(path_watcher);
            close_with_error(&conn, &endpoint, b"failed to accept stream").await;
            return Err(e);
        }
    };

    // Read the "ready" byte sent by the sender to confirm the stream is established.
    // See sender.rs for why this is needed (QUIC stream materialization).
    let mut ready = [0u8; 1];
    recv_stream
        .read_exact(&mut ready)
        .await
        .context("Failed to read ready byte")?;
    if ready[0] != 0x01 {
        drop(path_watcher);
        close_with_error(&conn, &endpoint, b"invalid ready byte").await;
        anyhow::bail!("Invalid ready byte: expected 0x01, got 0x{:02x}", ready[0]);
    }

    // Prove possession of the one-time secret and bind it to this endpoint ID
    // before accepting any transfer metadata.
    ui::status("Performing SPAKE2 authentication...");
    let mut duplex = IrohDuplex::new(&mut send_stream, &mut recv_stream);
    let handshake_result = timeout(
        Duration::from_secs(30),
        handshake_as_initiator(&mut duplex, secret, &session_id, &local_id),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SPAKE2 handshake timed out"))
    .and_then(|r| r.map_err(|e| anyhow::anyhow!("SPAKE2 handshake failed: {}", e)));
    let key = match handshake_result {
        Ok(key) => {
            ui::status("SPAKE2 authentication successful!");
            key
        }
        Err(e) => {
            drop(path_watcher);
            close_with_error(&conn, &endpoint, b"handshake failed").await;
            return Err(e);
        }
    };

    run_receiver_transfer(&mut duplex, &key, output_dir, no_resume).await?;

    drop(path_watcher);

    // Finish send stream and wait for acknowledgment (QUIC-specific)
    // This ensures the ACK message is fully delivered before closing the connection.
    send_stream
        .finish()
        .context("Failed to finish send stream")?;

    const STREAM_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
    match timeout(STREAM_CLOSE_TIMEOUT, send_stream.stopped()).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            // Stream was reset by peer - this is fine, they got the ACK
            log::debug!("Send stream stopped with error (likely peer closed): {}", e);
        }
        Err(_) => {
            log::debug!(
                "Waiting for stream acknowledgment timed out after {:?}",
                STREAM_CLOSE_TIMEOUT
            );
        }
    }

    const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

    conn.close(0u32.into(), b"transfer complete");

    if timeout(CLOSE_TIMEOUT, conn.closed()).await.is_err() {
        log::warn!(
            "Waiting for connection close timed out after {:?}",
            CLOSE_TIMEOUT
        );
    }

    // Always close the endpoint, even if connection close timed out
    if timeout(CLOSE_TIMEOUT, endpoint.close()).await.is_err() {
        log::warn!("Endpoint close timed out after {:?}", CLOSE_TIMEOUT);
    }

    ui::status("Connection closed.");

    Ok(())
}

/// Determine if a connection error indicates a relay or network connectivity issue.
///
/// This function inspects the structured error types from iroh/quinn to identify
/// errors that suggest relay failures, network unreachability, or similar issues
/// that warrant specific error messaging.
fn is_relay_or_network_error(e: &ConnectError) -> bool {
    match e {
        ConnectError::Connect { source, .. } => match source {
            ConnectWithOptsError::NoAddress { .. } => return true,
            ConnectWithOptsError::Noq { source, .. } => {
                // Quinn's ConnectError doesn't expose network-level issues directly
                let msg = source.to_string().to_lowercase();
                if msg.contains("no route") || msg.contains("unreachable") {
                    return true;
                }
            }
            _ => {}
        },
        ConnectError::Connecting { source, .. } => match source {
            ConnectingError::ConnectionError { source, .. } => {
                return is_connection_error_network_related(source);
            }
            ConnectingError::HandshakeFailure { source, .. } => {
                // Only treat ALPN-related handshake failures as relay/network issues.
                // Certificate validation or other protocol errors should go to
                // the general troubleshooting path.
                return is_authentication_error_relay_related(source);
            }
            _ => {}
        },
        ConnectError::Connection { source, .. } => {
            return is_connection_error_network_related(source);
        }
        _ => {}
    }

    // Fallback: check error message as a last resort for cases not covered
    // by the structured matching above.
    let err_str = e.to_string().to_lowercase();
    err_str.contains("relay")
        || err_str.contains("no route")
        || err_str.contains("unreachable")
        || err_str.contains("network")
}

/// Check if an AuthenticationError is relay-related (e.g., ALPN mismatch).
///
/// Returns true only for errors that suggest relay/network issues.
/// Certificate validation errors and other protocol issues return false
/// so they fall into the general troubleshooting path.
fn is_authentication_error_relay_related(e: &AuthenticationError) -> bool {
    match e {
        // NoAlpn indicates ALPN mismatch - typically a relay/protocol issue
        AuthenticationError::NoAlpn { .. } => true,
        // RemoteId errors are certificate/identity validation issues - not relay-related
        AuthenticationError::RemoteId { .. } => false,
        _ => false,
    }
}
