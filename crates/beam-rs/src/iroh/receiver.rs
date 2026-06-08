use anyhow::{Context, Result};
use iroh::endpoint::{
    AuthenticationError, ConnectError, ConnectWithOptsError, ConnectingError, ConnectionError,
};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::timeout;

use super::common::{
    ALPN, OwnedIrohDuplex, create_receiver_endpoint, minimal_addr_to_endpoint,
    watch_connection_paths,
};
use beam_common::auth::PinInfo;
use beam_common::auth::spake2::handshake_as_initiator;
use beam_common::core::transfer::run_receiver_transfer;
use beam_common::core::beam::parse_code;

/// Receive a file or folder using a beam code.
/// Auto-detects whether it's a file or folder transfer based on the header.
///
/// `pin_info` is `Some(PinInfo)` when PIN mode is active,
/// triggering a SPAKE2 handshake to derive the encryption key.
pub async fn receive(
    code: &str,
    output_dir: Option<PathBuf>,
    relay_urls: Vec<String>,
    no_resume: bool,
    pin_info: Option<PinInfo>,
    local_only: bool,
) -> Result<()> {
    eprintln!("Parsing beam code...");

    // Parse the beam code
    let token = parse_code(code).context("Failed to parse beam code")?;
    let key = beam_common::core::beam::decode_key(&token.key)
        .context("Failed to decode encryption key")?;
    let minimal_addr = token
        .addr
        .context("No iroh endpoint address in beam code")?;
    let addr = minimal_addr_to_endpoint(&minimal_addr)
        .context("Failed to parse endpoint address")?;

    eprintln!("Code valid. Connecting to sender...");

    // Create iroh endpoint
    let endpoint = create_receiver_endpoint(relay_urls, local_only).await?;

    // Connect to sender
    let conn = endpoint.connect(addr, ALPN).await.map_err(|e| {
        // Determine if this is a relay/network connectivity error by inspecting
        // the structured error types from iroh/quinn
        let is_relay_or_network_error = is_relay_or_network_error(&e);

        if is_relay_or_network_error {
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

    // Print connection info
    let remote_id = conn.remote_id();
    eprintln!("Connected!");
    eprintln!("Remote ID: {}", remote_id);

    let path_watcher = watch_connection_paths(&conn);

    const ACCEPT_STREAM_TIMEOUT: Duration = Duration::from_secs(30);

    // Accept bi-directional stream
    let (send_stream, mut recv_stream) = timeout(ACCEPT_STREAM_TIMEOUT, conn.accept_bi())
        .await
        .context("Timed out waiting for sender to open stream")?
        .context("Failed to accept stream")?;

    // Perform SPAKE2 handshake if PIN mode is active (receiver = initiator)
    let (key, send_stream) = if let Some(ref pin_info) = pin_info {
        let (pin, transfer_id) = (&pin_info.pin, &pin_info.transfer_id);
        // Read the "ready" byte sent by the sender to confirm the stream is established.
        // See sender.rs for why this is needed (QUIC stream materialization).
        let mut ready = [0u8; 1];
        recv_stream.read_exact(&mut ready).await.context("Failed to read ready byte")?;
        if ready[0] != 0x01 {
            anyhow::bail!("Invalid ready byte: expected 0x01, got 0x{:02x}", ready[0]);
        }
        eprintln!("Performing SPAKE2 authentication...");
        let mut send_stream_mut = send_stream;
        let mut duplex =
            super::common::IrohDuplex::new(&mut send_stream_mut, &mut recv_stream);
        let handshake_result = timeout(
            Duration::from_secs(30),
            handshake_as_initiator(&mut duplex, pin, transfer_id),
        )
        .await
        .map_err(|_| anyhow::anyhow!("SPAKE2 handshake timed out"))
        .and_then(|r| r.map_err(|e| anyhow::anyhow!("SPAKE2 handshake failed: {}", e)));
        match handshake_result {
            Ok(derived_key) => {
                eprintln!("SPAKE2 authentication successful!");
                (derived_key, send_stream_mut)
            }
            Err(e) => {
                drop(path_watcher);
                conn.close(2u32.into(), b"handshake failed");
                endpoint.close().await;
                return Err(e);
            }
        }
    } else {
        (key, send_stream)
    };

    // Create owned duplex for unified transfer logic
    let duplex = OwnedIrohDuplex::new(send_stream, recv_stream);

    // Run unified receiver transfer
    let (_path, duplex) = run_receiver_transfer(duplex, key, output_dir, no_resume).await?;

    // Stop path watcher before cleanup
    drop(path_watcher);

    // Finish send stream and wait for acknowledgment (QUIC-specific)
    // This ensures the ACK message is fully delivered before closing the connection.
    let mut send_stream = duplex.into_send_stream();
    send_stream
        .finish()
        .context("Failed to finish send stream")?;

    // Wait for the peer to acknowledge our FIN (with timeout to avoid hanging)
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

    // Close connection gracefully with timeout to avoid hanging indefinitely
    const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

    // Initiate connection close (non-async, just signals intent to close)
    conn.close(0u32.into(), b"transfer complete");

    // Wait for the connection to fully close, with timeout
    match timeout(CLOSE_TIMEOUT, conn.closed()).await {
        Ok(_) => {}
        Err(_) => {
            log::warn!(
                "Waiting for connection close timed out after {:?}",
                CLOSE_TIMEOUT
            );
        }
    }

    // Always close the endpoint, even if connection close timed out
    match timeout(CLOSE_TIMEOUT, endpoint.close()).await {
        Ok(_) => {}
        Err(_) => {
            log::warn!("Endpoint close timed out after {:?}", CLOSE_TIMEOUT);
        }
    }

    eprintln!("Connection closed.");

    Ok(())
}

/// Determine if a connection error indicates a relay or network connectivity issue.
///
/// This function inspects the structured error types from iroh/quinn to identify
/// errors that suggest relay failures, network unreachability, or similar issues
/// that warrant specific error messaging.
fn is_relay_or_network_error(e: &ConnectError) -> bool {
    // First, try to match on structured error variants
    match e {
        ConnectError::Connect { source, .. } => match source {
            ConnectWithOptsError::NoAddress { .. } => return true,
            ConnectWithOptsError::Noq { source, .. } => {
                // Quinn's ConnectError doesn't expose network-level issues directly
                // Check if the error message indicates connection failure
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
    // by the structured matching above. This is a best-effort heuristic for
    // error conditions that iroh/quinn don't expose as distinct variants.
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
        // Future variants: conservatively treat as not relay-related
        _ => false,
    }
}

/// Check if a quinn ConnectionError indicates a network-related issue
fn is_connection_error_network_related(e: &ConnectionError) -> bool {
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
