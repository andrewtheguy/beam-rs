use anyhow::{Context, Result};
use iroh::endpoint::{ConnectingError, ConnectionError};
use std::path::Path;
use tokio::fs::File;
use tokio::sync::oneshot;

use super::common::{IrohDuplex, create_sender_endpoint, generate_code, watch_connection_paths};
use crate::cli::instructions::print_receiver_command;
use beam_common::auth::PinInfo;
use beam_common::auth::spake2::handshake_as_responder;
use beam_common::core::crypto::generate_key;
use beam_common::core::transfer::{
    FileHeader, Interrupted, TransferResult, TransferType, run_sender_transfer, send_file_with,
    send_folder_with,
};
use beam_common::signaling::nostr_protocol::generate_transfer_id;

/// QUIC application close codes for connection termination.
///
/// These codes are sent to the peer when closing the connection to indicate
/// the reason for closure. Peers can use these to distinguish between normal
/// completion, errors, and cancellation.
mod close_codes {
    use iroh::endpoint::VarInt;

    /// Normal successful completion of the transfer.
    pub const OK: VarInt = VarInt::from_u32(0);

    /// Transfer was cancelled by user or receiver (abort).
    pub const CANCELLED: VarInt = VarInt::from_u32(1);

    /// An error occurred during transfer.
    pub const ERROR: VarInt = VarInt::from_u32(2);
}

/// Determine if a ConnectingError indicates a relay or network connectivity issue.
///
/// This function inspects the structured error types from iroh/quinn to identify
/// errors that suggest relay failures, network unreachability, or similar issues
/// that warrant specific error messaging.
fn is_relay_or_network_error(e: &ConnectingError) -> bool {
    // First, try to match on structured error variants
    match e {
        ConnectingError::ConnectionError { source, .. } => {
            return is_connection_error_network_related(source);
        }
        ConnectingError::HandshakeFailure { .. } => {
            // Handshake failures can indicate ALPN/relay issues
            return true;
        }
        _ => {}
    }

    // Fallback: check error message as a last resort for cases not covered
    // by the structured matching above. This is a best-effort heuristic for
    // error conditions that iroh/quinn don't expose as distinct variants.
    let err_str = e.to_string().to_lowercase();
    err_str.contains("relay")
        || err_str.contains("alpn")
        || err_str.contains("no route")
        || err_str.contains("unreachable")
        || err_str.contains("network")
}

/// Check if a quinn ConnectionError indicates a network-related issue.
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

/// Internal helper for common transfer logic.
/// Handles encryption setup, endpoint creation, connection, data transfer, and acknowledgment.
///
/// If `shutdown_rx` is provided and receives a signal, the transfer will be cancelled
/// and the connection will be properly closed before returning `Interrupted`.
#[allow(clippy::too_many_arguments)]
async fn transfer_data_internal(
    mut file: File,
    filename: String,
    file_size: u64,
    checksum: u64,
    transfer_type: TransferType,
    relay_urls: Vec<String>,
    use_pin: bool,
    local_only: bool,
    shutdown_rx: Option<oneshot::Receiver<()>>,
) -> Result<()> {
    // Always generate encryption key for application-layer encryption
    let key = generate_key();

    // Create iroh endpoint
    let endpoint = create_sender_endpoint(relay_urls, local_only).await?;

    // Get our address
    let addr = endpoint.addr();

    // Generate beam code
    let code = generate_code(&addr, &key)?;

    if use_pin {
        print_receiver_command("beam-rs receive --pin");
    } else {
        print_receiver_command("beam-rs receive");
    }

    println!("\n🔮 Beam code:\n{}\n", code);

    let pin_info = if use_pin {
        // Generate ephemeral keys for PIN exchange
        let keys = nostr_sdk::Keys::generate();
        // Generate unique transfer ID to avoid collisions with concurrent transfers
        let transfer_id = generate_transfer_id();
        let pin = beam_common::auth::nostr_pin::publish_beam_code_via_pin(
            &keys,
            &code,
            &transfer_id,
        )
        .await?;

        println!("🔢 PIN: {}\n", pin);
        println!("Then enter the PIN above when prompted.\n");
        Some(PinInfo { pin, transfer_id })
    } else {
        println!("Then enter the code above when prompted.\n");
        None
    };

    eprintln!("Waiting for receiver to connect...");

    // Wait for connection
    let conn = endpoint
        .accept()
        .await
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No incoming connection.\n\n\
                 Troubleshooting:\n  \
                 - Ensure the receiver has the correct beam code\n  \
                 - Check network connectivity on both ends"
            )
        })?
        .await
        .map_err(|e| {
            // Use structured error types to determine if this is a relay/network issue
            if is_relay_or_network_error(&e) {
                anyhow::anyhow!(
                    "Failed to accept connection: {}\n\n\
                     Relay connection failed. Check network connectivity and firewall settings.",
                    e
                )
            } else {
                anyhow::anyhow!(
                    "Failed to accept connection: {}\n\n\
                     Troubleshooting:\n  \
                     - Ensure the receiver has the correct beam code\n  \
                     - Check network connectivity and firewall settings",
                    e
                )
            }
        })?;

    let remote_id = conn.remote_id();
    eprintln!("Receiver connected!");
    eprintln!("   Remote ID: {}", remote_id);

    let path_watcher = watch_connection_paths(&conn);

    // Open bi-directional stream
    let (mut send_stream, mut recv_stream) =
        conn.open_bi().await.context("Failed to open stream")?;

    // Perform SPAKE2 handshake if PIN mode is active (sender = responder)
    let key = if let Some(ref pin_info) = pin_info {
        let (pin, transfer_id) = (&pin_info.pin, &pin_info.transfer_id);
        eprintln!("Performing SPAKE2 authentication...");
        // Write a "ready" byte to materialize the QUIC stream on the receiver side.
        // In QUIC, open_bi() allocates the stream locally but may not send a STREAM
        // frame until data is written. Since SPAKE2 responder reads first, without
        // this the receiver's accept_bi() would never see the stream.
        send_stream.write_all(&[0x01]).await.context("Failed to send ready byte")?;
        let mut duplex = IrohDuplex::new(&mut send_stream, &mut recv_stream);
        let handshake_result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            handshake_as_responder(&mut duplex, pin, transfer_id),
        )
        .await
        .map_err(|_| anyhow::anyhow!("SPAKE2 handshake timed out"))
        .and_then(|r| r.map_err(|e| anyhow::anyhow!("SPAKE2 handshake failed: {}", e)));
        match handshake_result {
            Ok(derived_key) => {
                eprintln!("SPAKE2 authentication successful!");
                derived_key
            }
            Err(e) => {
                drop(path_watcher);
                conn.close(close_codes::ERROR, b"handshake failed");
                endpoint.close().await;
                return Err(e);
            }
        }
    } else {
        key
    };

    // Create header and run unified transfer logic
    let header = FileHeader::new(transfer_type, filename, file_size, checksum);
    let mut duplex = IrohDuplex::new(&mut send_stream, &mut recv_stream);

    // Run transfer with optional shutdown handling
    // Don't use ? here - we need to ensure cleanup on all paths
    let transfer_result = if let Some(shutdown_rx) = shutdown_rx {
        tokio::select! {
            result = run_sender_transfer(&mut file, &mut duplex, &key, &header) => result,
            _ = shutdown_rx => {
                // Graceful shutdown requested - notify receiver and close connection
                eprintln!("\nShutdown requested, cancelling transfer...");
                drop(path_watcher);
                conn.close(close_codes::CANCELLED, b"cancelled");
                endpoint.close().await;
                return Err(Interrupted.into());
            }
        }
    } else {
        run_sender_transfer(&mut file, &mut duplex, &key, &header).await
    };

    // Stop path watcher before cleanup
    drop(path_watcher);

    // Handle transfer result - ensure cleanup on all paths
    match transfer_result {
        Ok(TransferResult::Aborted) => {
            conn.close(close_codes::CANCELLED, b"cancelled");
            endpoint.close().await;
            anyhow::bail!("Transfer cancelled by receiver");
        }
        Ok(_) => {
            // Success - proceed with normal cleanup below
        }
        Err(e) => {
            // Transfer error - close connection and propagate error
            conn.close(close_codes::ERROR, b"error");
            endpoint.close().await;
            return Err(e);
        }
    }

    // Finish the send stream to signal we're done sending (QUIC-specific)
    let finish_result = send_stream.finish().context("Failed to finish stream");

    // Close connection with appropriate code based on finish result
    if finish_result.is_ok() {
        conn.close(close_codes::OK, b"done");
    } else {
        conn.close(close_codes::ERROR, b"finish failed");
    }
    endpoint.close().await;

    // Propagate finish error after cleanup
    finish_result?;

    eprintln!("Connection closed.");

    Ok(())
}

/// Send a file through the beam.
pub async fn send_file(
    file_path: &Path,
    relay_urls: Vec<String>,
    use_pin: bool,
    local_only: bool,
) -> Result<()> {
    send_file_with(
        file_path,
        |file, filename, file_size, checksum, transfer_type| {
            transfer_data_internal(
                file,
                filename,
                file_size,
                checksum,
                transfer_type,
                relay_urls,
                use_pin,
                local_only,
                None, // No shutdown receiver for resumable file transfers
            )
        },
    )
    .await
}

/// Send a folder as a tar archive.
///
/// Note: File permissions may not be fully preserved in cross-platform transfers,
/// especially when sending from Unix to Windows or vice versa. Windows does not
/// support Unix permission modes (rwx), so files may have different permissions
/// after extraction on Windows.
pub async fn send_folder(
    folder_path: &Path,
    relay_urls: Vec<String>,
    use_pin: bool,
    local_only: bool,
) -> Result<()> {
    send_folder_with(
        folder_path,
        |file, filename, file_size, checksum, transfer_type| {
            transfer_data_internal(
                file,
                filename,
                file_size,
                checksum,
                transfer_type,
                relay_urls,
                use_pin,
                local_only,
                None, // Shutdown handling is done by send_folder_with
            )
        },
    )
    .await
}
