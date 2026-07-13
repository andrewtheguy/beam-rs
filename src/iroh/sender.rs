use anyhow::{Context, Result};
use iroh::endpoint::ConnectingError;
use std::path::Path;
use std::time::Duration;
use tokio::fs::File;
use tokio::sync::oneshot;

use super::common::{
    EndpointReadiness, IrohDuplex, create_sender_endpoint, generate_code,
    is_connection_error_network_related, wait_for_direct_address_hint, watch_connection_paths,
};
use crate::cli::instructions::print_receiver_command;
use crate::auth::PairingAuth;
use crate::auth::rendezvous::PinChannel;
use crate::auth::spake2::handshake_as_responder;
use beam_rs::core::crypto::generate_key;
use beam_rs::ui;
use beam_rs::core::transfer::{
    FileHeader, Interrupted, TransferResult, TransferType, run_sender_transfer, send_file_with,
    send_folder_with,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingMode {
    BeamCode,
    Pin(PinChannel),
    Serverless,
}

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
    pairing_mode: PairingMode,
    shutdown_rx: Option<oneshot::Receiver<()>>,
) -> Result<()> {
    // Always generate encryption key for application-layer encryption
    let key = generate_key();

    let readiness = match pairing_mode {
        PairingMode::BeamCode => EndpointReadiness::RelayOnline,
        PairingMode::Pin(PinChannel::NostrAndLan) => EndpointReadiness::RelayPreferred,
        PairingMode::Pin(PinChannel::LanOnly) | PairingMode::Serverless => {
            EndpointReadiness::LanDirect
        }
    };
    let endpoint = create_sender_endpoint(relay_urls.clone(), readiness).await?;

    let mut pin_advert = None;
    let mut nostr_publisher = None;
    let mut pin_deadline = None;

    let pairing_auth = match pairing_mode {
        PairingMode::BeamCode => {
            let code = generate_code(&endpoint.addr(), &key, &relay_urls)?;
            print_receiver_command("beam-rs receive");
            ui::show_code(&code);
            ui::info("Then enter the code above when prompted.\n");
            None
        }
        PairingMode::Serverless => {
            wait_for_direct_address_hint(&endpoint).await;
            let addr = endpoint.addr();
            let secret_bytes = generate_key();
            let code = crate::auth::serverless_code::encode(&addr, &secret_bytes)?;
            let secret = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                secret_bytes,
            );
            print_receiver_command("beam-rs receive");
            ui::show_code(&code);
            ui::info("Then paste the beam code when prompted.\n");
            Some(PairingAuth {
                secret,
                session_id: addr.id.to_string(),
            })
        }
        PairingMode::Pin(channel) => {
            let pin = crate::auth::pin::generate_pin();
            let bucket = crate::auth::pin::current_bucket();
            let keys = tokio::task::spawn_blocking({
                let pin = pin.clone();
                move || crate::auth::pin_record::pin_keys(&pin, bucket)
            })
            .await
            .context("PIN key-derivation task failed")??;
            let addr = endpoint.addr();
            if channel.lan() {
                let direct_addrs: Vec<_> = addr.ip_addrs().copied().collect();
                match crate::auth::lan::advertise_pin_record(&keys, &addr.id, direct_addrs) {
                    Ok(advert) => pin_advert = Some(advert),
                    Err(error) if channel == PinChannel::LanOnly => return Err(error),
                    Err(error) => {
                        log::warn!("Failed to advertise PIN on the local network: {error:#}")
                    }
                }
            }
            let expires_at_unix = crate::auth::rendezvous::expires_at_unix();
            if channel.nostr() {
                let node_id = addr.id;
                nostr_publisher = Some(tokio::spawn(async move {
                    if let Err(error) = crate::auth::rendezvous::publish_nostr_record(
                        &keys,
                        &node_id,
                        expires_at_unix,
                    )
                    .await
                    {
                        log::warn!("Failed to publish PIN to Nostr: {error:#}");
                    }
                }));
            }
            let receiver_command = if channel == PinChannel::LanOnly {
                "beam-rs receive --serverless"
            } else {
                "beam-rs receive"
            };
            print_receiver_command(receiver_command);
            ui::show_pin(&crate::auth::pin::format_pin(&pin));
            ui::info("This PIN is valid for 60 seconds and will not refresh.\n");
            pin_deadline = Some(
                tokio::time::Instant::now()
                    + Duration::from_secs(crate::auth::pin::PIN_LIFETIME_SECS),
            );
            Some(PairingAuth {
                secret: pin,
                session_id: addr.id.to_string(),
            })
        }
    };

    ui::status("Waiting for receiver to connect...");

    let incoming = if let Some(deadline) = pin_deadline {
        match tokio::time::timeout_at(deadline, endpoint.accept()).await {
            Ok(Some(incoming)) => incoming,
            Ok(None) => anyhow::bail!("Sender endpoint closed while waiting for a receiver"),
            Err(_) => {
                if let Some(task) = nostr_publisher.take() {
                    task.abort();
                }
                drop(pin_advert.take());
                endpoint.close().await;
                ui::status("PIN expired; sender stopped.");
                return Ok(());
            }
        }
    } else {
        endpoint.accept().await.ok_or_else(|| {
            anyhow::anyhow!(
                "No incoming connection.\n\n\
                 Troubleshooting:\n  \
                 - Ensure the receiver has the correct pairing input\n  \
                 - Check network connectivity on both ends"
            )
        })?
    };
    if let Some(task) = nostr_publisher.take() {
        task.abort();
    }
    drop(pin_advert.take());

    let conn = incoming
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
                     - Ensure the receiver has the correct pairing input\n  \
                     - Check network connectivity and firewall settings",
                    e
                )
            }
        })?;

    let remote_id = conn.remote_id();
    ui::status("Receiver connected!");
    ui::status(&format!("   Remote ID: {}", remote_id));

    let path_watcher = watch_connection_paths(&conn);

    // Open bi-directional stream
    let (mut send_stream, mut recv_stream) =
        conn.open_bi().await.context("Failed to open stream")?;

    // PIN and serverless modes both authenticate their session secret with SPAKE2.
    let key = if let Some(ref pairing_auth) = pairing_auth {
        ui::status("Performing SPAKE2 authentication...");
        // Write a "ready" byte to materialize the QUIC stream on the receiver side.
        // In QUIC, open_bi() allocates the stream locally but may not send a STREAM
        // frame until data is written. Since SPAKE2 responder reads first, without
        // this the receiver's accept_bi() would never see the stream.
        send_stream.write_all(&[0x01]).await.context("Failed to send ready byte")?;
        let mut duplex = IrohDuplex::new(&mut send_stream, &mut recv_stream);
        let handshake_result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            handshake_as_responder(
                &mut duplex,
                &pairing_auth.secret,
                &pairing_auth.session_id,
            ),
        )
        .await
        .map_err(|_| anyhow::anyhow!("SPAKE2 handshake timed out"))
        .and_then(|r| r.map_err(|e| anyhow::anyhow!("SPAKE2 handshake failed: {}", e)));
        match handshake_result {
            Ok(derived_key) => {
                ui::status("SPAKE2 authentication successful!");
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
                ui::status("\nShutdown requested, cancelling transfer...");
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

    ui::status("Connection closed.");

    Ok(())
}

/// Send a file through the beam.
pub async fn send_file(
    file_path: &Path,
    relay_urls: Vec<String>,
    pairing_mode: PairingMode,
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
                pairing_mode,
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
    pairing_mode: PairingMode,
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
                pairing_mode,
                None, // Shutdown handling is done by send_folder_with
            )
        },
    )
    .await
}
