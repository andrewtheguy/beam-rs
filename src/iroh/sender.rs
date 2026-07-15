use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
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
use crate::auth::pin::PinMode;
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

const PIN_COUNTDOWN_INTERVAL_SECS: u64 = 10;

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
    // Copied-code iroh flows use this one-time secret to authorize the connecting
    // endpoint before any transfer metadata or content is sent. PIN flows use the PIN.
    let session_secret = generate_key();

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
            let addr = endpoint.addr();
            let code = generate_code(&addr, &session_secret, &relay_urls)?;
            print_receiver_command("beam-rs receive");
            ui::show_code(&code);
            ui::info("Then enter the code above when prompted.\n");
            PairingAuth {
                secret: URL_SAFE_NO_PAD.encode(session_secret),
                session_id: addr.id.to_string(),
            }
        }
        PairingMode::Serverless => {
            wait_for_direct_address_hint(&endpoint).await;
            let addr = endpoint.addr();
            let code = crate::auth::serverless_code::encode(&addr, &session_secret)?;
            let secret = URL_SAFE_NO_PAD.encode(session_secret);
            print_receiver_command("beam-rs receive");
            ui::show_code(&code);
            ui::info("Then paste the beam code when prompted.\n");
            PairingAuth {
                secret,
                session_id: addr.id.to_string(),
            }
        }
        PairingMode::Pin(channel) => {
            let pin_mode = match channel {
                PinChannel::NostrAndLan => PinMode::Normal,
                PinChannel::LanOnly => PinMode::Serverless,
            };
            let pin = crate::auth::pin::generate_pin(pin_mode);
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
            print_receiver_command("beam-rs receive");
            ui::show_pin(&crate::auth::pin::format_pin(&pin));
            ui::info(&format!(
                "This PIN is valid for {} seconds and will not refresh.\n",
                crate::auth::pin::PIN_LIFETIME_SECS
            ));
            pin_deadline = Some(
                tokio::time::Instant::now()
                    + Duration::from_secs(crate::auth::pin::PIN_LIFETIME_SECS),
            );
            PairingAuth {
                secret: pin,
                session_id: addr.id.to_string(),
            }
        }
    };

    ui::status("Waiting for receiver to connect...");

    let mut countdown_task = pin_deadline.map(|_| {
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(PIN_COUNTDOWN_INTERVAL_SECS));
            interval.tick().await;
            let mut seconds_remaining = crate::auth::pin::PIN_LIFETIME_SECS;
            while seconds_remaining > PIN_COUNTDOWN_INTERVAL_SECS {
                interval.tick().await;
                seconds_remaining -= PIN_COUNTDOWN_INTERVAL_SECS;
                ui::transient_status(&format!("PIN expires in {seconds_remaining} seconds..."));
            }
        })
    });

    let (conn, mut send_stream, mut recv_stream, key) = loop {
        let authorize = async {
            let Some(incoming) = endpoint.accept().await else {
                return Ok::<_, anyhow::Error>(None);
            };

            let conn = incoming.await.map_err(|e| {
                if is_relay_or_network_error(&e) {
                    anyhow::anyhow!("Failed to accept connection: {e}")
                } else {
                    anyhow::anyhow!("Failed to authenticate iroh connection: {e}")
                }
            })?;
            let remote_id = conn.remote_id();
            let (mut send_stream, mut recv_stream) =
                conn.open_bi().await.context("Failed to open authorization stream")?;

            // Materialize the QUIC stream before the receiver waits in accept_bi().
            send_stream
                .write_all(&[0x01])
                .await
                .context("Failed to send authorization ready byte")?;
            let mut duplex = IrohDuplex::new(&mut send_stream, &mut recv_stream);
            let handshake_result = tokio::time::timeout(
                Duration::from_secs(30),
                handshake_as_responder(
                    &mut duplex,
                    &pairing_auth.secret,
                    &pairing_auth.session_id,
                    &remote_id.to_string(),
                ),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Peer authorization timed out"))
            .and_then(|result| result.context("Peer authorization failed"));
            let key = match handshake_result {
                Ok(key) => key,
                Err(error) => {
                    conn.close(close_codes::ERROR, b"unauthorized");
                    return Err(error);
                }
            };

            Ok::<_, anyhow::Error>(Some((conn, send_stream, recv_stream, key, remote_id)))
        };

        let result = if let Some(deadline) = pin_deadline {
            match tokio::time::timeout_at(deadline, authorize).await {
                Ok(result) => result,
                Err(_) => {
                    if let Some(task) = nostr_publisher.take() {
                        task.abort();
                    }
                    drop(pin_advert.take());
                    if let Some(task) = countdown_task.take() {
                        task.abort();
                    }
                    ui::transient_status("");
                    endpoint.close().await;
                    ui::status("PIN expired; sender stopped.");
                    return Ok(());
                }
            }
        } else {
            authorize.await
        };

        match result {
            Ok(Some((conn, send_stream, recv_stream, key, remote_id))) => {
                ui::status("Authorized receiver connected!");
                ui::status(&format!("   Receiver ID: {remote_id}"));
                break (conn, send_stream, recv_stream, key);
            }
            Ok(None) => {
                if let Some(task) = nostr_publisher.take() {
                    task.abort();
                }
                drop(pin_advert.take());
                if let Some(task) = countdown_task.take() {
                    task.abort();
                }
                ui::transient_status("");
                anyhow::bail!("Sender endpoint closed while waiting for a receiver");
            }
            Err(error) => {
                log::warn!("Rejected unauthorized receiver: {error:#}");
                ui::status("Rejected unauthorized receiver; waiting for the intended receiver...");
            }
        }
    };
    if let Some(task) = countdown_task.take() {
        task.abort();
    }
    ui::transient_status("");
    if let Some(task) = nostr_publisher.take() {
        task.abort();
    }
    drop(pin_advert.take());

    let path_watcher = watch_connection_paths(&conn);

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
