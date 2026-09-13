use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::Endpoint;
use iroh::endpoint::{Connection, ConnectingError, RecvStream, SendStream};
use std::path::Path;
use std::time::Duration;

use super::common::{
    EndpointReadiness, IrohDuplex, create_endpoint, generate_code,
    is_connection_error_network_related, wait_for_direct_address_hint, watch_connection_paths,
};
use crate::auth::spake2::handshake_as_responder;
use beam_rs::core::crypto::generate_key;
use beam_rs::core::transfer::{TransferResult, prepare_file_for_send, run_sender_transfer};
use beam_rs::ui;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingMode {
    BeamCode,
    Pin,
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

    /// Transfer was cancelled by the receiver (abort).
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
    // by the structured matching above.
    let err_str = e.to_string().to_lowercase();
    err_str.contains("relay")
        || err_str.contains("alpn")
        || err_str.contains("no route")
        || err_str.contains("unreachable")
        || err_str.contains("network")
}

type Authorized = (Connection, SendStream, RecvStream, [u8; 32]);

/// Accept the next incoming connection and authorize it with SPAKE2.
///
/// Returns `Ok(None)` when the endpoint has been closed.
async fn accept_authorized(
    endpoint: &Endpoint,
    secret: &str,
    session_id: &str,
) -> Result<Option<Authorized>> {
    let Some(incoming) = endpoint.accept().await else {
        return Ok(None);
    };

    let conn = incoming.await.map_err(|e| {
        if is_relay_or_network_error(&e) {
            anyhow::anyhow!("Failed to accept connection: {e}")
        } else {
            anyhow::anyhow!("Failed to authenticate iroh connection: {e}")
        }
    })?;
    let remote_id = conn.remote_id();
    let (mut send_stream, mut recv_stream) = conn
        .open_bi()
        .await
        .context("Failed to open authorization stream")?;

    // Materialize the QUIC stream before the receiver waits in accept_bi().
    send_stream
        .write_all(&[0x01])
        .await
        .context("Failed to send authorization ready byte")?;
    let mut duplex = IrohDuplex::new(&mut send_stream, &mut recv_stream);
    let handshake_result = tokio::time::timeout(
        Duration::from_secs(30),
        handshake_as_responder(&mut duplex, secret, session_id, &remote_id.to_string()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Peer authorization timed out"))
    .and_then(|result| result.context("Peer authorization failed"));

    match handshake_result {
        Ok(key) => {
            ui::status("Authorized receiver connected!");
            ui::status(&format!("   Receiver ID: {remote_id}"));
            Ok(Some((conn, send_stream, recv_stream, key)))
        }
        Err(error) => {
            conn.close(close_codes::ERROR, b"unauthorized");
            Err(error)
        }
    }
}

/// Send a file through the beam.
pub async fn send_file(
    file_path: &Path,
    relay_urls: Vec<String>,
    pairing_mode: PairingMode,
) -> Result<()> {
    let prepared = prepare_file_for_send(file_path).await?;
    let mut file = prepared.file;
    let header = prepared.header;

    // Copied-code flows use this one-time secret to authorize the connecting
    // endpoint (via SPAKE2) before any transfer metadata or content is sent.
    // PIN flows use the PIN.
    let session_secret = generate_key();

    let readiness = match pairing_mode {
        PairingMode::BeamCode => EndpointReadiness::RelayOnline,
        PairingMode::Pin | PairingMode::Serverless => EndpointReadiness::LanDirect,
    };
    let endpoint = create_endpoint(relay_urls.clone(), readiness, true).await?;

    let mut pin_advert = None;
    let mut pin_deadline = None;

    let (secret, session_id) = match pairing_mode {
        PairingMode::BeamCode => {
            let addr = endpoint.addr();
            let code = generate_code(&addr, &session_secret, &relay_urls)?;
            print_receiver_command();
            ui::show_code(&code);
            ui::info("Then enter the code above when prompted.\n");
            (URL_SAFE_NO_PAD.encode(session_secret), addr.id.to_string())
        }
        PairingMode::Serverless => {
            wait_for_direct_address_hint(&endpoint).await;
            let addr = endpoint.addr();
            let code = crate::auth::serverless_code::encode(&addr, &session_secret)?;
            print_receiver_command();
            ui::show_code(&code);
            ui::info("Then paste the beam code when prompted.\n");
            (URL_SAFE_NO_PAD.encode(session_secret), addr.id.to_string())
        }
        PairingMode::Pin => {
            let pin = crate::auth::pin::generate_pin();
            let bucket = crate::auth::pin::current_bucket();
            let key = tokio::task::spawn_blocking({
                let pin = pin.clone();
                move || crate::auth::pin_record::record_key(&pin, bucket)
            })
            .await
            .context("PIN key-derivation task failed")??;
            let addr = endpoint.addr();
            let direct_addrs: Vec<_> = addr.ip_addrs().copied().collect();
            pin_advert = Some(crate::auth::lan::advertise_pin_record(
                &key,
                &addr.id,
                direct_addrs,
            )?);
            print_receiver_command();
            ui::show_pin(&crate::auth::pin::format_pin(&pin));
            ui::info(&format!(
                "This PIN is valid for {} seconds and will not refresh.\n",
                crate::auth::pin::PIN_LIFETIME_SECS
            ));
            pin_deadline = Some(
                tokio::time::Instant::now()
                    + Duration::from_secs(crate::auth::pin::PIN_LIFETIME_SECS),
            );
            (pin, addr.id.to_string())
        }
    };

    ui::status("Waiting for receiver to connect...");

    let countdown_task = pin_deadline.map(|_| {
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

    // `Ok(None)` means the PIN expired before an authorized receiver connected.
    let accepted: Result<Option<Authorized>> = loop {
        let authorize = accept_authorized(&endpoint, &secret, &session_id);
        let result = match pin_deadline {
            Some(deadline) => match tokio::time::timeout_at(deadline, authorize).await {
                Ok(result) => result,
                Err(_) => break Ok(None),
            },
            None => authorize.await,
        };

        match result {
            Ok(Some(authorized)) => break Ok(Some(authorized)),
            Ok(None) => {
                break Err(anyhow::anyhow!(
                    "Sender endpoint closed while waiting for a receiver"
                ));
            }
            Err(error) => {
                log::warn!("Rejected unauthorized receiver: {error:#}");
                ui::status("Rejected unauthorized receiver; waiting for the intended receiver...");
            }
        }
    };

    // Stop advertising the PIN and its countdown whether or not a receiver connected.
    if let Some(task) = countdown_task {
        task.abort();
        ui::transient_status("");
    }
    drop(pin_advert);

    let Some((conn, mut send_stream, mut recv_stream, key)) = accepted? else {
        endpoint.close().await;
        ui::status("PIN expired; sender stopped.");
        return Ok(());
    };

    let path_watcher = watch_connection_paths(&conn);

    let mut duplex = IrohDuplex::new(&mut send_stream, &mut recv_stream);
    let transfer_result = run_sender_transfer(&mut file, &mut duplex, &key, &header).await;

    drop(path_watcher);

    match transfer_result {
        Ok(TransferResult::Success) => {}
        Ok(TransferResult::Aborted) => {
            conn.close(close_codes::CANCELLED, b"cancelled");
            endpoint.close().await;
            anyhow::bail!("Transfer cancelled by receiver");
        }
        Err(e) => {
            conn.close(close_codes::ERROR, b"error");
            endpoint.close().await;
            return Err(e);
        }
    }

    // Finish the send stream to signal we're done sending (QUIC-specific)
    let finish_result = send_stream.finish().context("Failed to finish stream");

    if finish_result.is_ok() {
        conn.close(close_codes::OK, b"done");
    } else {
        conn.close(close_codes::ERROR, b"finish failed");
    }
    endpoint.close().await;

    finish_result?;

    ui::status("Connection closed.");

    Ok(())
}

fn print_receiver_command() {
    ui::info("On the receiving end, run:");
    ui::info("  beam-rs receive\n");
}
