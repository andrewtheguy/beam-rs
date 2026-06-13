use anyhow::{Context, Result};
use arti_client::{ErrorKind, HasKind, TorClient, config::TorClientConfigBuilder};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::timeout;

use beam_common::core::transfer::run_receiver_transfer;
use beam_common::core::beam::{PROTOCOL_TOR, decode_key, parse_code};
use beam_common::ui::{self, Phase};

const MAX_RETRIES: u32 = 5;
const RETRY_DELAY_SECS: u64 = 5;

/// Default timeout for file transfer over Tor (30 minutes).
/// Tor transfers can be slow due to network latency, so this is generous.
/// Can be overridden via BEAM_TRANSFER_TIMEOUT_SECS environment variable.
const DEFAULT_TRANSFER_TIMEOUT_SECS: u64 = 30 * 60;

/// Get the transfer timeout from environment or use the default.
fn get_transfer_timeout() -> Duration {
    match std::env::var("BEAM_TRANSFER_TIMEOUT_SECS") {
        Ok(val) => match val.parse::<u64>() {
            Ok(secs) => Duration::from_secs(secs),
            Err(_) => {
                ui::sink().status(&format!(
                    "Warning: invalid BEAM_TRANSFER_TIMEOUT_SECS='{}', using default {}s",
                    val, DEFAULT_TRANSFER_TIMEOUT_SECS
                ));
                Duration::from_secs(DEFAULT_TRANSFER_TIMEOUT_SECS)
            }
        },
        Err(_) => Duration::from_secs(DEFAULT_TRANSFER_TIMEOUT_SECS),
    }
}

/// Check if error is retryable (timeout, temporary network issues)
fn is_retryable(e: &arti_client::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::TorNetworkTimeout
            | ErrorKind::RemoteNetworkTimeout
            | ErrorKind::TransientFailure
            | ErrorKind::LocalNetworkError
    )
}

/// Receive a file via Tor hidden service
pub async fn receive_file_tor(code: &str, output_dir: Option<PathBuf>) -> Result<()> {
    ui::sink().set_phase(Phase::Connecting);
    ui::sink().status("Parsing beam code...");

    // Parse the beam code
    let token = parse_code(code).context("Failed to parse beam code")?;

    // Validate protocol
    if token.protocol != PROTOCOL_TOR {
        anyhow::bail!(
            "Expected Tor protocol, got '{}'. Use the appropriate receive command.",
            token.protocol
        );
    }

    let key = decode_key(&token.key).context("Failed to decode encryption key")?;

    let onion_addr = token
        .onion_address
        .context("No onion address in beam code")?;

    ui::sink().status("Code valid. Connecting to sender via Tor...");

    // Bootstrap Tor client (ephemeral mode - allows multiple concurrent receivers)
    // IMPORTANT: _temp_dir must remain in scope for the lifetime of tor_client.
    // The Tor client uses state_dir and cache_dir which are subdirectories of _temp_dir.
    // If _temp_dir is dropped, the directories are deleted and the Tor client will fail.
    let _temp_dir =
        tempfile::tempdir().context("Failed to create temporary directory for Tor client")?;
    let state_dir = _temp_dir.path().join("state");
    let cache_dir = _temp_dir.path().join("cache");

    ui::sink().status("Bootstrapping Tor client (ephemeral mode)...");

    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
        .build()
        .context("Failed to build Tor client configuration")?;
    let tor_client = TorClient::create_bootstrapped(config)
        .await
        .context("Failed to bootstrap Tor client")?;
    ui::sink().status("Tor client bootstrapped!");

    // Retry connection for temporary errors
    let mut stream = None;
    let mut last_error = None;

    for attempt in 1..=MAX_RETRIES {
        ui::sink().status(&format!(
            "Connecting to {} (attempt {}/{})...",
            onion_addr, attempt, MAX_RETRIES
        ));

        match tor_client.connect((onion_addr.as_str(), 80)).await {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => {
                ui::sink().status(&format!("Connection failed: {}", e));

                if !is_retryable(&e) {
                    return Err(e.into());
                }

                last_error = Some(e);
                if attempt < MAX_RETRIES {
                    ui::sink().status(&format!("Retrying in {} seconds...", RETRY_DELAY_SECS));
                    tokio::time::sleep(tokio::time::Duration::from_secs(RETRY_DELAY_SECS)).await;
                }
            }
        }
    }

    let stream = stream.ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to connect after {} attempts: {}",
            MAX_RETRIES,
            last_error.map(|e| e.to_string()).unwrap_or_default()
        )
    })?;

    ui::sink().status("Connected!");

    // Run unified receiver transfer with timeout (no resume for Tor receiver by default)
    // Stream is dropped when function returns or on timeout; no explicit close needed for Tor streams
    ui::sink().set_phase(Phase::Transferring);
    let transfer_timeout = get_transfer_timeout();
    let transfer_result = timeout(
        transfer_timeout,
        run_receiver_transfer(stream, key, output_dir, false),
    )
    .await;

    match transfer_result {
        Ok(Ok((_path, _stream))) => {
            ui::sink().set_phase(Phase::Done);
            ui::sink().status("Transfer complete.");
            Ok(())
        }
        Ok(Err(e)) => {
            // Transfer failed with an error
            Err(e)
        }
        Err(_elapsed) => {
            // Timeout elapsed - stream is dropped here, cleaning up the connection
            ui::sink().status(&format!("Transfer timed out after {:?}", transfer_timeout));
            anyhow::bail!(
                "Transfer timed out after {:?}. You can increase the timeout by setting \
                 BEAM_TRANSFER_TIMEOUT_SECS environment variable.",
                transfer_timeout
            )
        }
    }
}
