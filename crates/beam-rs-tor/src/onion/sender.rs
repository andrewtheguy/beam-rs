use anyhow::Result;
use arti_client::{TorClient, config::TorClientConfigBuilder};
use futures::StreamExt;
use rand::Rng;
use safelog::DisplayRedacted;
use std::path::Path;
use std::time::Duration;
use tokio::fs::File;
use tokio::time::timeout;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests};

use beam_common::core::crypto::generate_key;
use beam_common::core::transfer::{
    FileHeader, TransferResult, TransferType, run_sender_transfer_with_timeout, send_file_with,
    send_folder_with,
};
use beam_common::core::beam::generate_tor_code;
use beam_common::ui::{self, Phase};

/// Timeout for waiting for receiver to connect via Tor (10 minutes)
/// Tor connections can be slow due to circuit building, so this is generous
const TOR_CONNECTION_TIMEOUT: Duration = Duration::from_secs(600);

/// Timeout for waiting for receiver's ACK after transfer completes.
/// Tor streams may close abruptly, so a timeout here is treated as success.
const ACK_TIMEOUT: Duration = Duration::from_secs(10);

fn print_receiver_command(command: &str) {
    ui::sink().info("On the receiving end, run:");
    ui::sink().info(&format!("  {}\n", command));
}

/// Internal helper for common Tor transfer logic.
/// Handles Tor bootstrap, onion service, connection, data transfer, and acknowledgment.
async fn transfer_data_tor_internal(
    mut file: File,
    filename: String,
    file_size: u64,
    checksum: u64,
    transfer_type: TransferType,
) -> Result<()> {
    ui::sink().set_phase(Phase::Preparing);

    // Always generate encryption key for application-layer encryption
    let key = generate_key();

    // Bootstrap Tor client (ephemeral mode - new keys each run)
    // IMPORTANT: _temp_dir must remain in scope for the lifetime of tor_client.
    // The Tor client uses state_dir and cache_dir which are subdirectories of _temp_dir.
    // If _temp_dir is dropped, the directories are deleted and the Tor client will fail.
    let _temp_dir = tempfile::tempdir()?;
    let state_dir = _temp_dir.path().join("state");
    let cache_dir = _temp_dir.path().join("cache");

    ui::sink().status("Bootstrapping Tor client (ephemeral mode)...");

    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir).build()?;
    let tor_client = TorClient::create_bootstrapped(config).await?;

    ui::sink().status("Tor client bootstrapped!");

    // Generate a random nickname for ephemeral service
    let random_suffix: u64 = rand::thread_rng().r#gen();
    let nickname = format!("wh_{:016x}", random_suffix);

    // Configure onion service
    let hs_config = OnionServiceConfigBuilder::default()
        .nickname(nickname.parse()?)
        .build()?;

    // Launch service
    let (onion_service, rend_requests) = tor_client
        .launch_onion_service(hs_config)?
        .ok_or_else(|| anyhow::anyhow!("Failed to launch onion service"))?;

    // Get .onion address
    let onion_addr = onion_service
        .onion_address()
        .ok_or_else(|| anyhow::anyhow!("No onion address available yet"))?;

    let onion_addr_str = format!("{}", onion_addr.display_unredacted());

    // Generate beam code
    let code = generate_tor_code(onion_addr_str.clone(), &key)?;

    print_receiver_command("beam-rs-tor receive");

    ui::sink().show_code(&code);
    ui::sink().info("Then enter the code above when prompted.\n");

    ui::sink().set_phase(Phase::Waiting);
    ui::sink().status("Waiting for receiver to connect via Tor...");

    // Convert RendRequest stream to StreamRequest stream
    let mut stream_requests = handle_rend_requests(rend_requests);

    // Wait for incoming stream request with timeout
    let stream_req = match timeout(TOR_CONNECTION_TIMEOUT, stream_requests.next()).await {
        Ok(Some(req)) => req,
        Ok(None) => {
            anyhow::bail!("No connection received (stream closed)");
        }
        Err(_) => {
            ui::sink().status(&format!(
                "Timed out waiting for receiver after {:?}",
                TOR_CONNECTION_TIMEOUT
            ));
            anyhow::bail!(
                "No receiver connected within {:?}. The beam code may have expired.",
                TOR_CONNECTION_TIMEOUT
            );
        }
    };

    ui::sink().set_phase(Phase::Connecting);
    ui::sink().status("Receiver connected! Accepting stream...");

    // Accept the stream request
    let mut stream = stream_req.accept(Connected::new_empty()).await?;

    // Create header and run unified transfer logic with 10s ACK timeout
    // Tor streams may close abruptly, so timeout is considered successful
    ui::sink().set_phase(Phase::Transferring);
    let header = FileHeader::new(transfer_type, filename, file_size, checksum);
    let result = run_sender_transfer_with_timeout(
        &mut file,
        &mut stream,
        &key,
        &header,
        Some(ACK_TIMEOUT),
    )
    .await?;

    if result == TransferResult::Aborted {
        anyhow::bail!("Transfer cancelled by receiver");
    }

    ui::sink().set_phase(Phase::Done);
    ui::sink().status("Done.");

    Ok(())
}

/// Send a file via Tor hidden service
pub async fn send_file_tor(file_path: &Path) -> Result<()> {
    send_file_with(
        file_path,
        |file, filename, file_size, checksum, transfer_type| {
            transfer_data_tor_internal(file, filename, file_size, checksum, transfer_type)
        },
    )
    .await
}

/// Send a folder via Tor hidden service (as tar archive)
pub async fn send_folder_tor(folder_path: &Path) -> Result<()> {
    send_folder_with(
        folder_path,
        |file, filename, file_size, checksum, transfer_type| {
            transfer_data_tor_internal(file, filename, file_size, checksum, transfer_type)
        },
    )
    .await
}
