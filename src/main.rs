use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

use beam_rs::core::transfer::is_interrupted;
use beam_rs::core::beam;
use beam_rs::ui;

mod auth;
mod signaling;
use auth::PinInfo;

mod iroh;
use iroh::{receiver as iroh_receiver, sender as iroh_sender};

mod onion;
use onion::{receiver as onion_receiver, sender as onion_sender};

mod cli;

#[derive(Parser)]
#[command(name = "beam-rs")]
#[command(about = "Secure peer-to-peer file transfer")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file or folder via iroh (default, recommended)
    Send {
        /// Path to file or folder
        path: PathBuf,

        /// Send a folder (creates tar archive)
        #[arg(long)]
        folder: bool,

        /// Use PIN-based code exchange for Nostr (prompts for PIN input)
        #[arg(long)]
        pin: bool,

        /// Custom relay server URLs (for iroh transport)
        #[arg(long)]
        relay_url: Vec<String>,

        /// Serverless: no third-party server: disable relays (and Nostr), embed
        /// all discovered IPs (LAN and public) in the beam code, and connect
        /// directly via those with mDNS as a fallback. Primarily for same-LAN
        /// transfers (not strictly local-only). Incompatible with --pin and
        /// --relay-url.
        #[arg(long)]
        serverless: bool,

        /// Send via a Tor hidden service (anonymous) instead of iroh.
        /// Incompatible with --pin, --relay-url, and --serverless.
        #[arg(long)]
        tor: bool,
    },

    /// Receive a file or folder using a beam code or PIN
    Receive {
        /// Output directory (default: current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Disable resumable transfers (don't save partial downloads)
        #[arg(long)]
        no_resume: bool,
    },
}

/// Validate path exists and matches folder flag
fn validate_path(path: &Path, folder: bool) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("Path not found: {}", path.display());
    }

    if folder {
        if !path.is_dir() {
            anyhow::bail!(
                "--folder specified but path is not a directory: {}",
                path.display()
            );
        }
    } else if !path.is_file() {
        anyhow::bail!(
            "Path is not a regular file: {}. If you intended a directory, use --folder.",
            path.display()
        );
    }

    Ok(())
}

/// Validate output directory exists and is a directory
fn validate_output_dir(output: &Option<PathBuf>) -> Result<()> {
    if let Some(dir) = output {
        if !dir.exists() {
            anyhow::bail!("Output path does not exist: {}", dir.display());
        }
        if !dir.is_dir() {
            anyhow::bail!("Output path is not a directory: {}", dir.display());
        }
    }
    Ok(())
}

fn main() {
    // Run the async main and handle errors
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime")
        .block_on(async_main());

    if let Err(e) = result {
        // Check if this was an interrupt (Ctrl+C)
        if is_interrupted(&e) {
            // Exit with 128 + SIGINT (2) = 130, standard Unix convention
            std::process::exit(130);
        }
        // Print error and exit with failure code
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}

async fn async_main() -> Result<()> {
    // Install the process-level rustls CryptoProvider. The iroh transport passes
    // its own provider explicitly, but the Nostr relay path (WebSocket TLS) relies
    // on rustls' global default, which newer rustls versions no longer auto-select.
    // Without this, `--pin` panics with "Could not automatically determine the
    // process-level CryptoProvider". Ignore the error if one is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    init_tracing();
    run(cli.command).await
}

/// Set up quiet-by-default diagnostic logging. User-facing transfer status is
/// printed separately by `ui`, while `RUST_LOG` can opt into detailed logs.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("error"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();
}

/// Prompt for a beam code or PIN, re-prompting on empty input.
///
/// Auto-detection happens at the call site via [`crate::auth::pin::validate_pin`].
/// As a usability aid, an input that has the PIN length and uses only PIN
/// characters but fails the checksum is treated as a mistyped PIN and re-prompted
/// (pre-filled for editing) rather than silently falling through to be parsed as a
/// beam code, which would produce a confusing "invalid code" error.
fn prompt_code_or_pin() -> Result<String> {
    use crate::auth::pin::{PIN_CHARSET, PIN_LENGTH, validate_pin};

    let mut initial = String::new();
    loop {
        let input = ui::prompt_line("Enter beam code or PIN: ", &initial)?
            .trim()
            .to_string();

        if input.is_empty() {
            ui::info("Input cannot be empty.");
            initial = String::new();
            continue;
        }

        // Looks like a PIN attempt (right length, valid charset) but the checksum
        // doesn't match — almost certainly a typo. Re-prompt instead of treating
        // it as a beam code.
        let looks_like_pin = input.len() == PIN_LENGTH
            && input.bytes().all(|b| PIN_CHARSET.contains(&b));
        if looks_like_pin && !validate_pin(&input) {
            ui::info("That looks like a PIN but the checksum is invalid — please re-check it.");
            initial = input;
            continue;
        }

        return Ok(input);
    }
}

/// Dispatch the parsed CLI command.
async fn run(command: Commands) -> Result<()> {
    match command {
        Commands::Send {
            path,
            folder,
            pin,
            relay_url,
            serverless,
            tor,
        } => {
            validate_path(&path, folder)?;
            if tor && (pin || serverless || !relay_url.is_empty()) {
                anyhow::bail!(
                    "--tor cannot be combined with --pin, --serverless, or --relay-url: \
                     those options configure the iroh transport, which --tor replaces."
                );
            }
            if tor {
                if folder {
                    onion_sender::send_folder_tor(&path).await?;
                } else {
                    onion_sender::send_file_tor(&path).await?;
                }
                return Ok(());
            }
            if serverless && pin {
                anyhow::bail!(
                    "--serverless cannot be combined with --pin: PIN exchange uses Nostr, \
                     which requires a third-party server."
                );
            }
            if serverless && !relay_url.is_empty() {
                anyhow::bail!(
                    "--serverless cannot be combined with --relay-url: relays are disabled \
                     in serverless mode."
                );
            }
            if folder {
                iroh_sender::send_folder(&path, relay_url, pin, serverless).await?;
            } else {
                iroh_sender::send_file(&path, relay_url, pin, serverless).await?;
            }
        }

        Commands::Receive { output, no_resume } => {
            // Validate output directory if provided
            validate_output_dir(&output)?;

            // Prompt for the input, then auto-detect whether it is a 12-character
            // PIN (resolved via Nostr) or a full beam code.
            let input = prompt_code_or_pin()?;

            let (code, pin_info) = if crate::auth::pin::validate_pin(&input) {
                ui::status("Searching for beam token via Nostr...");

                // Fetch encrypted token from Nostr using the PIN.
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    crate::auth::nostr_pin::fetch_beam_code_via_pin(&input),
                )
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Timeout: Failed to retrieve beam code from Nostr after 30 seconds"
                    )
                })??;
                ui::status("Token found and decrypted!");
                (result.code, Some(PinInfo { pin: input, transfer_id: result.transfer_id }))
            } else {
                (input, None)
            };

            receive_with_code(&code, output, no_resume, pin_info).await?;
        }
    }

    Ok(())
}

/// Receive using a beam code (auto-detects transport)
async fn receive_with_code(
    code: &str,
    output: Option<PathBuf>,
    no_resume: bool,
    pin_info: Option<PinInfo>,
) -> Result<()> {
    // Validate code format
    beam::validate_code_format(code)?;

    // Parse code to determine transport
    let token = beam::parse_code(code)?;

    match token.protocol.as_str() {
        beam::PROTOCOL_IROH => {
            // A serverless code carries an endpoint address with no relay URL
            // (but embedded direct IPs). Detect that and disable relays on the
            // receiver to match the sender. Any custom relays the sender used
            // travel inside the code, so the receiver needs no relay flag.
            let serverless = token
                .addr
                .as_ref()
                .map(|addr| addr.relay.is_none())
                .unwrap_or(false);
            iroh_receiver::receive(code, output, no_resume, pin_info, serverless).await?;
        }
        beam::PROTOCOL_TOR => {
            // A Tor code carries an onion address; bootstrap the Tor client and
            // connect anonymously. `pin_info` is iroh-only and does not apply
            // to the Tor transport.
            onion_receiver::receive_file_tor(code, output, no_resume).await?;
        }
        proto => {
            anyhow::bail!("Unknown protocol in beam code: {}", proto);
        }
    }

    Ok(())
}
