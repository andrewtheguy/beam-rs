use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

use beam_rs::core::transfer::is_interrupted;
use beam_rs::core::beam;
use beam_rs::ui;

mod auth;

mod iroh;
use iroh::{receiver as iroh_receiver, sender as iroh_sender};
use iroh::common::EndpointReadiness;
use iroh::sender::PairingMode;
use auth::rendezvous::PinChannel;

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

        /// Use a single 60-second PIN advertised over Nostr and the LAN
        #[arg(long)]
        pin: bool,

        /// Custom relay server URLs (for iroh transport)
        #[arg(long)]
        relay_url: Vec<String>,

        /// Use no third-party services: copy/paste a direct-address code, or
        /// combine with --pin for LAN-only mDNS PIN discovery.
        #[arg(long)]
        serverless: bool,

        /// Send via a Tor hidden service (anonymous) instead of iroh.
        /// Incompatible with iroh pairing and relay options.
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

        /// With a PIN, resolve only over mDNS and disable iroh relays/DNS
        #[arg(long)]
        serverless: bool,
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
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();
}

/// Prompt for a beam code or PIN, re-prompting on empty input.
///
fn prompt_pairing_input() -> Result<String> {
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
        if crate::auth::pin::looks_like_pin(&input)
            && crate::auth::pin::normalize_pin(&input).is_none()
        {
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
            if (pin || serverless) && !relay_url.is_empty() {
                anyhow::bail!(
                    "--relay-url is only supported by the default beam-code mode; PIN discovery does not carry custom relay configuration and serverless mode disables relays"
                );
            }
            let pairing_mode = if pin {
                let channel = if serverless {
                    PinChannel::LanOnly
                } else {
                    PinChannel::NostrAndLan
                };
                PairingMode::Pin(channel)
            } else if serverless {
                PairingMode::Serverless
            } else {
                PairingMode::BeamCode
            };
            if folder {
                iroh_sender::send_folder(&path, relay_url, pairing_mode).await?;
            } else {
                iroh_sender::send_file(&path, relay_url, pairing_mode).await?;
            }
        }

        Commands::Receive {
            output,
            no_resume,
            serverless,
        } => {
            // Validate output directory if provided
            validate_output_dir(&output)?;

            let input = prompt_pairing_input()?;

            if let Some(pin) = crate::auth::pin::normalize_pin(&input) {
                let channel = if serverless {
                    PinChannel::LanOnly
                } else {
                    PinChannel::NostrAndLan
                };
                ui::status(if serverless {
                    "Searching for the sender on the local network..."
                } else {
                    "Searching for the sender via Nostr and the local network..."
                });
                let node_id = crate::auth::rendezvous::resolve_pin(&pin, channel).await?;
                ui::status("Sender found!");
                let readiness = if serverless {
                    EndpointReadiness::LanDirect
                } else {
                    EndpointReadiness::RelayPreferred
                };
                iroh_receiver::receive_paired(
                    ::iroh::EndpointAddr::new(node_id),
                    pin,
                    readiness,
                    output,
                    no_resume,
                )
                .await?;
            } else if let Some(serverless) = crate::auth::serverless_code::decode(&input)? {
                iroh_receiver::receive_paired(
                    serverless.addr,
                    serverless.secret,
                    EndpointReadiness::LanDirect,
                    output,
                    no_resume,
                )
                .await?;
            } else {
                if serverless {
                    anyhow::bail!("--serverless requires a beam code or PIN as input");
                }
                receive_with_code(&input, output, no_resume).await?;
            }
        }
    }

    Ok(())
}

/// Receive using a beam code (auto-detects transport)
async fn receive_with_code(
    code: &str,
    output: Option<PathBuf>,
    no_resume: bool,
) -> Result<()> {
    // Validate code format
    beam::validate_code_format(code)?;

    // Parse code to determine transport
    let token = beam::parse_code(code)?;

    match token.protocol.as_str() {
        beam::PROTOCOL_IROH => {
            iroh_receiver::receive(code, output, no_resume).await?;
        }
        beam::PROTOCOL_TOR => {
            // A Tor code carries an onion address; bootstrap the Tor client and
            // connect anonymously.
            onion_receiver::receive_file_tor(code, output, no_resume).await?;
        }
        proto => {
            anyhow::bail!("Unknown protocol in beam code: {}", proto);
        }
    }

    Ok(())
}
