use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

use beam_common::auth::PinInfo;
use beam_common::core::transfer::is_interrupted;
use beam_common::core::beam;

mod iroh;
use iroh::{receiver as iroh_receiver, sender as iroh_sender};

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

        /// Same-LAN transfer only: disable relays and the internet, discover
        /// the peer purely via mDNS. Incompatible with --pin and --relay-url.
        #[arg(long)]
        local_only: bool,
    },

    /// Receive a file or folder using a code
    Receive {
        /// Beam code from sender (will prompt if not provided)
        #[arg(short, long)]
        code: Option<String>,

        /// Output directory (default: current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Custom relay server URLs (for iroh transport)
        #[arg(long)]
        relay_url: Vec<String>,

        /// Use PIN-based code exchange for Nostr (prompts for PIN input)
        #[arg(long)]
        pin: bool,

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
    // Set up tracing subscriber with filters for noisy iroh internals
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info")
            // Suppress noisy iroh internal logs
            .add_directive("iroh=warn".parse().unwrap())
            .add_directive("iroh_net=warn".parse().unwrap())
            .add_directive("iroh_relay=warn".parse().unwrap())
            .add_directive("iroh_quinn=warn".parse().unwrap())
            .add_directive("netwatch=warn".parse().unwrap())
            .add_directive("portmapper=warn".parse().unwrap())
            .add_directive("swarm_discovery=warn".parse().unwrap())

            .add_directive("quinn=warn".parse().unwrap())
            .add_directive("quinn_proto=warn".parse().unwrap())
    });

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Send {
            path,
            folder,
            pin,
            relay_url,
            local_only,
        } => {
            validate_path(&path, folder)?;
            if local_only && pin {
                anyhow::bail!(
                    "--local-only cannot be combined with --pin: PIN exchange uses Nostr, \
                     which requires internet access."
                );
            }
            if local_only && !relay_url.is_empty() {
                anyhow::bail!(
                    "--local-only cannot be combined with --relay-url: relays are disabled \
                     in local-only mode."
                );
            }
            if folder {
                iroh_sender::send_folder(&path, relay_url, pin, local_only).await?;
            } else {
                iroh_sender::send_file(&path, relay_url, pin, local_only).await?;
            }
        }

        Commands::Receive {
            mut code,
            output,
            relay_url,
            pin,
            no_resume,
        } => {
            // Validate output directory if provided
            validate_output_dir(&output)?;

            // Handle PIN mode if requested
            let pin_info = if pin {
                let pin_str = beam_common::auth::pin::prompt_pin()?;

                eprintln!("Searching for beam token via Nostr...");

                // Fetch encrypted token from Nostr
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    beam_common::auth::nostr_pin::fetch_beam_code_via_pin(&pin_str),
                )
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Timeout: Failed to retrieve beam code from Nostr after 30 seconds"
                    )
                })??;
                eprintln!("Token found and decrypted!");
                code = Some(result.code);
                Some(PinInfo { pin: pin_str, transfer_id: result.transfer_id })
            } else {
                None
            };

            // Get code from argument or prompt
            let code = match code {
                Some(c) => c,
                None => {
                    print!("Enter beam code: ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            receive_with_code(&code, output, relay_url, no_resume, pin_info).await?;
        }
    }

    Ok(())
}

/// Receive using a beam code (auto-detects transport)
async fn receive_with_code(
    code: &str,
    output: Option<PathBuf>,
    relay_url: Vec<String>,
    no_resume: bool,
    pin_info: Option<PinInfo>,
) -> Result<()> {
    // Validate code format
    beam::validate_code_format(code)?;

    // Parse code to determine transport
    let token = beam::parse_code(code)?;

    match token.protocol.as_str() {
        beam::PROTOCOL_IROH => {
            // A local-only code carries an endpoint address with no relay URL.
            // Detect that and disable relays on the receiver to match the sender.
            let local_only = token
                .addr
                .as_ref()
                .map(|addr| addr.relay.is_none())
                .unwrap_or(false);
            iroh_receiver::receive(code, output, relay_url, no_resume, pin_info, local_only)
                .await?;
        }
        beam::PROTOCOL_TOR => {
            anyhow::bail!(
                "This beam code uses Tor transport.\n\
                 To receive via Tor, use: beam-rs-tor receive --code <CODE>"
            );
        }
        proto => {
            anyhow::bail!("Unknown protocol in beam code: {}", proto);
        }
    }

    Ok(())
}
