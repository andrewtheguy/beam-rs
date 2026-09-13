use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

use beam_rs::core::transfer::is_interrupted;
use beam_rs::ui;

mod auth;

mod iroh;
use iroh::sender::PairingMode;
use iroh::{receiver as iroh_receiver, sender as iroh_sender};

#[derive(Parser)]
#[command(name = "beam-rs")]
#[command(about = "Secure, resumable peer-to-peer file transfer")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Help heading for the mutually exclusive `send` mode flags.
const MODE_HEADING: &str = "Mode (pick at most one; default: iroh with relay fallback)";

#[derive(Subcommand)]
enum Commands {
    /// Send a file via iroh
    Send {
        /// Path to the file
        path: PathBuf,

        /// Serverless iroh mode: no third-party services, copied direct-address code
        #[arg(long, group = "mode", help_heading = MODE_HEADING)]
        serverless: bool,

        /// Serverless PIN mode: a single 120-second PIN for LAN discovery
        #[arg(long, group = "mode", help_heading = MODE_HEADING)]
        pin: bool,

        /// Custom relay server URLs, embedded in the beam code (default iroh mode only)
        #[arg(long, conflicts_with_all = ["serverless", "pin"])]
        relay_url: Vec<String>,
    },

    /// Receive a file using a beam code or PIN
    Receive {
        /// Output directory (default: current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Disable resumable transfers (don't save partial downloads)
        #[arg(long)]
        no_resume: bool,
    },
}

/// Validate path exists and is a regular file
fn validate_path(path: &Path) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("Path not found: {}", path.display());
    }
    if !path.is_file() {
        anyhow::bail!("Path is not a regular file: {}", path.display());
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
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime")
        .block_on(async_main());

    if let Err(e) = result {
        if is_interrupted(&e) {
            // Exit with 128 + SIGINT (2) = 130, standard Unix convention
            std::process::exit(130);
        }
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}

async fn async_main() -> Result<()> {
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

        // Looks like a PIN attempt (right length and character set) but its
        // checksum is invalid. Re-prompt instead of treating it as a beam code.
        if auth::pin::looks_like_pin(&input) && auth::pin::normalize_pin(&input).is_none() {
            ui::info("That looks like a PIN but its checksum is invalid — please re-check it.");
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
            pin,
            relay_url,
            serverless,
        } => {
            validate_path(&path)?;
            let pairing_mode = if serverless {
                PairingMode::Serverless
            } else if pin {
                PairingMode::Pin
            } else {
                PairingMode::BeamCode
            };
            iroh_sender::send_file(&path, relay_url, pairing_mode).await?;
        }

        Commands::Receive { output, no_resume } => {
            validate_output_dir(&output)?;

            let input = prompt_pairing_input()?;

            if let Some(pin) = auth::pin::normalize_pin(&input) {
                ui::status("Searching for the sender on the local network...");
                let node_id = auth::lan::resolve_pin(&pin).await?;
                ui::status("Sender found!");
                iroh_receiver::receive_paired(
                    ::iroh::EndpointAddr::new(node_id),
                    &pin,
                    output,
                    no_resume,
                )
                .await?;
            } else if let Some(serverless) = auth::serverless_code::decode(&input)? {
                iroh_receiver::receive_paired(serverless.addr, &serverless.secret, output, no_resume)
                    .await?;
            } else {
                iroh_receiver::receive(&input, output, no_resume).await?;
            }
        }
    }

    Ok(())
}
