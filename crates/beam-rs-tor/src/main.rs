use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

use beam_common::core::transfer::is_interrupted;
use beam_common::core::beam;
use beam_common::ui;

mod onion;
use onion::{receiver as onion_receiver, sender as onion_sender};

#[derive(Parser)]
#[command(name = "beam-rs-tor")]
#[command(about = "Secure anonymous file transfer via Tor hidden services")]
#[command(version)]
struct Cli {
    /// Disable the interactive terminal UI and use plain line output.
    /// The TUI is also auto-disabled when stdout/stderr is not a terminal.
    #[arg(long, global = true)]
    no_tui: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file or folder via Tor hidden service (anonymous)
    Send {
        /// Path to file or folder
        path: PathBuf,

        /// Send a folder (creates tar archive)
        #[arg(long)]
        folder: bool,
    },

    /// Receive a file or folder using a code
    Receive {
        /// Beam code from sender (will prompt if not provided)
        #[arg(short, long)]
        code: Option<String>,

        /// Output directory (default: current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,
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
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime")
        .block_on(async_main());

    if let Err(e) = result {
        if is_interrupted(&e) {
            std::process::exit(130);
        }
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}

async fn async_main() -> Result<()> {
    let cli = Cli::parse();

    // Start the inline TUI (if applicable) and install its sink. Honors
    // --no-tui and the terminal auto-detect; returns None in plain mode (or if
    // the inline viewport can't be initialized), leaving the plain sink in place.
    let tui_handle = beam_common::tui::decide_and_install(cli.no_tui);

    // Only discard tracing once the TUI is actually active — otherwise a failed
    // TUI init would silently drop logs with no viewport to show status.
    init_tracing(tui_handle.is_some());

    let result = run(cli.command).await;

    // Always restore the terminal before propagating the result/error.
    if let Some(handle) = tui_handle {
        handle.finish();
    }

    result
}

/// Set up the tracing subscriber. When `discard` is true (TUI mode) all log
/// output is sent to a sink so it does not interfere with the inline viewport.
fn init_tracing(discard: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info")
            // Suppress noisy arti/tor internal logs
            .add_directive("arti=warn".parse().unwrap())
            .add_directive("arti_client=warn".parse().unwrap())
            .add_directive("tor_proto=warn".parse().unwrap())
            .add_directive("tor_chanmgr=warn".parse().unwrap())
            .add_directive("tor_circmgr=off".parse().unwrap())
            .add_directive("tor_guardmgr=warn".parse().unwrap())
            .add_directive("tor_netdir=warn".parse().unwrap())
            .add_directive("tor_dirmgr=warn".parse().unwrap())
            .add_directive("tor_hsservice=warn".parse().unwrap())
            .add_directive("tor_hsclient=warn".parse().unwrap())
            .add_directive("tor_rtcompat=warn".parse().unwrap())
            .add_directive("tor_persist=off".parse().unwrap())
    });

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time();

    if discard {
        builder.with_writer(std::io::sink).init();
    } else {
        builder.init();
    }
}

/// Dispatch the parsed CLI command.
async fn run(command: Commands) -> Result<()> {
    match command {
        Commands::Send { path, folder } => {
            validate_path(&path, folder)?;
            if folder {
                onion_sender::send_folder_tor(&path).await?;
            } else {
                onion_sender::send_file_tor(&path).await?;
            }
        }

        Commands::Receive { code, output } => {
            validate_output_dir(&output)?;

            let code = match code {
                Some(c) => c,
                None => ui::sink().prompt_line("Enter beam code: ", "")?.trim().to_string(),
            };

            beam::validate_code_format(&code)?;
            onion_receiver::receive_file_tor(&code, output).await?;
        }
    }

    Ok(())
}
