//! User-interface output abstraction shared across all beam-rs transports.
//!
//! Historically the transfer code wrote status, progress, and prompts directly
//! with `eprintln!`/`println!` and blocking `stdin` reads. That hard-coded a
//! plain-text CLI and made a richer UI (e.g. an inline TUI) impossible.
//!
//! This module introduces a [`UiSink`] trait that the transfer code dispatches
//! to instead. A process installs exactly one sink via [`install`]; until then
//! (and for transports that never install one), [`sink`] returns the default
//! [`PlainSink`], which reproduces the original plain-text behaviour byte for
//! byte. The `tui` feature provides an alternative sink (see [`crate::tui`]).

use anyhow::{Result, anyhow};
use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;

use crate::core::transfer::{FileExistsChoice, calc_percent, format_bytes};

/// Direction of a transfer, used to label progress in interactive UIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Outgoing transfer (we are the sender).
    Send,
    /// Incoming transfer (we are the receiver).
    Receive,
}

/// Coarse phase of a transfer. Interactive UIs use this to label the live
/// region; [`PlainSink`] ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Preparing the file/archive (checksum, tar creation).
    Preparing,
    /// Sender is waiting for a receiver to connect.
    Waiting,
    /// Establishing the peer connection.
    Connecting,
    /// Performing the optional SPAKE2/PIN handshake.
    Authenticating,
    /// Bytes are flowing.
    Transferring,
    /// Wrapping up (finalize, ACK, close).
    Finalizing,
    /// Transfer finished.
    Done,
}

/// A single progress update for the live progress indicator.
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    /// Whether we are sending or receiving.
    pub dir: Direction,
    /// Bytes transferred so far.
    pub bytes: u64,
    /// Total bytes expected.
    pub total: u64,
    /// `(current_chunk, total_chunks)` — populated by the sender, `None` for
    /// the receiver (which historically printed no chunk counter).
    pub chunk: Option<(u64, u64)>,
}

/// Sink for all user-facing output produced during a transfer.
///
/// Methods that take input ([`prompt_file_exists`](UiSink::prompt_file_exists),
/// [`confirm_large_folder`](UiSink::confirm_large_folder),
/// [`prompt_line`](UiSink::prompt_line)) are synchronous and may block; callers
/// already invoke them from `tokio::task::spawn_blocking`.
pub trait UiSink: Send + Sync {
    /// Informational status line written to stderr (was `eprintln!`).
    fn status(&self, line: &str);

    /// Informational line written to stdout (was `println!`).
    fn info(&self, line: &str);

    /// Update the live progress indicator (was the `\r` progress `eprint!`).
    fn progress(&self, p: Progress);

    /// Finish the current progress indicator (was the trailing `eprintln!()`).
    fn progress_end(&self);

    /// Display the sender's beam code.
    fn show_code(&self, code: &str);

    /// Display the sender's PIN.
    fn show_pin(&self, pin: &str);

    /// Hint the current transfer [`Phase`]. Default: ignore.
    fn set_phase(&self, _phase: Phase) {}

    /// Ask the user how to handle an existing destination file.
    fn prompt_file_exists(&self, path: &Path) -> Result<FileExistsChoice>;

    /// Confirm sending a large (non-resumable) folder archive.
    /// `size` is the archive size in bytes, `name` its filename.
    fn confirm_large_folder(&self, size: u64, name: &str) -> Result<bool>;

    /// Read a line of input from the user. `initial` pre-fills the editable
    /// buffer (empty for a fresh prompt).
    fn prompt_line(&self, prompt: &str, initial: &str) -> Result<String>;
}

/// The default plain-text sink. Reproduces the original CLI output exactly so
/// transports that never install another sink are unaffected.
pub struct PlainSink;

impl UiSink for PlainSink {
    fn status(&self, line: &str) {
        eprintln!("{}", line);
    }

    fn info(&self, line: &str) {
        println!("{}", line);
    }

    fn progress(&self, p: Progress) {
        let percent = calc_percent(p.bytes, p.total) as u32;
        match p.chunk {
            Some((chunk, total_chunks)) => {
                eprint!(
                    "\r   Progress: {}% ({}/{}) - chunk {}/{}",
                    percent,
                    format_bytes(p.bytes),
                    format_bytes(p.total),
                    chunk,
                    total_chunks
                );
            }
            None => {
                eprint!(
                    "\r   Progress: {}% ({}/{})",
                    percent,
                    format_bytes(p.bytes),
                    format_bytes(p.total)
                );
            }
        }
        let _ = std::io::stderr().flush();
    }

    fn progress_end(&self) {
        eprintln!(); // New line after progress
    }

    fn show_code(&self, code: &str) {
        println!("\n🔮 Beam code:\n{}\n", code);
    }

    fn show_pin(&self, pin: &str) {
        println!("🔢 PIN: {}\n", pin);
    }

    fn prompt_file_exists(&self, path: &Path) -> Result<FileExistsChoice> {
        let display_path = path.display().to_string();

        print!(
            "⚠️  File exists: {}\n[o]verwrite / [r]ename / [c]ancel: ",
            display_path
        );
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        let choice = input.trim().to_lowercase();
        match choice.as_str() {
            "o" | "overwrite" => Ok(FileExistsChoice::Overwrite),
            "r" | "rename" => Ok(FileExistsChoice::Rename),
            _ => Ok(FileExistsChoice::Cancel),
        }
    }

    fn confirm_large_folder(&self, size: u64, name: &str) -> Result<bool> {
        let size_str = format_bytes(size);
        println!("\n⚠️  Warning: {} is large ({}).", name, size_str);
        println!("Folder transfers are NOT resumable. If interrupted, you must start over.");
        println!(
            "Large folders are recommended for local connections only (beam-rs send --local-only)."
        );
        print!("Continue anyway? [y/N]: ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        Ok(input.trim().eq_ignore_ascii_case("y"))
    }

    fn prompt_line(&self, prompt: &str, initial: &str) -> Result<String> {
        use rustyline::DefaultEditor;

        let mut rl = DefaultEditor::new().map_err(|e| anyhow!(e.to_string()))?;
        let readline = if initial.is_empty() {
            rl.readline(prompt)
        } else {
            rl.readline_with_initial(prompt, (initial, ""))
        };

        match readline {
            Ok(line) => Ok(line),
            Err(rustyline::error::ReadlineError::Interrupted) => Err(anyhow!("Interrupted")),
            Err(rustyline::error::ReadlineError::Eof) => Err(anyhow!("EOF")),
            Err(e) => Err(anyhow!(e.to_string())),
        }
    }
}

static SINK: OnceLock<Box<dyn UiSink>> = OnceLock::new();
static PLAIN: PlainSink = PlainSink;

/// Install the process-wide UI sink. The first call wins; later calls are
/// ignored (returns `false` if a sink was already installed).
pub fn install(sink: Box<dyn UiSink>) -> bool {
    SINK.set(sink).is_ok()
}

/// Get the installed UI sink, or the default [`PlainSink`] if none was set.
pub fn sink() -> &'static dyn UiSink {
    match SINK.get() {
        Some(s) => s.as_ref(),
        None => &PLAIN,
    }
}
