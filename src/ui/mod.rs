//! User-facing terminal output and prompts shared by all transports.

use anyhow::{Result, anyhow};
use rustyline::DefaultEditor;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use crate::core::transfer::{FileExistsChoice, calc_percent, format_bytes};

static EDITOR: Mutex<Option<DefaultEditor>> = Mutex::new(None);

/// Write a status line to stderr.
pub fn status(line: &str) {
    eprintln!("{}", line);
}

/// Replace a short-lived status message on the current terminal line.
pub fn transient_status(line: &str) {
    eprint!("\r{line:<40}\r");
    let _ = std::io::stderr().flush();
}

/// Write an informational line to stdout.
pub fn info(line: &str) {
    println!("{}", line);
}

/// Update the in-place transfer progress indicator.
pub fn progress(bytes: u64, total: u64, chunk: Option<(u64, u64)>) {
    let percent = calc_percent(bytes, total) as u32;
    match chunk {
        Some((chunk, total_chunks)) => {
            eprint!(
                "\r   Progress: {}% ({}/{}) - chunk {}/{}",
                percent,
                format_bytes(bytes),
                format_bytes(total),
                chunk,
                total_chunks
            );
        }
        None => {
            eprint!(
                "\r   Progress: {}% ({}/{})",
                percent,
                format_bytes(bytes),
                format_bytes(total)
            );
        }
    }
    let _ = std::io::stderr().flush();
}

/// Finish the current in-place progress indicator.
pub fn progress_end() {
    eprintln!();
}

/// Display the sender's beam code.
pub fn show_code(code: &str) {
    println!("\n🔮 Beam code:\n{}\n", code);
}

/// Display the sender's PIN.
pub fn show_pin(pin: &str) {
    println!("🔢 PIN: {}\n", pin);
}

/// Ask how to handle an existing destination file.
pub fn prompt_file_exists(path: &Path) -> Result<FileExistsChoice> {
    print!(
        "⚠️  File exists: {}\n[o]verwrite / [r]ename / [c]ancel: ",
        path.display()
    );
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    match input.trim().to_lowercase().as_str() {
        "o" | "overwrite" => Ok(FileExistsChoice::Overwrite),
        "r" | "rename" => Ok(FileExistsChoice::Rename),
        _ => Ok(FileExistsChoice::Cancel),
    }
}

/// Confirm sending a large, non-resumable folder archive.
pub fn confirm_large_folder(size: u64, name: &str) -> Result<bool> {
    println!(
        "\n⚠️  Warning: {} is large ({}).",
        name,
        format_bytes(size)
    );
    println!("Folder transfers are NOT resumable. If interrupted, you must start over.");
    print!("Continue anyway? [y/N]: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

/// Read a line, optionally pre-filling the editable input buffer.
pub fn prompt_line(prompt: &str, initial: &str) -> Result<String> {
    let mut editor = EDITOR
        .lock()
        .map_err(|e| anyhow!("Failed to lock line editor: {e}"))?;
    if editor.is_none() {
        *editor = Some(DefaultEditor::new().map_err(|e| anyhow!(e.to_string()))?);
    }
    let rl = editor.as_mut().expect("line editor was initialized");

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
