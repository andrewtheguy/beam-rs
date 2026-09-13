use anyhow::{Context, Result};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::core::crypto::{CHUNK_SIZE, decrypt, encrypt};
use crate::core::resume::{
    ResumeMetadata, calculate_file_checksum, check_resume, create_resume_file,
    finalize_resume_file, get_data_offset, temp_file_path, update_resume_metadata,
};
use crate::ui;

/// Error returned when a transfer is interrupted by Ctrl+C.
///
/// This error should be handled at the CLI level by exiting with code 130
/// (standard Unix convention for SIGINT).
#[derive(Debug, Clone, Copy)]
pub struct Interrupted;

impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Transfer interrupted")
    }
}

impl std::error::Error for Interrupted {}

/// Check if an error is an Interrupted error.
pub fn is_interrupted(err: &anyhow::Error) -> bool {
    err.downcast_ref::<Interrupted>().is_some()
}

/// Check if a filename contains invalid characters.
///
/// Returns `true` if the name contains:
/// - Path traversal patterns (starts with "..")
/// - Path separators (`/` or `\`)
/// - Null bytes
pub fn is_invalid_filename(name: &str) -> bool {
    name.starts_with("..") || name.contains('/') || name.contains('\\') || name.contains('\0')
}

/// Transfer protocol header
/// Format: filename_len (2 bytes) || filename || file_size (8 bytes) || checksum (8 bytes)
pub struct FileHeader {
    pub filename: String,
    pub file_size: u64,
    /// xxhash64 checksum of the file, used to validate resume state
    pub checksum: u64,
}

impl FileHeader {
    pub fn new(filename: String, file_size: u64, checksum: u64) -> Self {
        Self {
            filename,
            file_size,
            checksum,
        }
    }

    /// Serialize header for transmission.
    ///
    /// Returns an error if the filename exceeds the protocol limit (65535 bytes).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let filename_bytes = self.filename.as_bytes();
        if filename_bytes.len() > u16::MAX as usize {
            anyhow::bail!(
                "Filename too long for protocol: {} bytes (max {} bytes)",
                filename_bytes.len(),
                u16::MAX
            );
        }
        let mut bytes = Vec::with_capacity(2 + filename_bytes.len() + 8 + 8);

        bytes.extend_from_slice(&(filename_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(filename_bytes);
        bytes.extend_from_slice(&self.file_size.to_be_bytes());
        bytes.extend_from_slice(&self.checksum.to_be_bytes());

        Ok(bytes)
    }

    /// Deserialize header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            anyhow::bail!("Header data too short");
        }

        let filename_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        // Need: 2 (filename_len) + filename + 8 (file_size) + 8 (checksum)
        if data.len() < 2 + filename_len + 16 {
            anyhow::bail!("Header data truncated");
        }

        let filename = String::from_utf8(data[2..2 + filename_len].to_vec())
            .context("Invalid filename encoding")?;

        // Validate filename doesn't contain path traversal or invalid characters
        if is_invalid_filename(&filename) {
            anyhow::bail!("Invalid filename: contains path traversal or invalid characters");
        }
        if filename.is_empty() {
            anyhow::bail!("Invalid filename: empty");
        }

        let size_start = 2 + filename_len;
        let file_size = u64::from_be_bytes(data[size_start..size_start + 8].try_into().unwrap());

        let checksum_start = size_start + 8;
        let checksum =
            u64::from_be_bytes(data[checksum_start..checksum_start + 8].try_into().unwrap());

        Ok(Self {
            filename,
            file_size,
            checksum,
        })
    }
}

/// Write one encrypted, length-prefixed message.
/// Format: len (4 bytes BE) || nonce || ciphertext || tag
async fn send_encrypted<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<()> {
    let encrypted = encrypt(key, plaintext)?;
    writer
        .write_all(&(encrypted.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&encrypted).await?;
    Ok(())
}

/// Read and decrypt one length-prefixed message, rejecting lengths above `max_len`
/// before allocating (prevents OOM from malicious peers).
async fn recv_encrypted<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    key: &[u8; 32],
    max_len: usize,
    what: &str,
) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .with_context(|| format!("Failed to read {what} length"))?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len == 0 {
        anyhow::bail!("Invalid {what}: length is zero");
    }
    if len > max_len {
        anyhow::bail!("{what} size {len} exceeds maximum {max_len} bytes");
    }

    let mut encrypted = vec![0u8; len];
    reader
        .read_exact(&mut encrypted)
        .await
        .with_context(|| format!("Failed to read {what} data"))?;

    decrypt(key, &encrypted)
}

// Maximum header size (64KB - headers contain filename + metadata, this is generous)
const MAX_HEADER_SIZE: usize = 64 * 1024;

// Maximum chunk size (CHUNK_SIZE + reasonable overhead for encryption tags/nonce)
const MAX_CHUNK_SIZE: usize = CHUNK_SIZE + 256;

/// Maximum size for encrypted control signals.
/// Control signals are small (e.g., "ACK", "PROCEED", "RESUME:"+8 bytes) plus encryption overhead
const MAX_CONTROL_SIGNAL_SIZE: usize = 1024;

/// Send an encrypted header over the stream
pub async fn send_encrypted_header<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    key: &[u8; 32],
    header: &FileHeader,
) -> Result<()> {
    let header_bytes = header.to_bytes().context("Failed to serialize header")?;
    send_encrypted(writer, key, &header_bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Receive and decrypt a header from the stream
pub async fn recv_encrypted_header<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    key: &[u8; 32],
) -> Result<FileHeader> {
    let data = recv_encrypted(reader, key, MAX_HEADER_SIZE, "header").await?;
    FileHeader::from_bytes(&data)
}

/// Send an encrypted chunk over the stream
pub async fn send_encrypted_chunk<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    key: &[u8; 32],
    data: &[u8],
) -> Result<()> {
    send_encrypted(writer, key, data).await
}

/// Receive and decrypt a chunk from the stream
pub async fn recv_encrypted_chunk<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    key: &[u8; 32],
) -> Result<Vec<u8>> {
    recv_encrypted(reader, key, MAX_CHUNK_SIZE, "chunk").await
}

/// Calculate number of chunks for a file
pub fn num_chunks(file_size: u64) -> u64 {
    file_size.div_ceil(CHUNK_SIZE as u64)
}

/// Format bytes for human-readable display
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Calculate percentage safely, avoiding division by zero
/// Returns 0.0 if total is 0, otherwise returns (current / total) * 100.0
pub fn calc_percent(current: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        current as f64 / total as f64 * 100.0
    }
}

/// Format a resume progress message for logging
/// Used by both senders and receivers when resuming a transfer
pub fn format_resume_progress(offset: u64, file_size: u64) -> String {
    format!(
        "Resuming from {} ({:.1}%)...",
        format_bytes(offset),
        calc_percent(offset, file_size)
    )
}

/// Result of preparing a file for transfer
pub struct PreparedFile {
    pub file: File,
    pub header: FileHeader,
}

/// Prepare a file for sending: read metadata, calculate checksum, and open.
pub async fn prepare_file_for_send(file_path: &Path) -> Result<PreparedFile> {
    let metadata = tokio::fs::metadata(file_path)
        .await
        .context("Failed to read file metadata")?;
    let file_size = metadata.len();
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid filename")?
        .to_string();

    ui::info(&format!(
        "📁 Preparing to send: {} ({})",
        filename,
        format_bytes(file_size)
    ));

    // Calculate checksum for resumable transfers
    ui::info("   Calculating checksum...");
    let checksum = calculate_file_checksum(file_path)
        .await
        .context("Failed to calculate file checksum")?;

    let file = File::open(file_path).await.context("Failed to open file")?;

    Ok(PreparedFile {
        file,
        header: FileHeader::new(filename, file_size, checksum),
    })
}

// ============================================================================
// Control signals (confirmation, resume, acknowledgment)
// ============================================================================

/// Control signal types for encrypted handshake
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlSignal {
    Proceed,
    Abort,
    Ack,
    /// Resume transfer from byte offset
    Resume(u64),
}

/// Send an encrypted control signal.
/// RESUME is encoded as "RESUME:" || offset (8 bytes BE).
pub async fn send_control<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    key: &[u8; 32],
    signal: &ControlSignal,
) -> Result<()> {
    let payload = match signal {
        ControlSignal::Proceed => b"PROCEED".to_vec(),
        ControlSignal::Abort => b"ABORT".to_vec(),
        ControlSignal::Ack => b"ACK".to_vec(),
        ControlSignal::Resume(offset) => [b"RESUME:".as_slice(), &offset.to_be_bytes()].concat(),
    };
    send_encrypted(writer, key, &payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Receive and decrypt a control signal
pub async fn recv_control<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    key: &[u8; 32],
) -> Result<ControlSignal> {
    let data = recv_encrypted(reader, key, MAX_CONTROL_SIGNAL_SIZE, "control signal")
        .await
        .context("Failed to receive control signal")?;

    match data.as_slice() {
        b"PROCEED" => Ok(ControlSignal::Proceed),
        b"ABORT" => Ok(ControlSignal::Abort),
        b"ACK" => Ok(ControlSignal::Ack),
        _ if data.starts_with(b"RESUME:") && data.len() == 15 => {
            let offset_bytes: [u8; 8] = data[7..15].try_into().unwrap();
            Ok(ControlSignal::Resume(u64::from_be_bytes(offset_bytes)))
        }
        _ => anyhow::bail!("Unknown control signal"),
    }
}

/// User's choice when file already exists
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileExistsChoice {
    Overwrite,
    Rename,
    Cancel,
}

/// Find next available filename by appending _2, _3, etc.
/// Example: file.txt -> file_2.txt -> file_3.txt
pub fn find_available_filename(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }

    let stem = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let parent = path.parent().unwrap_or(Path::new("."));

    for i in 2..=999 {
        let new_name = format!("{}_{}{}", stem, i, ext);
        let new_path = parent.join(&new_name);
        if !new_path.exists() {
            return new_path;
        }
    }

    // Fallback with timestamp if somehow 999 files exist
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("System clock is set before Unix epoch")
        .as_secs();
    parent.join(format!("{}_{}{}", stem, timestamp, ext))
}

// ============================================================================
// Data transfer with resume support
// ============================================================================

/// Send file data starting from given offset.
/// Handles chunk encryption, progress reporting.
pub async fn send_file_data<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    file: &mut R,
    writer: &mut W,
    key: &[u8; 32],
    file_size: u64,
    start_offset: u64,
    progress_interval: u64,
) -> Result<()> {
    let total_chunks = num_chunks(file_size);
    let mut bytes_sent = start_offset;
    let mut chunk_num = start_offset / CHUNK_SIZE as u64 + 1;
    let mut buffer = vec![0u8; CHUNK_SIZE];

    while bytes_sent < file_size {
        let to_read = std::cmp::min(CHUNK_SIZE, (file_size - bytes_sent) as usize);
        file.read_exact(&mut buffer[..to_read]).await?;

        send_encrypted_chunk(writer, key, &buffer[..to_read]).await?;

        bytes_sent += to_read as u64;
        chunk_num += 1;

        if progress_interval > 0
            && (chunk_num.is_multiple_of(progress_interval) || bytes_sent == file_size)
        {
            ui::progress(
                bytes_sent,
                file_size,
                Some((chunk_num - 1, total_chunks)),
            );
        }
    }

    if progress_interval > 0 {
        ui::progress_end();
    }

    Ok(())
}

/// State for resumable file reception
pub struct FileReceiver {
    /// The temp file being written to
    pub temp_file: std::fs::File,
    /// Path to the temp file
    pub temp_path: PathBuf,
    /// Bytes of file data already received
    pub bytes_received: u64,
    /// Offset in temp file where file data starts (after metadata header)
    pub data_offset: u64,
    /// Metadata for updating progress
    pub metadata: ResumeMetadata,
}

/// Check for resumable transfer and prepare file receiver.
/// Returns (FileReceiver, control_signal_to_send).
pub fn prepare_file_receiver(
    final_path: &Path,
    header: &FileHeader,
    no_resume: bool,
) -> Result<(FileReceiver, ControlSignal)> {
    let temp_path = temp_file_path(final_path);

    if !no_resume
        && let Some(resume_check) = check_resume(&temp_path, header.checksum, header.file_size)?
    {
        let bytes_received = resume_check.metadata.bytes_received;
        ui::status(&format!(
            "   Found partial download: {} of {} received",
            format_bytes(bytes_received),
            format_bytes(header.file_size)
        ));

        return Ok((
            FileReceiver {
                temp_file: resume_check.file,
                temp_path,
                bytes_received,
                data_offset: resume_check.data_offset,
                metadata: resume_check.metadata,
            },
            ControlSignal::Resume(bytes_received),
        ));
    }

    let metadata = ResumeMetadata {
        checksum: header.checksum,
        file_size: header.file_size,
        bytes_received: 0,
        filename: header.filename.clone(),
    };
    let temp_file = create_resume_file(&temp_path, &metadata)?;

    Ok((
        FileReceiver {
            temp_file,
            temp_path,
            bytes_received: 0,
            data_offset: get_data_offset(),
            metadata,
        },
        ControlSignal::Proceed,
    ))
}

/// Receive file data and write to temp file.
/// Handles chunk decryption, progress reporting, and metadata updates.
pub async fn receive_file_data<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    receiver: &mut FileReceiver,
    key: &[u8; 32],
    file_size: u64,
    progress_interval: u64,
    metadata_update_interval: u64,
) -> Result<()> {
    let mut chunk_num = receiver.bytes_received / CHUNK_SIZE as u64 + 1;

    // Seek to end of data in temp file (for appending)
    receiver.temp_file.seek(SeekFrom::Start(
        receiver.data_offset + receiver.bytes_received,
    ))?;

    while receiver.bytes_received < file_size {
        let chunk = recv_encrypted_chunk(reader, key)
            .await
            .context("Failed to receive chunk")?;

        receiver
            .temp_file
            .write_all(&chunk)
            .context("Failed to write to temp file")?;

        receiver.bytes_received += chunk.len() as u64;
        chunk_num += 1;

        // Update metadata periodically for crash recovery.
        // `update_resume_metadata` writes the header at offset 0 without moving the
        // write cursor (pwrite on Unix; save/restore elsewhere), so no seek is needed
        // around it — the cursor stays at the data tail for the next append.
        if metadata_update_interval > 0 && chunk_num.is_multiple_of(metadata_update_interval) {
            receiver.metadata.bytes_received = receiver.bytes_received;
            update_resume_metadata(&mut receiver.temp_file, &receiver.metadata)?;
        }

        if progress_interval > 0
            && (chunk_num.is_multiple_of(progress_interval) || receiver.bytes_received == file_size)
        {
            ui::progress(receiver.bytes_received, file_size, None);
        }
    }

    if progress_interval > 0 {
        ui::progress_end();
    }

    receiver.metadata.bytes_received = receiver.bytes_received;
    update_resume_metadata(&mut receiver.temp_file, &receiver.metadata)?;
    receiver.temp_file.flush()?;

    Ok(())
}

/// Set up a Ctrl+C handler for the receiver's temp file.
///
/// Resumable transfers keep the partial file on interrupt; with resume disabled it
/// is removed. The returned receiver completes once the interrupt has been handled.
fn setup_interrupt_handler(
    temp_path: PathBuf,
    is_resumable: bool,
) -> tokio::sync::oneshot::Receiver<()> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if is_resumable {
                ui::status("\nInterrupted. Partial download saved for resume.");
            } else {
                let _ = tokio::fs::remove_file(&temp_path).await;
                ui::status("\nInterrupted. Cleaned up temp file.");
            }
            let _ = shutdown_tx.send(());
        }
    });

    shutdown_rx
}

// ============================================================================
// Transfer orchestration
// ============================================================================

/// Result of a sender transfer operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferResult {
    /// Transfer completed successfully
    Success,
    /// Transfer was aborted by receiver
    Aborted,
}

/// Sender transfer logic.
///
/// 1. Send encrypted header
/// 2. Wait for receiver response (PROCEED/RESUME/ABORT)
/// 3. Seek file if resuming
/// 4. Send file data
/// 5. Wait for ACK
pub async fn run_sender_transfer<S, F>(
    file: &mut F,
    stream: &mut S,
    key: &[u8; 32],
    header: &FileHeader,
) -> Result<TransferResult>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
    F: AsyncReadExt + AsyncSeekExt + Unpin,
{
    send_encrypted_header(stream, key, header)
        .await
        .context("Failed to send header")?;

    ui::status("Waiting for receiver to confirm...");
    let start_offset = match recv_control(stream, key).await? {
        ControlSignal::Proceed => {
            ui::status("Receiver ready, starting transfer...");
            0
        }
        ControlSignal::Resume(offset) => {
            if offset > header.file_size {
                anyhow::bail!(
                    "Receiver requested resume offset {} beyond file size {}",
                    offset,
                    header.file_size
                );
            }
            ui::status(&format_resume_progress(offset, header.file_size));
            file.seek(SeekFrom::Start(offset)).await?;
            offset
        }
        ControlSignal::Abort => {
            ui::status("Receiver declined transfer");
            return Ok(TransferResult::Aborted);
        }
        other => anyhow::bail!("Unexpected control signal: {:?}", other),
    };

    send_file_data(file, stream, key, header.file_size, start_offset, 10).await?;

    stream.flush().await.context("Failed to flush stream")?;

    ui::status("\nTransfer complete!");
    ui::status("Waiting for receiver to confirm...");

    match recv_control(stream, key).await {
        Ok(ControlSignal::Ack) => {
            ui::status("Receiver confirmed!");
            Ok(TransferResult::Success)
        }
        Ok(other) => anyhow::bail!("Expected ACK, got {:?}", other),
        Err(e) => Err(e).context("Failed to receive ACK"),
    }
}

/// Receiver transfer logic.
///
/// 1. Receive encrypted header
/// 2. Handle file existence check
/// 3. Prepare receiver (resume check) and send control signal
/// 4. Receive file data
/// 5. Finalize and send ACK
///
/// Returns the path of the received file.
pub async fn run_receiver_transfer<S>(
    stream: &mut S,
    key: &[u8; 32],
    output_dir: Option<PathBuf>,
    no_resume: bool,
) -> Result<PathBuf>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let header = recv_encrypted_header(stream, key)
        .await
        .context("Failed to read header")?;

    ui::status(&format!(
        "Receiving: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    ));

    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let output_path = output_dir.join(&header.filename);

    let final_path = if output_path.exists() {
        let path_clone = output_path.clone();
        let choice = tokio::task::spawn_blocking(move || ui::prompt_file_exists(&path_clone))
            .await
            .context("Prompt task panicked")??;

        match choice {
            FileExistsChoice::Overwrite => {
                // Handle TOCTOU race: file may have been removed between check and now
                match tokio::fs::remove_file(&output_path).await {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(e).context("Failed to remove existing file");
                    }
                }
                output_path
            }
            FileExistsChoice::Rename => {
                let new_path = find_available_filename(&output_path);
                ui::status(&format!("Will save as: {}", new_path.display()));
                new_path
            }
            FileExistsChoice::Cancel => {
                send_control(stream, key, &ControlSignal::Abort)
                    .await
                    .context("Failed to send abort signal")?;
                anyhow::bail!("Transfer cancelled by user");
            }
        }
    } else {
        output_path
    };

    let (mut receiver, control_signal) =
        prepare_file_receiver(&final_path, &header, no_resume)?;

    let shutdown_rx = setup_interrupt_handler(receiver.temp_path.clone(), !no_resume);

    send_control(stream, key, &control_signal)
        .await
        .context("Failed to send control signal")?;
    match control_signal {
        ControlSignal::Resume(offset) => {
            ui::status(&format_resume_progress(offset, header.file_size))
        }
        _ => ui::status("Ready to receive data..."),
    }

    tokio::select! {
        result = receive_file_data(stream, &mut receiver, key, header.file_size, 10, 100) => {
            result?;
        }
        _ = shutdown_rx => {
            return Err(Interrupted.into());
        }
    }

    finalize_resume_file(
        receiver.temp_file,
        &receiver.temp_path,
        &final_path,
        receiver.data_offset,
    )?;

    ui::status("\nFile received successfully!");
    ui::status(&format!("Saved to: {}", final_path.display()));

    send_control(stream, key, &ControlSignal::Ack)
        .await
        .context("Failed to send acknowledgment")?;

    Ok(final_path)
}
