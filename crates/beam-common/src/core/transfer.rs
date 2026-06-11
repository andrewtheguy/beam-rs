use anyhow::{Context, Result};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::core::crypto::{CHUNK_SIZE, decrypt, encrypt};
use crate::core::folder::{create_tar_archive, print_tar_creation_info};
use crate::core::resume::calculate_file_checksum;
use crate::ui::{self, Direction, Progress};

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

/// Check if a path contains traversal patterns.
///
/// Returns `true` if the path contains dangerous patterns like:
/// - Starts with ".." (e.g., "../etc/passwd")
/// - Contains "/.." (e.g., "foo/../bar")
/// - Contains "\\.." (Windows path traversal)
///
/// Allows legitimate names like "file..txt" or "archive..tar.gz".
/// Use this for paths that may legitimately contain separators (e.g., tar entries).
pub fn contains_path_traversal(path: &str) -> bool {
    path.starts_with("..") || path.contains("/..") || path.contains("\\..")
}

/// Check if a filename contains invalid characters.
///
/// Returns `true` if the name contains:
/// - Path traversal patterns (starts with "..")
/// - Path separators (`/` or `\`)
/// - Null bytes
///
/// Use this for single-component names (filenames, folder names).
pub fn is_invalid_filename(name: &str) -> bool {
    name.starts_with("..") || name.contains('/') || name.contains('\\') || name.contains('\0')
}

/// Soft limit for large file transfers (100MB)
pub const LARGE_FILE_THRESHOLD: u64 = 100 * 1024 * 1024;

/// Transfer type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferType {
    File = 0,
    Folder = 1, // Tar archive
}

impl TransferType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(TransferType::File),
            1 => Ok(TransferType::Folder),
            _ => anyhow::bail!("Unknown transfer type: {}", value),
        }
    }
}

/// Transfer protocol header
/// Format: transfer_type (1 byte) || filename_len (2 bytes) || filename || file_size (8 bytes) || checksum (8 bytes)
pub struct FileHeader {
    pub transfer_type: TransferType,
    pub filename: String,
    pub file_size: u64,
    /// xxhash64 checksum of the file (0 for folders)
    pub checksum: u64,
}

impl FileHeader {
    pub fn new(
        transfer_type: TransferType,
        filename: String,
        file_size: u64,
        checksum: u64,
    ) -> Self {
        Self {
            transfer_type,
            filename,
            file_size,
            checksum,
        }
    }

    /// Serialize header for transmission
    /// Format: transfer_type (1 byte) || filename_len (2 bytes) || filename || file_size (8 bytes) || checksum (8 bytes)
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
        let mut bytes = Vec::with_capacity(1 + 2 + filename_bytes.len() + 8 + 8);

        bytes.push(self.transfer_type as u8);
        bytes.extend_from_slice(&(filename_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(filename_bytes);
        bytes.extend_from_slice(&self.file_size.to_be_bytes());
        bytes.extend_from_slice(&self.checksum.to_be_bytes());

        Ok(bytes)
    }

    /// Deserialize header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 3 {
            anyhow::bail!("Header data too short");
        }

        let transfer_type = TransferType::from_u8(data[0])?;
        let filename_len = u16::from_be_bytes([data[1], data[2]]) as usize;
        // Need: 1 (type) + 2 (filename_len) + filename + 8 (file_size) + 8 (checksum)
        if data.len() < 3 + filename_len + 16 {
            anyhow::bail!("Header data truncated");
        }

        let filename = String::from_utf8(data[3..3 + filename_len].to_vec())
            .context("Invalid filename encoding")?;

        // Validate filename doesn't contain path traversal or invalid characters
        if is_invalid_filename(&filename) {
            anyhow::bail!("Invalid filename: contains path traversal or invalid characters");
        }
        if filename.is_empty() {
            anyhow::bail!("Invalid filename: empty");
        }

        let size_start = 3 + filename_len;
        let file_size = u64::from_be_bytes(data[size_start..size_start + 8].try_into().unwrap());

        let checksum_start = size_start + 8;
        let checksum =
            u64::from_be_bytes(data[checksum_start..checksum_start + 8].try_into().unwrap());

        Ok(Self {
            transfer_type,
            filename,
            file_size,
            checksum,
        })
    }
}

/// Send a header over the stream (unencrypted, relies on QUIC/TLS)
/// Format: header_len (4 bytes) || header_data
pub async fn send_header<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    header: &FileHeader,
) -> Result<()> {
    let header_bytes = header.to_bytes().context("Failed to serialize header")?;

    // Write length prefix
    let len = header_bytes.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;

    // Write header
    writer.write_all(&header_bytes).await?;

    Ok(())
}

/// Send an encrypted header over the stream (uses chunk_num 0)
/// Format: header_len (4 bytes) || encrypted_header
pub async fn send_encrypted_header<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    key: &[u8; 32],
    header: &FileHeader,
) -> Result<()> {
    let header_bytes = header.to_bytes().context("Failed to serialize header")?;
    let encrypted = encrypt(key, &header_bytes)?;

    // Write length prefix
    let len = encrypted.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;

    // Write encrypted header
    writer.write_all(&encrypted).await?;

    // Flush to ensure header is sent immediately (required for Tor streams)
    writer.flush().await?;

    Ok(())
}

// Maximum header size (64KB - headers contain filename + metadata, this is generous)
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Receive a header from the stream (unencrypted, relies on QUIC/TLS)
pub async fn recv_header<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<FileHeader> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read header length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Validate header size to prevent huge allocations from malicious peers
    if len == 0 {
        anyhow::bail!("Invalid header: length is zero");
    }
    if len > MAX_HEADER_SIZE {
        anyhow::bail!(
            "Header size {} exceeds maximum {} bytes",
            len,
            MAX_HEADER_SIZE
        );
    }

    // Read header
    let mut data = vec![0u8; len];
    reader
        .read_exact(&mut data)
        .await
        .context("Failed to read header data")?;

    FileHeader::from_bytes(&data)
}

/// Receive and decrypt a header from the stream (uses chunk_num 0)
pub async fn recv_encrypted_header<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    key: &[u8; 32],
) -> Result<FileHeader> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read header length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Validate header size to prevent huge allocations from malicious peers
    if len == 0 {
        anyhow::bail!("Invalid header: length is zero");
    }
    if len > MAX_HEADER_SIZE {
        anyhow::bail!(
            "Header size {} exceeds maximum {} bytes",
            len,
            MAX_HEADER_SIZE
        );
    }

    // Read encrypted header
    let mut encrypted = vec![0u8; len];
    reader
        .read_exact(&mut encrypted)
        .await
        .context("Failed to read header data")?;

    // Decrypt
    let decrypted = decrypt(key, &encrypted)?;

    FileHeader::from_bytes(&decrypted)
}

/// Send a chunk over the stream (unencrypted, relies on QUIC/TLS)
/// Format: chunk_len (4 bytes) || chunk_data
pub async fn send_chunk<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    // Write length prefix
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;

    // Write data
    writer.write_all(data).await?;

    Ok(())
}

/// Send an encrypted chunk over the stream
/// Format: chunk_len (4 bytes) || encrypted_chunk
pub async fn send_encrypted_chunk<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    key: &[u8; 32],
    data: &[u8],
) -> Result<()> {
    let encrypted = encrypt(key, data)?;

    // Write length prefix
    let len = encrypted.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;

    // Write encrypted data
    writer.write_all(&encrypted).await?;

    Ok(())
}

// Maximum chunk size (CHUNK_SIZE + reasonable overhead for encryption tags/nonce)
const MAX_CHUNK_SIZE: usize = CHUNK_SIZE + 256;

/// Receive a chunk from the stream (unencrypted, relies on QUIC/TLS)
pub async fn recv_chunk<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read chunk length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_CHUNK_SIZE {
        anyhow::bail!("Chunk size {} exceeds maximum {}", len, MAX_CHUNK_SIZE);
    }

    // Read data
    let mut data = vec![0u8; len];
    reader
        .read_exact(&mut data)
        .await
        .context("Failed to read chunk data")?;

    Ok(data)
}

/// Receive and decrypt a chunk from the stream
pub async fn recv_encrypted_chunk<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    key: &[u8; 32],
) -> Result<Vec<u8>> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read chunk length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Validate chunk size to prevent OOM from malicious length prefix
    if len > MAX_CHUNK_SIZE {
        anyhow::bail!(
            "Encrypted chunk size {} exceeds maximum {}",
            len,
            MAX_CHUNK_SIZE
        );
    }

    // Read encrypted data
    let mut encrypted = vec![0u8; len];
    reader
        .read_exact(&mut encrypted)
        .await
        .context("Failed to read chunk data")?;

    // Decrypt
    decrypt(key, &encrypted)
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

/// Prompt user for confirmation if folder archive exceeds soft limit.
/// Only used for folders since they are NOT resumable. Files are resumable and don't need this warning.
/// Returns Ok(true) to proceed, Ok(false) to cancel.
///
/// This function is async and runs blocking I/O in a separate thread to avoid
/// blocking the Tokio runtime.
pub async fn confirm_large_folder_transfer(file_size: u64, filename: &str) -> Result<bool> {
    if file_size <= LARGE_FILE_THRESHOLD {
        return Ok(true);
    }

    // Capture values needed in the blocking closure
    let filename = filename.to_string();

    tokio::task::spawn_blocking(move || ui::sink().confirm_large_folder(file_size, &filename))
        .await
        .context("Blocking task panicked")?
}

/// Result of preparing a file for transfer
pub struct PreparedFile {
    pub file: File,
    pub filename: String,
    pub file_size: u64,
    /// xxhash64 checksum of the file
    pub checksum: u64,
}

/// Prepare a file for sending: validate, calculate checksum, confirm if large, and open.
/// Returns None if user cancels the transfer.
pub async fn prepare_file_for_send(file_path: &Path) -> Result<Option<PreparedFile>> {
    let metadata = tokio::fs::metadata(file_path)
        .await
        .context("Failed to read file metadata")?;
    let file_size = metadata.len();
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid filename")?
        .to_string();

    ui::sink().info(&format!(
        "📁 Preparing to send: {} ({})",
        filename,
        format_bytes(file_size)
    ));

    // Calculate checksum for resumable transfers
    ui::sink().info("   Calculating checksum...");
    let checksum = calculate_file_checksum(file_path)
        .await
        .context("Failed to calculate file checksum")?;

    // No large file warning needed - file transfers are resumable

    // Open file
    let file = File::open(file_path).await.context("Failed to open file")?;

    Ok(Some(PreparedFile {
        file,
        filename,
        file_size,
        checksum,
    }))
}

/// Result of preparing a folder archive for transfer
pub struct PreparedFolder {
    pub file: File,
    pub filename: String,
    pub file_size: u64,
    /// Keep temp file alive to prevent deletion until transfer completes
    pub temp_file: NamedTempFile,
    /// Checksum (always 0 for folders, as they are not resumable)
    pub checksum: u64,
}

/// Prepare a folder for sending: validate, create tar archive, confirm if large, and open.
/// Returns None if user cancels the transfer.
pub async fn prepare_folder_for_send(folder_path: &Path) -> Result<Option<PreparedFolder>> {
    // Validate folder
    if !folder_path.is_dir() {
        anyhow::bail!("Not a directory: {}", folder_path.display());
    }

    let folder_name = folder_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid folder name")?;

    // Validate folder name - must not contain path separators or traversal patterns
    if is_invalid_filename(folder_name) {
        anyhow::bail!("Invalid folder name: contains path traversal or invalid characters");
    }
    if folder_name.is_empty() {
        anyhow::bail!("Invalid folder name: empty");
    }

    ui::sink().info(&format!("📁 Creating tar archive of: {}", folder_name));
    print_tar_creation_info();

    // Create tar archive
    let tar_archive = create_tar_archive(folder_path)?;
    let filename = tar_archive.filename;
    let file_size = tar_archive.file_size;

    ui::sink().info(&format!(
        "📦 Archive created: {} ({})",
        filename,
        format_bytes(file_size)
    ));

    // Confirm if archive is large (folders are NOT resumable)
    if !confirm_large_folder_transfer(file_size, &filename).await? {
        ui::sink().info("Transfer cancelled.");
        return Ok(None);
    }

    // Open tar file
    let file = File::open(tar_archive.temp_file.path())
        .await
        .context("Failed to open tar file")?;

    Ok(Some(PreparedFolder {
        file,
        filename,
        file_size,
        temp_file: tar_archive.temp_file,
        checksum: 0, // Folders are not resumable
    }))
}

// ============================================================================
// Generic sender wrappers (reduce code duplication across transport modes)
// ============================================================================

/// Generic file sender that accepts a closure for mode-specific transfer logic.
///
/// This function handles file preparation (validation, size check, confirmation)
/// and delegates the actual transfer to the provided closure.
///
/// # Arguments
/// * `file_path` - Path to the file to send
/// * `transfer_fn` - Closure that performs the mode-specific transfer.
///   Receives: (file, filename, file_size, checksum, transfer_type)
///
/// # Returns
/// * `Ok(())` if transfer completes or user cancels
/// * `Err` if preparation or transfer fails
pub async fn send_file_with<F, Fut>(file_path: &Path, transfer_fn: F) -> Result<()>
where
    F: FnOnce(File, String, u64, u64, TransferType) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let prepared = match prepare_file_for_send(file_path).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    transfer_fn(
        prepared.file,
        prepared.filename,
        prepared.file_size,
        prepared.checksum,
        TransferType::File,
    )
    .await
}

/// Generic folder sender that accepts a closure for mode-specific transfer logic.
///
/// This function handles folder preparation (tar archive creation, size check,
/// confirmation) and interrupt handling with temp file cleanup.
///
/// # Arguments
/// * `folder_path` - Path to the folder to send
/// * `transfer_fn` - Closure that performs the mode-specific transfer.
///   Receives: (file, filename, file_size, checksum, transfer_type)
///
/// # Returns
/// * `Ok(())` if transfer completes or user cancels
/// * `Err(Interrupted)` if user presses Ctrl+C
/// * `Err` if preparation or transfer fails
pub async fn send_folder_with<F, Fut>(folder_path: &Path, transfer_fn: F) -> Result<()>
where
    F: FnOnce(File, String, u64, u64, TransferType) -> Fut,
    Fut: Future<Output = Result<()>> + Send,
{
    let prepared = match prepare_folder_for_send(folder_path).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    // Set up cleanup handler for Ctrl+C
    let temp_path = prepared.temp_file.path().to_path_buf();
    let cleanup_handler = setup_temp_file_cleanup_handler(temp_path.clone());

    // Run transfer with interrupt handling
    let result = tokio::select! {
        result = transfer_fn(
            prepared.file,
            prepared.filename,
            prepared.file_size,
            0, // Folders are not resumable
            TransferType::Folder,
        ) => result,
        _ = cleanup_handler.shutdown_rx => {
            // Graceful shutdown requested - clean up and return Interrupted error
            cleanup_handler.cleanup_path.lock().await.take();
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(Interrupted.into());
        }
    };

    // Clear cleanup path (transfer completed or failed normally)
    cleanup_handler.cleanup_path.lock().await.take();

    result
}

// ============================================================================
// Confirmation handshake protocol (file exists check before data transfer)
// ============================================================================

// Legacy plaintext signals (kept for reference, use encrypted versions below)
/// Signal sent by receiver to indicate transfer should proceed
pub const PROCEED_SIGNAL: &[u8] = b"PROCEED";
/// Signal sent by receiver to abort transfer (e.g., file exists and user declined)
pub const ABORT_SIGNAL: &[u8] = b"ABORT\0\0"; // Padded to 7 bytes like PROCEED

/// Maximum size for encrypted control signals (prevents OOM from malicious length prefixes)
/// Control signals are small (e.g., "ACK", "PROCEED", "RESUME:"+8 bytes) plus encryption overhead
const MAX_CONTROL_SIGNAL_SIZE: usize = 1024;

/// Control signal types for encrypted handshake
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlSignal {
    Proceed,
    Abort,
    Ack,
    Done,
    /// Resume transfer from byte offset
    Resume(u64),
}

/// Send encrypted PROCEED signal
pub async fn send_proceed<W: AsyncWriteExt + Unpin>(writer: &mut W, key: &[u8; 32]) -> Result<()> {
    let encrypted = encrypt(key, b"PROCEED")?;
    let len = encrypted.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&encrypted).await?;
    writer.flush().await?;
    Ok(())
}

/// Send encrypted ABORT signal
pub async fn send_abort<W: AsyncWriteExt + Unpin>(writer: &mut W, key: &[u8; 32]) -> Result<()> {
    let encrypted = encrypt(key, b"ABORT")?;
    let len = encrypted.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&encrypted).await?;
    writer.flush().await?;
    Ok(())
}

/// Send encrypted ACK signal
pub async fn send_ack<W: AsyncWriteExt + Unpin>(writer: &mut W, key: &[u8; 32]) -> Result<()> {
    let encrypted = encrypt(key, b"ACK")?;
    let len = encrypted.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&encrypted).await?;
    writer.flush().await?;
    Ok(())
}

/// Send encrypted RESUME signal with byte offset
/// Format: "RESUME:" || offset(8 bytes BE)
pub async fn send_resume<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    key: &[u8; 32],
    offset: u64,
) -> Result<()> {
    let mut payload = Vec::with_capacity(15); // "RESUME:" + 8 bytes
    payload.extend_from_slice(b"RESUME:");
    payload.extend_from_slice(&offset.to_be_bytes());

    let encrypted = encrypt(key, &payload)?;
    let len = encrypted.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&encrypted).await?;
    writer.flush().await?;
    Ok(())
}

/// Receive and decrypt a control signal
pub async fn recv_control<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    key: &[u8; 32],
) -> Result<ControlSignal> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read control signal length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Validate length to prevent OOM from malicious peers
    if len == 0 {
        anyhow::bail!("Invalid control signal: zero length");
    }
    if len > MAX_CONTROL_SIGNAL_SIZE {
        anyhow::bail!(
            "Control signal too large: {} bytes (max {})",
            len,
            MAX_CONTROL_SIGNAL_SIZE
        );
    }

    // Read encrypted data (safe to allocate after bounds check)
    let mut encrypted = vec![0u8; len];
    reader
        .read_exact(&mut encrypted)
        .await
        .context("Failed to read control signal data")?;

    // Decrypt and check plaintext
    let data = decrypt(key, &encrypted).context("Failed to decrypt control signal")?;

    match data.as_slice() {
        b"PROCEED" => Ok(ControlSignal::Proceed),
        b"ABORT" => Ok(ControlSignal::Abort),
        b"ACK" => Ok(ControlSignal::Ack),
        _ if data.starts_with(b"RESUME:") && data.len() == 15 => {
            // Parse offset from "RESUME:" || offset(8 bytes BE)
            let offset_bytes: [u8; 8] = data[7..15].try_into().unwrap();
            let offset = u64::from_be_bytes(offset_bytes);
            Ok(ControlSignal::Resume(offset))
        }
        _ => anyhow::bail!("Unknown control signal"),
    }
}

// WebRTC-specific control message format: [type(1)][len(4)][encrypted]
// Type: 2 = DONE, 3 = ACK, 4 = PROCEED, 5 = ABORT, 6 = RESUME
const WEBRTC_MSG_TYPE_DONE: u8 = 2;
const WEBRTC_MSG_TYPE_ACK: u8 = 3;
const WEBRTC_MSG_TYPE_PROCEED: u8 = 4;
const WEBRTC_MSG_TYPE_ABORT: u8 = 5;
const WEBRTC_MSG_TYPE_RESUME: u8 = 6;

/// Create encrypted PROCEED message for WebRTC data channel
pub fn make_webrtc_proceed_msg(key: &[u8; 32]) -> Result<Vec<u8>> {
    let encrypted = encrypt(key, b"PROCEED")?;
    let mut msg = vec![WEBRTC_MSG_TYPE_PROCEED];
    msg.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
    msg.extend_from_slice(&encrypted);
    Ok(msg)
}

/// Create encrypted ABORT message for WebRTC data channel
pub fn make_webrtc_abort_msg(key: &[u8; 32]) -> Result<Vec<u8>> {
    let encrypted = encrypt(key, b"ABORT")?;
    let mut msg = vec![WEBRTC_MSG_TYPE_ABORT];
    msg.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
    msg.extend_from_slice(&encrypted);
    Ok(msg)
}

/// Create encrypted ACK message for WebRTC data channel
pub fn make_webrtc_ack_msg(key: &[u8; 32]) -> Result<Vec<u8>> {
    let encrypted = encrypt(key, b"ACK")?;
    let mut msg = vec![WEBRTC_MSG_TYPE_ACK];
    msg.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
    msg.extend_from_slice(&encrypted);
    Ok(msg)
}

/// Create encrypted DONE message for WebRTC data channel
pub fn make_webrtc_done_msg(key: &[u8; 32]) -> Result<Vec<u8>> {
    let encrypted = encrypt(key, b"DONE")?;
    let mut msg = vec![WEBRTC_MSG_TYPE_DONE];
    msg.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
    msg.extend_from_slice(&encrypted);
    Ok(msg)
}

/// Create encrypted RESUME message for WebRTC data channel
/// Payload format: "RESUME:" || offset(8 bytes BE)
pub fn make_webrtc_resume_msg(key: &[u8; 32], offset: u64) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(15); // "RESUME:" + 8 bytes
    payload.extend_from_slice(b"RESUME:");
    payload.extend_from_slice(&offset.to_be_bytes());

    let encrypted = encrypt(key, &payload)?;
    let mut msg = vec![WEBRTC_MSG_TYPE_RESUME];
    msg.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
    msg.extend_from_slice(&encrypted);
    Ok(msg)
}

/// Parse encrypted control message from WebRTC data channel
/// Returns Some(signal) if the message type matches a control signal and decryption succeeds
/// Returns None if the message type is not a control signal
/// Returns Err if the message is malformed or decryption fails
pub fn parse_webrtc_control_msg(data: &[u8], key: &[u8; 32]) -> Result<Option<ControlSignal>> {
    if data.is_empty() {
        return Ok(None);
    }

    let msg_type = data[0];

    // Check if it's a control message type
    if msg_type != WEBRTC_MSG_TYPE_DONE
        && msg_type != WEBRTC_MSG_TYPE_ACK
        && msg_type != WEBRTC_MSG_TYPE_PROCEED
        && msg_type != WEBRTC_MSG_TYPE_ABORT
        && msg_type != WEBRTC_MSG_TYPE_RESUME
    {
        return Ok(None); // Not a control message
    }

    // Parse message: [type(1)][len(4)][encrypted]
    if data.len() < 5 {
        anyhow::bail!("Control message too short");
    }

    let encrypted_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    if data.len() < 5 + encrypted_len {
        anyhow::bail!("Control message truncated");
    }

    let encrypted = &data[5..5 + encrypted_len];

    // Decrypt and verify payload matches message type
    let decrypted = decrypt(key, encrypted)?;

    match (msg_type, decrypted.as_slice()) {
        (WEBRTC_MSG_TYPE_DONE, b"DONE") => Ok(Some(ControlSignal::Done)),
        (WEBRTC_MSG_TYPE_PROCEED, b"PROCEED") => Ok(Some(ControlSignal::Proceed)),
        (WEBRTC_MSG_TYPE_ABORT, b"ABORT") => Ok(Some(ControlSignal::Abort)),
        (WEBRTC_MSG_TYPE_ACK, b"ACK") => Ok(Some(ControlSignal::Ack)),
        (WEBRTC_MSG_TYPE_RESUME, payload)
            if payload.starts_with(b"RESUME:") && payload.len() == 15 =>
        {
            // Parse offset from "RESUME:" || offset(8 bytes BE)
            let offset_bytes: [u8; 8] = payload[7..15].try_into().unwrap();
            let offset = u64::from_be_bytes(offset_bytes);
            Ok(Some(ControlSignal::Resume(offset)))
        }
        _ => anyhow::bail!("Control message type/payload mismatch"),
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

/// Prompt user for choice when file already exists.
/// Returns the user's choice (overwrite, rename, or cancel).
pub fn prompt_file_exists(path: &Path) -> Result<FileExistsChoice> {
    ui::sink().prompt_file_exists(path)
}

// ============================================================================
// Shared resume components for sender and receiver
// ============================================================================

use crate::core::resume::{
    ResumeMetadata, check_resume, create_resume_file, finalize_resume_file as resume_finalize,
    get_data_offset, temp_file_path, update_resume_metadata,
};
use std::io::{Seek, SeekFrom};

/// Result from handling receiver's control signal
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeResponse {
    /// Fresh transfer from beginning
    Fresh,
    /// Resume from byte offset
    Resume { offset: u64, starting_chunk: u64 },
    /// Transfer aborted by receiver
    Aborted,
}

/// Handle receiver's response to header (PROCEED, RESUME, or ABORT).
/// Returns ResumeResponse indicating how to proceed.
pub async fn handle_receiver_response<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    key: &[u8; 32],
) -> Result<ResumeResponse> {
    match recv_control(reader, key).await? {
        ControlSignal::Proceed => Ok(ResumeResponse::Fresh),
        ControlSignal::Resume(offset) => {
            let starting_chunk = offset / CHUNK_SIZE as u64 + 1;
            ui::sink().status(&format!(
                "   Resuming from byte offset {} (chunk {})",
                offset, starting_chunk
            ));
            Ok(ResumeResponse::Resume {
                offset,
                starting_chunk,
            })
        }
        ControlSignal::Abort => Ok(ResumeResponse::Aborted),
        other => anyhow::bail!("Unexpected control signal: {:?}", other),
    }
}

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

        // Progress update
        if progress_interval > 0
            && (chunk_num.is_multiple_of(progress_interval) || bytes_sent == file_size)
        {
            ui::sink().progress(Progress {
                dir: Direction::Send,
                bytes: bytes_sent,
                total: file_size,
                chunk: Some((chunk_num - 1, total_chunks)),
            });
        }
    }

    if progress_interval > 0 {
        ui::sink().progress_end(); // New line after progress
    }

    Ok(())
}

/// State for resumable file reception
pub struct FileReceiver {
    /// The temp file being written to
    pub temp_file: std::fs::File,
    /// Path to the temp file
    pub temp_path: PathBuf,
    /// Final destination path
    pub final_path: PathBuf,
    /// Bytes of file data already received
    pub bytes_received: u64,
    /// Whether this is a resumed transfer
    pub is_resuming: bool,
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

    // Folders are not resumable
    if header.transfer_type == TransferType::Folder || no_resume || header.checksum == 0 {
        // Create fresh temp file
        let metadata = ResumeMetadata {
            checksum: header.checksum,
            file_size: header.file_size,
            bytes_received: 0,
            filename: header.filename.clone(),
        };
        let temp_file = create_resume_file(&temp_path, &metadata)?;
        let data_offset = get_data_offset();

        return Ok((
            FileReceiver {
                temp_file,
                temp_path,
                final_path: final_path.to_path_buf(),
                bytes_received: 0,
                is_resuming: false,
                data_offset,
                metadata,
            },
            ControlSignal::Proceed,
        ));
    }

    // Check for existing temp file that can be resumed
    match check_resume(&temp_path, header.checksum, header.file_size)? {
        Some(resume_check) => {
            // Valid temp file found, resume transfer
            let bytes_received = resume_check.metadata.bytes_received;
            let data_offset = resume_check.data_offset;
            ui::sink().status(&format!(
                "   Found partial download: {} of {} received",
                format_bytes(bytes_received),
                format_bytes(header.file_size)
            ));

            Ok((
                FileReceiver {
                    temp_file: resume_check.file,
                    temp_path,
                    final_path: final_path.to_path_buf(),
                    bytes_received,
                    is_resuming: true,
                    data_offset,
                    metadata: resume_check.metadata,
                },
                ControlSignal::Resume(bytes_received),
            ))
        }
        None => {
            // No valid temp file, start fresh
            let metadata = ResumeMetadata {
                checksum: header.checksum,
                file_size: header.file_size,
                bytes_received: 0,
                filename: header.filename.clone(),
            };
            let temp_file = create_resume_file(&temp_path, &metadata)?;
            let data_offset = get_data_offset();

            Ok((
                FileReceiver {
                    temp_file,
                    temp_path,
                    final_path: final_path.to_path_buf(),
                    bytes_received: 0,
                    is_resuming: false,
                    data_offset,
                    metadata,
                },
                ControlSignal::Proceed,
            ))
        }
    }
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
    let _total_chunks = num_chunks(file_size);
    let start_chunk = receiver.bytes_received / CHUNK_SIZE as u64 + 1;
    let mut chunk_num = start_chunk;

    // Seek to end of data in temp file (for appending)
    receiver.temp_file.seek(SeekFrom::Start(
        receiver.data_offset + receiver.bytes_received,
    ))?;

    while receiver.bytes_received < file_size {
        let chunk = recv_encrypted_chunk(reader, key)
            .await
            .context("Failed to receive chunk")?;

        // Write to temp file
        receiver
            .temp_file
            .write_all(&chunk)
            .context("Failed to write to temp file")?;

        receiver.bytes_received += chunk.len() as u64;
        chunk_num += 1;

        // Update metadata periodically for crash recovery
        if metadata_update_interval > 0 && chunk_num.is_multiple_of(metadata_update_interval) {
            receiver.metadata.bytes_received = receiver.bytes_received;
            // Seek to beginning to update metadata
            receiver.temp_file.seek(SeekFrom::Start(0))?;
            update_resume_metadata(&mut receiver.temp_file, &receiver.metadata)?;
            // Seek back to end of data
            receiver.temp_file.seek(SeekFrom::Start(
                receiver.data_offset + receiver.bytes_received,
            ))?;
        }

        // Progress update
        if progress_interval > 0
            && (chunk_num.is_multiple_of(progress_interval) || receiver.bytes_received == file_size)
        {
            ui::sink().progress(Progress {
                dir: Direction::Receive,
                bytes: receiver.bytes_received,
                total: file_size,
                chunk: None,
            });
        }
    }

    if progress_interval > 0 {
        ui::sink().progress_end(); // New line after progress
    }

    // Final metadata update
    receiver.metadata.bytes_received = receiver.bytes_received;
    receiver.temp_file.seek(SeekFrom::Start(0))?;
    update_resume_metadata(&mut receiver.temp_file, &receiver.metadata)?;
    receiver.temp_file.flush()?;

    Ok(())
}

/// Finalize a completed transfer: strip metadata header and rename to final path.
pub fn finalize_file_receiver(receiver: FileReceiver) -> Result<()> {
    resume_finalize(
        receiver.temp_file,
        &receiver.temp_path,
        &receiver.final_path,
        receiver.data_offset,
    )
}

/// Type alias for cleanup path shared state
pub type CleanupPath = std::sync::Arc<tokio::sync::Mutex<Option<PathBuf>>>;

/// Result of setting up a cleanup handler
pub struct CleanupHandler {
    /// Shared path that can be cleared when cleanup is no longer needed
    pub cleanup_path: CleanupPath,
    /// Receiver that completes when Ctrl+C is received and cleanup is done
    /// Callers should select! on this to handle graceful shutdown
    pub shutdown_rx: tokio::sync::oneshot::Receiver<()>,
}

/// Describes what cleanup action to take on Ctrl+C interrupt.
enum CleanupAction {
    /// Remove a file unconditionally.
    RemoveFile,
    /// Remove a directory recursively.
    RemoveDir,
    /// Remove a file only if the transfer is not resumable;
    /// otherwise preserve it for resume.
    ResumableFile { is_resumable: bool },
}

/// Shared helper that wires up Ctrl+C → cleanup → shutdown signal.
fn spawn_cleanup_handler(path: PathBuf, action: CleanupAction) -> CleanupHandler {
    let cleanup_path: CleanupPath = std::sync::Arc::new(tokio::sync::Mutex::new(Some(path)));
    let cleanup_clone = cleanup_path.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            match action {
                CleanupAction::RemoveFile => {
                    if let Some(path) = cleanup_clone.lock().await.take() {
                        let _ = tokio::fs::remove_file(&path).await;
                        ui::sink().status("\nInterrupted. Cleaned up temp file.");
                    }
                }
                CleanupAction::RemoveDir => {
                    if let Some(path) = cleanup_clone.lock().await.take() {
                        let _ = tokio::fs::remove_dir_all(&path).await;
                        ui::sink().status("\nInterrupted. Cleaned up extraction directory.");
                    }
                }
                CleanupAction::ResumableFile { is_resumable } => {
                    if !is_resumable {
                        if let Some(path) = cleanup_clone.lock().await.take() {
                            let _ = tokio::fs::remove_file(&path).await;
                            ui::sink().status("\nInterrupted. Cleaned up temp file.");
                        }
                    } else {
                        ui::sink().status("\nInterrupted. Partial download saved for resume.");
                    }
                }
            }
            let _ = shutdown_tx.send(());
        }
    });

    CleanupHandler {
        cleanup_path,
        shutdown_rx,
    }
}

/// Set up Ctrl+C handler for resumable transfers.
/// For resumable transfers, preserves temp file and logs resume message.
/// For non-resumable transfers, removes temp file on interrupt.
///
/// Returns a CleanupHandler with:
/// - `cleanup_path`: Clear this when transfer completes normally
/// - `shutdown_rx`: Await or select! on this to detect interrupt and shut down gracefully
///
/// The caller should handle the shutdown signal and exit with code 130.
pub fn setup_resumable_cleanup_handler(temp_path: PathBuf, is_resumable: bool) -> CleanupHandler {
    spawn_cleanup_handler(temp_path, CleanupAction::ResumableFile { is_resumable })
}

/// Set up Ctrl+C handler to always clean up a temp file on interrupt.
/// Used by senders for folder transfers (temp tar archives are not resumable).
///
/// Returns a CleanupHandler with:
/// - `cleanup_path`: Clear this when transfer completes normally
/// - `shutdown_rx`: Await or select! on this to detect interrupt and shut down gracefully
///
/// The caller should handle the shutdown signal and exit with code 130.
pub fn setup_temp_file_cleanup_handler(temp_path: PathBuf) -> CleanupHandler {
    spawn_cleanup_handler(temp_path, CleanupAction::RemoveFile)
}

/// Set up Ctrl+C handler to clean up extraction directory on interrupt.
/// Used by receivers for folder transfers to clean up partial extraction.
///
/// Returns a CleanupHandler with:
/// - `cleanup_path`: Clear this when extraction completes normally
/// - `shutdown_rx`: Await or select! on this to detect interrupt and shut down gracefully
///
/// The caller should handle the shutdown signal and exit with code 130.
pub fn setup_dir_cleanup_handler(extract_dir: PathBuf) -> CleanupHandler {
    spawn_cleanup_handler(extract_dir, CleanupAction::RemoveDir)
}

// ============================================================================
// Unified transfer orchestration functions
// ============================================================================

use tokio::io::AsyncSeekExt;

/// Result of a sender transfer operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferResult {
    /// Transfer completed successfully
    Success,
    /// Transfer was aborted by receiver
    Aborted,
}

/// Unified sender transfer logic for all transports.
///
/// Handles the complete transfer flow:
/// 1. Send encrypted header
/// 2. Wait for receiver response (PROCEED/RESUME/ABORT)
/// 3. Seek file if resuming
/// 4. Send file data
/// 5. Flush stream
/// 6. Wait for ACK (with optional timeout)
///
/// # Arguments
/// * `file` - File to send (must be seekable for resume support)
/// * `stream` - Bidirectional stream for reading and writing
/// * `key` - 32-byte encryption key
/// * `header` - File header with metadata
///
/// # Returns
/// * `TransferResult::Success` - Transfer completed successfully
/// * `TransferResult::Aborted` - Receiver declined the transfer
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
    run_sender_transfer_with_timeout(file, stream, key, header, None).await
}

/// Unified sender transfer logic with optional ACK timeout.
///
/// Same as `run_sender_transfer` but allows specifying a timeout for ACK.
/// If the timeout expires, the transfer is considered successful (data was sent).
/// This is useful for unreliable transports like Tor where streams may close abruptly.
///
/// # Arguments
/// * `file` - File to send (must be seekable for resume support)
/// * `stream` - Bidirectional stream for reading and writing
/// * `key` - 32-byte encryption key
/// * `header` - File header with metadata
/// * `ack_timeout` - Optional timeout for waiting for ACK. If None, waits indefinitely.
///   If timeout expires, considers transfer successful.
pub async fn run_sender_transfer_with_timeout<S, F>(
    file: &mut F,
    stream: &mut S,
    key: &[u8; 32],
    header: &FileHeader,
    ack_timeout: Option<std::time::Duration>,
) -> Result<TransferResult>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
    F: AsyncReadExt + AsyncSeekExt + Unpin,
{
    // 1. Send encrypted header
    send_encrypted_header(stream, key, header)
        .await
        .context("Failed to send header")?;

    // 2. Wait for receiver response
    ui::sink().status("Waiting for receiver to confirm...");
    let start_offset = match handle_receiver_response(stream, key).await? {
        ResumeResponse::Fresh => {
            ui::sink().status("Receiver ready, starting transfer...");
            0
        }
        ResumeResponse::Resume { offset, .. } => {
            ui::sink().status(&format_resume_progress(offset, header.file_size));
            file.seek(SeekFrom::Start(offset)).await?;
            offset
        }
        ResumeResponse::Aborted => {
            ui::sink().status("Receiver declined transfer");
            return Ok(TransferResult::Aborted);
        }
    };

    // 3. Send file data
    send_file_data(file, stream, key, header.file_size, start_offset, 10).await?;

    // 4. Flush stream (important for TCP-based transports)
    stream.flush().await.context("Failed to flush stream")?;

    ui::sink().status("\nTransfer complete!");

    // 5. Wait for ACK (with optional timeout)
    ui::sink().status("Waiting for receiver to confirm...");

    let ack_result = match ack_timeout {
        Some(timeout) => {
            match tokio::time::timeout(timeout, recv_control(stream, key)).await {
                Ok(result) => result,
                Err(_) => {
                    // Timeout - consider transfer successful (data was sent)
                    ui::sink().status("Connection closed (transfer completed)");
                    return Ok(TransferResult::Success);
                }
            }
        }
        None => recv_control(stream, key).await,
    };

    match ack_result {
        Ok(ControlSignal::Ack) => {
            ui::sink().status("Receiver confirmed!");
            Ok(TransferResult::Success)
        }
        Ok(other) => anyhow::bail!("Expected ACK, got {:?}", other),
        Err(e) => {
            // For unreliable transports, connection errors after data sent are acceptable
            if ack_timeout.is_some() {
                ui::sink().status("Connection closed (transfer completed)");
                Ok(TransferResult::Success)
            } else {
                Err(e).context("Failed to receive ACK")
            }
        }
    }
}

use crate::core::folder::{
    StreamingReader, extract_tar_archive_returning_reader, get_extraction_dir,
    print_skipped_entries, print_tar_extraction_info,
};

/// Unified receiver transfer logic for all transports.
///
/// Handles the complete transfer flow:
/// 1. Receive encrypted header
/// 2. Handle file existence check (for files)
/// 3. Prepare receiver and send control signal
/// 4. Receive file/folder data
/// 5. Finalize transfer
/// 6. Send ACK
///
/// # Arguments
/// * `stream` - Bidirectional stream for reading and writing
/// * `key` - 32-byte encryption key
/// * `output_dir` - Optional output directory (defaults to current directory)
/// * `no_resume` - If true, disable resume support
///
/// # Returns
/// * Tuple of (path to received file/directory, stream for cleanup)
///   The stream is returned so callers can perform transport-specific cleanup
///   (e.g., QUIC stream finish).
pub async fn run_receiver_transfer<S>(
    stream: S,
    key: [u8; 32],
    output_dir: Option<PathBuf>,
    no_resume: bool,
) -> Result<(PathBuf, S)>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    // We need to box the stream to allow moving it between async/sync contexts
    let mut stream = stream;

    // 1. Receive header
    let header = recv_encrypted_header(&mut stream, &key)
        .await
        .context("Failed to read header")?;

    ui::sink().status(&format!(
        "Receiving: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    ));

    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));

    // 2. Handle based on transfer type
    let (final_path, stream) = match header.transfer_type {
        TransferType::File => {
            let path =
                receive_file_transfer_impl(&mut stream, &key, &header, &output_dir, no_resume)
                    .await?;
            (path, stream)
        }
        TransferType::Folder => {
            receive_folder_transfer_impl(stream, &key, &header, &output_dir).await?
        }
    };

    Ok((final_path, stream))
}

/// Internal implementation for file transfer reception.
async fn receive_file_transfer_impl<S>(
    stream: &mut S,
    key: &[u8; 32],
    header: &FileHeader,
    output_dir: &Path,
    no_resume: bool,
) -> Result<PathBuf>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Determine final output path
    let output_path = output_dir.join(&header.filename);

    // Check file existence and get final path
    let final_output_path = if output_path.exists() {
        // Prompt user in blocking context
        let path_clone = output_path.clone();
        let choice = tokio::task::spawn_blocking(move || prompt_file_exists(&path_clone))
            .await
            .context("Prompt task panicked")??;

        match choice {
            FileExistsChoice::Overwrite => {
                // Handle TOCTOU race: file may have been removed between check and now
                match tokio::fs::remove_file(&output_path).await {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // File was already removed - this is fine
                    }
                    Err(e) => {
                        return Err(e).context("Failed to remove existing file");
                    }
                }
                output_path
            }
            FileExistsChoice::Rename => {
                let new_path = find_available_filename(&output_path);
                ui::sink().status(&format!("Will save as: {}", new_path.display()));
                new_path
            }
            FileExistsChoice::Cancel => {
                // Send abort signal to sender
                send_abort(stream, key)
                    .await
                    .context("Failed to send abort signal")?;
                anyhow::bail!("Transfer cancelled by user");
            }
        }
    } else {
        output_path
    };

    // Prepare file receiver (checks for resume)
    let (mut receiver, control_signal) =
        prepare_file_receiver(&final_output_path, header, no_resume)?;

    // Set up cleanup handler
    let is_resumable = !no_resume && header.checksum != 0;
    let cleanup_handler = setup_resumable_cleanup_handler(receiver.temp_path.clone(), is_resumable);

    // Send control signal
    match &control_signal {
        ControlSignal::Proceed => {
            send_proceed(stream, key)
                .await
                .context("Failed to send proceed signal")?;
            ui::sink().status("Ready to receive data...");
        }
        ControlSignal::Resume(offset) => {
            send_resume(stream, key, *offset)
                .await
                .context("Failed to send resume signal")?;
            ui::sink().status(&format_resume_progress(*offset, header.file_size));
        }
        other => anyhow::bail!(
            "Unexpected control signal from prepare_file_receiver: {:?}",
            other
        ),
    }

    // Receive file data with interrupt handling
    tokio::select! {
        result = receive_file_data(stream, &mut receiver, key, header.file_size, 10, 100) => {
            result?;
        }
        _ = cleanup_handler.shutdown_rx => {
            // Graceful shutdown requested - return Interrupted error
            return Err(Interrupted.into());
        }
    }

    // Clear cleanup and finalize
    cleanup_handler.cleanup_path.lock().await.take();
    finalize_file_receiver(receiver)?;

    ui::sink().status("\nFile received successfully!");
    ui::sink().status(&format!("Saved to: {}", final_output_path.display()));

    // Send ACK
    send_ack(stream, key)
        .await
        .context("Failed to send acknowledgment")?;

    Ok(final_output_path)
}

/// Internal implementation for folder transfer reception.
/// Returns (path, stream) so callers can perform transport-specific cleanup.
async fn receive_folder_transfer_impl<S>(
    mut stream: S,
    key: &[u8; 32],
    header: &FileHeader,
    output_dir: &Path,
) -> Result<(PathBuf, S)>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    ui::sink().status(&format!(
        "Receiving folder archive: {} ({})",
        header.filename,
        format_bytes(header.file_size)
    ));

    // Folders are not resumable, always send proceed
    send_proceed(&mut stream, key)
        .await
        .context("Failed to send proceed signal")?;
    ui::sink().status("Ready to receive data...");

    // Determine extraction directory
    let extract_dir = get_extraction_dir(Some(output_dir.to_path_buf()));
    std::fs::create_dir_all(&extract_dir).context("Failed to create extraction directory")?;

    // Set up cleanup handler
    let cleanup_handler = setup_dir_cleanup_handler(extract_dir.clone());

    ui::sink().status(&format!("Extracting to: {}", extract_dir.display()));
    print_tar_extraction_info();

    // Get runtime handle for blocking in StreamingReader
    let runtime_handle = tokio::runtime::Handle::current();

    // Create streaming reader that feeds tar extractor
    let reader = StreamingReader::new(stream, *key, header.file_size, runtime_handle);

    // Run tar extraction in blocking context with interrupt handling
    let extract_dir_clone = extract_dir.clone();
    let extraction_result = tokio::select! {
        result = tokio::task::spawn_blocking(move || {
            extract_tar_archive_returning_reader(reader, &extract_dir_clone)
        }) => result.context("Extraction task panicked")?,
        _ = cleanup_handler.shutdown_rx => {
            // Graceful shutdown requested - return Interrupted error
            // Note: cleanup_handler already cleaned up the directory in its signal handler
            return Err(Interrupted.into());
        }
    };

    let (skipped_entries, streaming_reader) = extraction_result?;

    // Report skipped entries
    print_skipped_entries(&skipped_entries);

    // Clear cleanup
    cleanup_handler.cleanup_path.lock().await.take();

    ui::sink().status("\nFolder received successfully!");
    ui::sink().status(&format!("Extracted to: {}", extract_dir.display()));

    // Get stream back and send ACK
    // Validate that all expected bytes were received before sending ACK
    let mut stream = streaming_reader
        .into_inner()
        .context("Transfer validation failed")?;
    send_ack(&mut stream, key)
        .await
        .context("Failed to send acknowledgment")?;

    Ok((extract_dir, stream))
}
