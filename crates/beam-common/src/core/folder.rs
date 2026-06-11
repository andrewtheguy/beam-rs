//! Transport-agnostic folder operations for tar archive creation and extraction.
//!
//! This module provides common folder handling logic used by both iroh and Tor transports.

use anyhow::{Context, Result};
use std::cmp;
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::{Archive, Builder};
use tempfile::NamedTempFile;
use walkdir::WalkDir;

use crate::core::transfer::{contains_path_traversal, recv_encrypted_chunk};

/// Result of creating a tar archive from a folder.
pub struct TarArchive {
    /// The temporary file containing the tar archive.
    pub temp_file: NamedTempFile,
    /// The archive filename (folder_name.tar).
    pub filename: String,
    /// The archive size in bytes.
    pub file_size: u64,
}

/// Create a tar archive from a folder.
///
/// Returns the temp file containing the archive, the archive filename, and its size.
/// The caller is responsible for cleaning up the temp file on error/interrupt.
///
/// # Arguments
/// * `folder_path` - Path to the folder to archive
///
/// # Returns
/// * `TarArchive` containing the temp file, filename, and size
pub fn create_tar_archive(folder_path: &Path) -> Result<TarArchive> {
    // Validate that the path exists and is a directory
    if !folder_path.exists() {
        anyhow::bail!("Folder does not exist: {}", folder_path.display());
    }
    if !folder_path.is_dir() {
        anyhow::bail!(
            "Path is not a directory: {} (use send for files)",
            folder_path.display()
        );
    }

    let folder_name = folder_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid folder name")?;

    // Create tar archive to temp file
    let temp_tar = NamedTempFile::new().context("Failed to create temporary file")?;

    // Build tar archive
    {
        let tar_file = temp_tar.reopen().context("Failed to open tar file")?;
        let mut builder = Builder::new(tar_file);

        // Walk the directory and add all entries
        for entry in WalkDir::new(folder_path) {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            // Calculate relative path from folder root
            let rel_path = path
                .strip_prefix(folder_path)
                .context("Failed to calculate relative path")?;

            // Skip the root folder itself
            if rel_path.as_os_str().is_empty() {
                continue;
            }

            // Create archive path with folder name as root
            let archive_path = Path::new(folder_name).join(rel_path);

            if path.is_symlink() {
                // Handle symlinks explicitly before is_dir()/is_file() which follow symlinks
                builder
                    .append_path_with_name(path, &archive_path)
                    .with_context(|| format!("Failed to add symlink: {}", path.display()))?;
            } else if path.is_dir() {
                builder
                    .append_dir(&archive_path, path)
                    .with_context(|| format!("Failed to add directory: {}", path.display()))?;
            } else if path.is_file() {
                builder
                    .append_path_with_name(path, &archive_path)
                    .with_context(|| format!("Failed to add file: {}", path.display()))?;
            }
            // Other special files (devices, sockets, etc.) are skipped
        }

        builder.finish().context("Failed to finalize tar archive")?;
    }

    // Get tar file size
    let file_size = std::fs::metadata(temp_tar.path())
        .context("Failed to read tar file metadata")?
        .len();

    let filename = format!("{}.tar", folder_name);

    Ok(TarArchive {
        temp_file: temp_tar,
        filename,
        file_size,
    })
}

/// Wrapper to bridge async chunk receiving with sync tar reading.
/// Implements std::io::Read by fetching chunks on demand.
///
/// # Usage Requirements
///
/// This type uses `runtime_handle.block_on()` internally to fetch async chunks
/// from within a synchronous `Read::read()` implementation. **This is only safe
/// when called from outside the Tokio async runtime context.**
///
/// The correct pattern is to use `tokio::task::spawn_blocking` to move the
/// tar extraction (which calls `Read::read()`) to a blocking thread pool:
///
/// ```ignore
/// let reader = StreamingReader::new(stream, key, file_size, runtime_handle);
/// let result = tokio::task::spawn_blocking(move || {
///     extract_tar_archive_returning_reader(reader, &extract_dir)
/// }).await?;
/// ```
///
/// # Panics
///
/// Calling `Read::read()` from within an async context (e.g., directly from
/// an async function without `spawn_blocking`) will cause a panic or deadlock.
pub struct StreamingReader<R> {
    recv_stream: R,
    key: [u8; 32],
    chunk_num: u64,
    buffer: Vec<u8>,
    buffer_pos: usize,
    bytes_remaining: u64,
    file_size: u64,
    runtime_handle: tokio::runtime::Handle,
}

impl<R> StreamingReader<R> {
    /// Create a new StreamingReader.
    ///
    /// # Arguments
    /// * `recv_stream` - The async stream to read from
    /// * `key` - AES-256-GCM encryption key
    /// * `file_size` - Total expected bytes to read
    /// * `runtime_handle` - Tokio runtime handle for blocking operations
    pub fn new(
        recv_stream: R,
        key: [u8; 32],
        file_size: u64,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            recv_stream,
            key,
            chunk_num: 1, // Chunks start at 1, header was 0
            buffer: Vec::new(),
            buffer_pos: 0,
            bytes_remaining: file_size,
            file_size,
            runtime_handle,
        }
    }

    /// Consume the StreamingReader and return the underlying stream.
    ///
    /// Use this to send ACK after extraction is complete.
    ///
    /// # Errors
    ///
    /// Returns an error if not all expected bytes were read from the stream,
    /// indicating an incomplete or corrupted transfer.
    pub fn into_inner(self) -> Result<R> {
        if self.bytes_remaining != 0 {
            anyhow::bail!(
                "Incomplete stream: {} of {} bytes not received",
                self.bytes_remaining,
                self.file_size
            );
        }
        Ok(self.recv_stream)
    }
}

impl<R: tokio::io::AsyncReadExt + Unpin + Send> Read for StreamingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // If buffer is exhausted and there's more data, fetch next chunk
        if self.buffer_pos >= self.buffer.len() && self.bytes_remaining > 0 {
            // Use runtime_handle.block_on() to run the async future.
            // SAFETY: This is only safe when called from a blocking thread pool
            // (via spawn_blocking), not from within an async context.
            // See struct documentation for the correct usage pattern.
            let chunk_result = self
                .runtime_handle
                .block_on(async { recv_encrypted_chunk(&mut self.recv_stream, &self.key).await });

            match chunk_result {
                Ok(chunk) => {
                    if chunk.is_empty() && self.bytes_remaining > 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            format!(
                                "Received empty chunk with {} bytes remaining",
                                self.bytes_remaining
                            ),
                        ));
                    }
                    self.bytes_remaining = self.bytes_remaining.saturating_sub(chunk.len() as u64);
                    log::trace!(
                        "Received chunk {}, {} bytes remaining",
                        self.chunk_num,
                        self.bytes_remaining
                    );
                    self.chunk_num += 1;
                    self.buffer = chunk;
                    self.buffer_pos = 0;
                }
                Err(e) => {
                    return Err(std::io::Error::other(format!(
                        "Failed to receive chunk {}: {}",
                        self.chunk_num, e
                    )));
                }
            }
        }

        // Return data from buffer
        if self.buffer_pos >= self.buffer.len() {
            return Ok(0); // EOF
        }

        let available = self.buffer.len() - self.buffer_pos;
        let to_copy = cmp::min(available, buf.len());
        buf[..to_copy].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
        self.buffer_pos += to_copy;

        Ok(to_copy)
    }
}

/// Extract a tar archive from a reader to a directory.
///
/// # Arguments
/// * `reader` - Any type implementing std::io::Read (can be StreamingReader or std::fs::File)
/// * `extract_dir` - Directory to extract files to
///
/// # Returns
/// * Vector of skipped entry descriptions (for logging)
pub fn extract_tar_archive<R: Read>(reader: R, extract_dir: &Path) -> Result<Vec<String>> {
    let (skipped, _reader) = extract_tar_archive_returning_reader(reader, extract_dir)?;
    Ok(skipped)
}

/// Extract a tar archive from a reader to a directory, returning the reader for further use.
///
/// This variant returns the underlying reader after extraction, allowing callers to
/// send ACK messages or perform other operations on the stream.
///
/// # Arguments
/// * `reader` - Any type implementing std::io::Read (can be StreamingReader or std::fs::File)
/// * `extract_dir` - Directory to extract files to
///
/// # Returns
/// * Tuple of (skipped entry descriptions, reader)
///
/// # Security
///
/// This function validates each entry path to prevent directory traversal attacks.
/// Entries with paths that would escape the extraction directory are skipped and logged.
pub fn extract_tar_archive_returning_reader<R: Read>(
    reader: R,
    extract_dir: &Path,
) -> Result<(Vec<String>, R)> {
    // Ensure extraction directory exists and is writable
    std::fs::create_dir_all(extract_dir).with_context(|| {
        format!(
            "Failed to create extraction directory: {}",
            extract_dir.display()
        )
    })?;

    // Verify it's actually a directory
    if !extract_dir.is_dir() {
        anyhow::bail!(
            "Extraction path exists but is not a directory: {}",
            extract_dir.display()
        );
    }

    // Verify directory is writable by creating and removing a temp file
    let test_file = extract_dir.join(".beam_write_test");
    std::fs::File::create(&test_file).with_context(|| {
        format!(
            "Extraction directory is not writable: {}",
            extract_dir.display()
        )
    })?;
    let _ = std::fs::remove_file(&test_file);

    // Canonicalize extract_dir for path traversal checks
    let canonical_extract_dir = extract_dir.canonicalize().with_context(|| {
        format!(
            "Failed to canonicalize extraction directory: {}",
            extract_dir.display()
        )
    })?;

    let mut archive = Archive::new(reader);
    // Preserve file mode (0755, etc.) but not owner/group (UID/GID mismatch across machines)
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(false);

    let mut skipped = Vec::new();

    for entry in archive.entries().context("Failed to read tar entries")? {
        let mut entry = entry.context("Failed to read tar entry")?;
        let entry_path = entry
            .path()
            .context("Failed to get entry path")?
            .into_owned();

        // Security: Validate entry path to prevent directory traversal
        let path_str = entry_path.to_string_lossy();
        if contains_path_traversal(&path_str) {
            skipped.push(format!("{} (path traversal attempt)", entry_path.display()));
            log::warn!(
                "Skipping entry with path traversal: {}",
                entry_path.display()
            );
            continue;
        }

        // Validate that the resolved path stays within extract_dir
        // We need to check the target path after joining with extract_dir
        let target_path = canonical_extract_dir.join(&entry_path);
        // For entries that don't exist yet, we can't canonicalize them,
        // so we check component-by-component that no ".." escapes the root
        if !is_path_within_dir(&target_path, &canonical_extract_dir) {
            skipped.push(format!(
                "{} (escapes extraction directory)",
                entry_path.display()
            ));
            log::warn!(
                "Skipping entry that escapes extraction directory: {}",
                entry_path.display()
            );
            continue;
        }

        // Check entry type
        let entry_type = entry.header().entry_type();

        // On Windows, symlinks require special privileges and may fail
        #[cfg(windows)]
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            skipped.push(format!("{} (symlink/hardlink)", entry_path.display()));
            continue;
        }

        // Skip special files that can't be extracted
        if entry_type.is_block_special()
            || entry_type.is_character_special()
            || entry_type.is_fifo()
        {
            skipped.push(format!("{} (special file)", entry_path.display()));
            continue;
        }

        // Extract the entry
        entry
            .unpack_in(extract_dir)
            .with_context(|| format!("Failed to extract: {}", entry_path.display()))?;
    }

    // Return reader for ACK sending
    let reader = archive.into_inner();
    Ok((skipped, reader))
}

/// Check if a target path stays within the given base directory.
///
/// This function handles paths that may not exist yet by checking
/// that no component causes traversal outside the base directory.
fn is_path_within_dir(target: &Path, base: &Path) -> bool {
    use std::path::Component;

    // Normalize both paths by iterating components
    let mut normalized = base.to_path_buf();

    for component in target.strip_prefix(base).unwrap_or(target).components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                // Absolute path component - this escapes the base
                return false;
            }
            Component::ParentDir => {
                // ".." - go up one level, but don't go above base
                if !normalized.pop() || !normalized.starts_with(base) {
                    return false;
                }
            }
            Component::CurDir => {
                // "." - ignore
            }
            Component::Normal(name) => {
                normalized.push(name);
            }
        }
    }

    // Final check: the normalized path must start with base
    normalized.starts_with(base)
}

/// Print folder creation info messages.
pub fn print_tar_creation_info() {
    let sink = crate::ui::sink();
    #[cfg(unix)]
    sink.status("   File modes (e.g., 0755) will be preserved; owner/group will not.");
    #[cfg(windows)]
    sink.status("   Note: Windows does not support Unix file modes.");
    sink.status("   Symlinks are included; special files (devices, FIFOs) are skipped.");
}

/// Print folder extraction info messages.
pub fn print_tar_extraction_info() {
    let sink = crate::ui::sink();
    #[cfg(unix)]
    sink.status("   File modes (e.g., 0755) will be preserved; owner/group will not.");
    #[cfg(windows)]
    {
        sink.status("   Note: Unix file modes are not supported on Windows.");
        sink.status("   Symlinks require admin privileges and may be skipped.");
    }
    sink.status("   Special files (devices, FIFOs) will be skipped if present.");
}

/// Determine the extraction directory for a folder transfer.
///
/// If `output_dir` is provided, uses it directly.
/// Otherwise, generates a unique directory name with timestamp and random suffix.
///
/// # Arguments
/// * `output_dir` - Optional user-specified output directory
///
/// # Returns
/// * The directory path to extract files into
pub fn get_extraction_dir(output_dir: Option<PathBuf>) -> PathBuf {
    match output_dir {
        Some(dir) => dir,
        None => {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("System clock is set before Unix epoch")
                .as_secs();
            let random_id: u32 = rand::random();
            PathBuf::from(format!("beam_{}_{:08x}", timestamp, random_id))
        }
    }
}

/// Print skipped entries warning if any were skipped during extraction.
pub fn print_skipped_entries(skipped_entries: &[String]) {
    if !skipped_entries.is_empty() {
        let sink = crate::ui::sink();
        sink.status(&format!(
            "\n⚠️  Skipped {} entries (not supported on this platform):",
            skipped_entries.len()
        ));
        for entry in skipped_entries {
            sink.status(&format!("   - {}", entry));
        }
    }
}
