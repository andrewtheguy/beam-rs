//! Resumable file transfer support.
//!
//! This module provides functionality for resuming interrupted file transfers.
//! It uses a temporary file with metadata header to track transfer progress,
//! and std file locking (`File::try_lock`) for cross-platform locking.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;
use xxhash_rust::xxh64::Xxh64;

use crate::core::crypto::CHUNK_SIZE;

/// Magic bytes at the start of resume temp files
const RESUME_MAGIC: &[u8; 4] = b"WHRM";

/// Size of the metadata header (magic + length prefix)
const HEADER_PREFIX_SIZE: usize = 8; // 4 bytes magic + 4 bytes length

/// Fixed size for padded JSON metadata to prevent data corruption on updates.
/// Must be large enough for max filename (255 chars) + max u64 values + JSON overhead.
/// 512 bytes is plenty: ~300 for max filename + ~100 for numbers + JSON syntax.
const PADDED_METADATA_SIZE: usize = 512;

/// Metadata stored in temp file header for resume verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeMetadata {
    /// xxhash64 of the source file
    pub checksum: u64,
    /// Expected final file size
    pub file_size: u64,
    /// Bytes of file data already written to temp file (excludes metadata header)
    pub bytes_received: u64,
    /// Original filename
    pub filename: String,
}

/// Result of checking for a resumable transfer
pub struct ResumeCheck {
    /// The locked temp file ready for writing
    pub file: File,
    /// Metadata from the temp file
    pub metadata: ResumeMetadata,
    /// Offset in temp file where file data starts (after metadata header)
    pub data_offset: u64,
}

/// Get the temp file path for a given final output path.
/// Format: `<final_path>.beam-rs.partial`
pub fn temp_file_path(final_path: &Path) -> PathBuf {
    let mut temp_path = final_path.as_os_str().to_owned();
    temp_path.push(".beam-rs.partial");
    PathBuf::from(temp_path)
}

/// Calculate xxhash64 checksum of a file (async, streaming).
/// Uses 64KB buffer for efficient reading.
pub async fn calculate_file_checksum(path: &Path) -> Result<u64> {
    let mut file = tokio::fs::File::open(path)
        .await
        .context("Failed to open file for checksum")?;

    let mut hasher = Xxh64::new(0);
    let mut buffer = vec![0u8; 64 * 1024]; // 64KB buffer

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .await
            .context("Failed to read file for checksum")?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.digest())
}

/// Calculate xxhash64 checksum of a file synchronously.
/// Used for verifying temp file contents.
pub fn calculate_file_checksum_sync(path: &Path) -> Result<u64> {
    let mut file = File::open(path).context("Failed to open file for checksum")?;

    let mut hasher = Xxh64::new(0);
    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        let bytes_read = file.read(&mut buffer).context("Failed to read file")?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.digest())
}

/// Try to acquire an exclusive non-blocking lock on a file.
/// Returns Ok(true) if lock acquired, Ok(false) if file is already locked.
pub fn try_exclusive_lock(file: &File) -> Result<bool> {
    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(e)) => Err(e).context("Failed to acquire file lock"),
    }
}

/// Create a new resume temp file with metadata header.
/// The file is created with an exclusive lock.
pub fn create_resume_file(temp_path: &Path, metadata: &ResumeMetadata) -> Result<File> {
    // If file exists, acquire lock and truncate while holding the lock
    // This prevents TOCTOU race where we truncate another process's in-progress file
    if temp_path.exists() {
        match OpenOptions::new().read(true).write(true).open(temp_path) {
            Ok(mut file) => {
                if !try_exclusive_lock(&file)? {
                    anyhow::bail!("Another transfer is in progress for this file");
                }
                // Lock acquired, truncate this handle (keeping the lock)
                file.set_len(0).context("Failed to truncate temp file")?;
                file.seek(SeekFrom::Start(0))
                    .context("Failed to seek after truncate")?;
                write_metadata_header(&mut file, metadata)?;
                return Ok(file);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // File was removed between exists() check and open(), fall through to create
            }
            Err(e) => {
                return Err(e).context("Failed to open existing temp file");
            }
        }
    }

    // File doesn't exist, create it exclusively
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(temp_path)
        .context("Failed to create temp file")?;

    // Acquire exclusive lock on the new file
    if !try_exclusive_lock(&file)? {
        anyhow::bail!("Another transfer is in progress for this file");
    }

    // Write metadata header
    write_metadata_header(&mut file, metadata)?;

    Ok(file)
}

/// Write metadata header to the beginning of a file.
/// JSON is padded to a fixed size to prevent data corruption when updating
/// (e.g., when bytes_received grows from small to large numbers).
fn write_metadata_header(file: &mut File, metadata: &ResumeMetadata) -> Result<()> {
    let mut json = serde_json::to_vec(metadata).context("Failed to serialize metadata")?;

    // Ensure metadata fits in padded size
    if json.len() > PADDED_METADATA_SIZE {
        anyhow::bail!(
            "Metadata too large: {} bytes > {} max (filename too long?)",
            json.len(),
            PADDED_METADATA_SIZE
        );
    }

    // Pad JSON to fixed size (JSON parsers ignore trailing whitespace)
    json.resize(PADDED_METADATA_SIZE, b' ');

    // Write magic
    file.write_all(RESUME_MAGIC)
        .context("Failed to write magic")?;

    // Write length prefix (4 bytes, big-endian) - always PADDED_METADATA_SIZE
    let len = PADDED_METADATA_SIZE as u32;
    file.write_all(&len.to_be_bytes())
        .context("Failed to write metadata length")?;

    // Write padded JSON metadata
    file.write_all(&json).context("Failed to write metadata")?;

    file.flush().context("Failed to flush metadata")?;

    Ok(())
}

/// Read metadata from temp file and return file positioned at data start.
/// Returns None if file doesn't exist or has invalid format.
pub fn read_resume_metadata(temp_path: &Path) -> Result<Option<ResumeCheck>> {
    // Check if file exists
    if !temp_path.exists() {
        return Ok(None);
    }

    // Open file
    let mut file = match OpenOptions::new().read(true).write(true).open(temp_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("Failed to open temp file"),
    };

    // Try to acquire exclusive lock
    if !try_exclusive_lock(&file)? {
        anyhow::bail!("Another transfer is in progress for this file");
    }

    // Read and validate magic
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        // File too short, treat as invalid
        drop(file);
        std::fs::remove_file(temp_path).ok();
        return Ok(None);
    }

    if &magic != RESUME_MAGIC {
        // Invalid magic, not a resume file
        drop(file);
        std::fs::remove_file(temp_path).ok();
        return Ok(None);
    }

    // Read metadata length
    let mut len_buf = [0u8; 4];
    if file.read_exact(&mut len_buf).is_err() {
        drop(file);
        std::fs::remove_file(temp_path).ok();
        return Ok(None);
    }
    let metadata_len = u32::from_be_bytes(len_buf) as usize;

    // Sanity check metadata length (max 64KB)
    if metadata_len > 64 * 1024 {
        drop(file);
        std::fs::remove_file(temp_path).ok();
        return Ok(None);
    }

    // Read metadata JSON
    let mut json_buf = vec![0u8; metadata_len];
    if file.read_exact(&mut json_buf).is_err() {
        drop(file);
        std::fs::remove_file(temp_path).ok();
        return Ok(None);
    }

    // Parse metadata
    let metadata: ResumeMetadata = match serde_json::from_slice(&json_buf) {
        Ok(m) => m,
        Err(_) => {
            drop(file);
            std::fs::remove_file(temp_path).ok();
            return Ok(None);
        }
    };

    // Calculate data offset (header size)
    let data_offset = (HEADER_PREFIX_SIZE + metadata_len) as u64;

    // Verify bytes_received matches actual file size
    let file_size = file
        .metadata()
        .context("Failed to get temp file metadata")?
        .len();
    let actual_data_bytes = file_size.saturating_sub(data_offset);

    // If file has less data than metadata claims, update and persist corrected metadata
    let adjusted_metadata = if actual_data_bytes < metadata.bytes_received {
        log::warn!(
            "Resume file has less data than metadata claims: {} bytes actual vs {} bytes recorded. Correcting metadata.",
            actual_data_bytes,
            metadata.bytes_received
        );
        let corrected = ResumeMetadata {
            bytes_received: actual_data_bytes,
            ..metadata
        };

        // Persist the corrected metadata immediately
        // Seek to beginning and rewrite the metadata header
        file.seek(SeekFrom::Start(0))
            .context("Failed to seek to metadata for correction")?;
        write_metadata_header(&mut file, &corrected)
            .context("Failed to persist corrected metadata")?;
        file.sync_all()
            .context("Failed to sync corrected metadata")?;

        corrected
    } else {
        metadata
    };

    Ok(Some(ResumeCheck {
        file,
        metadata: adjusted_metadata,
        data_offset,
    }))
}

/// Check if we can resume a transfer for the given file.
/// Returns Some(ResumeCheck) if resume is possible, None if we should start fresh.
pub fn check_resume(
    temp_path: &Path,
    expected_checksum: u64,
    expected_size: u64,
) -> Result<Option<ResumeCheck>> {
    let resume_check = match read_resume_metadata(temp_path)? {
        Some(rc) => rc,
        None => return Ok(None),
    };

    // Verify checksum and size match
    if resume_check.metadata.checksum != expected_checksum
        || resume_check.metadata.file_size != expected_size
    {
        // Different file, remove temp and start fresh
        drop(resume_check.file);
        std::fs::remove_file(temp_path).ok();
        return Ok(None);
    }

    // Valid resume point
    Ok(Some(resume_check))
}

/// Update the bytes_received field in the temp file metadata.
/// Called periodically during transfer to track progress.
///
/// Uses pwrite on Unix to avoid seek/write/seek pattern that could leave the
/// file pointer in an incorrect position if any operation fails.
pub fn update_resume_metadata(file: &mut File, metadata: &ResumeMetadata) -> Result<()> {
    // Validate metadata consistency before writing
    if metadata.bytes_received > metadata.file_size {
        anyhow::bail!(
            "Invalid resume metadata: bytes_received ({}) exceeds file_size ({})",
            metadata.bytes_received,
            metadata.file_size
        );
    }

    // Serialize and pad metadata
    let header_bytes = serialize_metadata_header(metadata)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        // Use pwrite to write at offset 0 without affecting file position
        file.write_all_at(&header_bytes, 0)
            .context("Failed to write metadata with pwrite")?;
        file.sync_data().context("Failed to sync metadata")?;
    }

    #[cfg(not(unix))]
    {
        // On non-Unix, save position, write, and restore
        let original_pos = file
            .stream_position()
            .context("Failed to get current file position")?;

        // Seek to beginning and write
        file.seek(SeekFrom::Start(0))
            .context("Failed to seek to metadata")?;

        let write_result = file.write_all(&header_bytes);
        let flush_result = file.flush();

        // Always try to restore position, even if write failed
        let restore_result = file.seek(SeekFrom::Start(original_pos));

        // Now check results in order
        write_result.context("Failed to write metadata")?;
        flush_result.context("Failed to flush metadata")?;
        restore_result.context("Failed to restore file position after metadata update")?;

        file.sync_data().context("Failed to sync metadata")?;
    }

    Ok(())
}

/// Serialize metadata to a complete header buffer (magic + length + padded JSON).
fn serialize_metadata_header(metadata: &ResumeMetadata) -> Result<Vec<u8>> {
    let mut json = serde_json::to_vec(metadata).context("Failed to serialize metadata")?;

    // Ensure metadata fits in padded size
    if json.len() > PADDED_METADATA_SIZE {
        anyhow::bail!(
            "Metadata too large: {} bytes > {} max (filename too long?)",
            json.len(),
            PADDED_METADATA_SIZE
        );
    }

    // Pad JSON to fixed size (JSON parsers ignore trailing whitespace)
    json.resize(PADDED_METADATA_SIZE, b' ');

    // Build complete header: magic + length + padded JSON
    let mut header = Vec::with_capacity(HEADER_PREFIX_SIZE + PADDED_METADATA_SIZE);
    header.extend_from_slice(RESUME_MAGIC);
    header.extend_from_slice(&(PADDED_METADATA_SIZE as u32).to_be_bytes());
    header.extend_from_slice(&json);

    Ok(header)
}

/// Finalize a completed transfer: strip metadata header and rename to final path.
///
/// Uses atomic rename for safety:
/// 1. Write to a staging file (final_path.partial) in the same directory
/// 2. Sync the staging file and parent directory
/// 3. Atomically rename staging file to final path
/// 4. Only after successful rename, remove the original temp file
///
/// If any step fails, the original temp file is preserved for resume.
pub fn finalize_resume_file(
    mut temp_file: File,
    temp_path: &Path,
    final_path: &Path,
    data_offset: u64,
) -> Result<()> {
    // Get total file size
    let file_size = temp_file
        .metadata()
        .context("Failed to get temp file size")?
        .len();

    // Guard against corrupted temp file (data_offset > file_size would underflow)
    if data_offset > file_size {
        anyhow::bail!(
            "Corrupted temp file: data_offset ({}) > file_size ({})",
            data_offset,
            file_size
        );
    }
    let data_size = file_size - data_offset;

    // We need to strip the metadata header. There are a few approaches:
    // 1. Read data, write to new file, rename
    // 2. Use platform-specific APIs to truncate from beginning (not portable)
    // 3. Memory map and copy (complex)
    //
    // For safety, we use atomic rename:
    // - Write to a staging file (.partial) in the same directory as final_path
    // - This ensures rename is atomic (same filesystem)
    // - Only remove temp file after successful rename

    // Create staging path in the same directory as final_path
    let staging_path = {
        let mut staging = final_path.as_os_str().to_owned();
        staging.push(".partial");
        PathBuf::from(staging)
    };

    // Get parent directory for fsync
    let parent_dir = final_path
        .parent()
        .context("Final path has no parent directory")?;

    // Write to staging file
    // Scope the staging_file so it's dropped before rename
    // Use a helper to ensure cleanup on any error path
    let copy_result: Result<()> = (|| {
        let mut staging_file =
            File::create(&staging_path).context("Failed to create staging file")?;

        // Seek past metadata in temp file
        temp_file
            .seek(SeekFrom::Start(data_offset))
            .context("Failed to seek past metadata")?;

        // Copy data in chunks
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut remaining = data_size;

        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buffer.len() as u64) as usize;
            let bytes_read = temp_file
                .read(&mut buffer[..to_read])
                .context("Failed to read from temp file")?;
            if bytes_read == 0 {
                anyhow::bail!(
                    "Temp file truncated: expected {} bytes, but {} bytes remaining (copied {} of {} bytes)",
                    data_size,
                    remaining,
                    data_size - remaining,
                    data_size
                );
            }
            staging_file
                .write_all(&buffer[..bytes_read])
                .context("Failed to write to staging file")?;
            remaining -= bytes_read as u64;
        }

        // Sync staging file to disk
        staging_file
            .sync_all()
            .context("Failed to sync staging file")?;

        // staging_file is dropped here, before rename
        Ok(())
    })();

    // Clean up staging file on any error (file is already closed)
    if let Err(e) = copy_result {
        let _ = std::fs::remove_file(&staging_path);
        return Err(e);
    }

    // Sync parent directory to ensure staging file entry is persisted
    // This is important for crash safety on some filesystems
    if let Ok(dir) = File::open(parent_dir) {
        let _ = dir.sync_all();
    }

    // Atomically rename staging file to final path
    // This is atomic on POSIX systems when src and dst are on the same filesystem
    std::fs::rename(&staging_path, final_path).with_context(|| {
        // Don't clean up staging file on rename failure - user may want to recover it
        format!(
            "Failed to rename staging file {:?} to {:?}",
            staging_path, final_path
        )
    })?;

    // Sync parent directory again to persist the rename
    if let Ok(dir) = File::open(parent_dir) {
        let _ = dir.sync_all();
    }

    // Only now that everything succeeded, remove the temp file
    drop(temp_file);
    std::fs::remove_file(temp_path).context("Failed to remove temp file")?;

    Ok(())
}

/// Get the data offset in a resume temp file.
/// This is the position where actual file data starts.
/// Since metadata is always padded to PADDED_METADATA_SIZE, the offset is constant.
pub fn get_data_offset() -> u64 {
    (HEADER_PREFIX_SIZE + PADDED_METADATA_SIZE) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_temp_file_path() {
        let path = Path::new("/home/user/file.txt");
        let temp = temp_file_path(path);
        assert_eq!(
            temp,
            PathBuf::from("/home/user/file.txt.beam-rs.partial")
        );
    }

    #[test]
    fn test_resume_metadata_roundtrip() {
        let dir = tempdir().unwrap();
        let temp_path = dir.path().join("test.beam-rs.partial");

        let metadata = ResumeMetadata {
            checksum: 0x123456789ABCDEF0,
            file_size: 1024 * 1024,
            bytes_received: 512 * 1024,
            filename: "test_file.bin".to_string(),
        };

        // Create file with metadata
        let _file = create_resume_file(&temp_path, &metadata).unwrap();
        drop(_file);

        // Read back metadata
        let resume_check = read_resume_metadata(&temp_path).unwrap().unwrap();
        assert_eq!(resume_check.metadata.checksum, metadata.checksum);
        assert_eq!(resume_check.metadata.file_size, metadata.file_size);
        assert_eq!(resume_check.metadata.filename, metadata.filename);
    }

    #[test]
    fn test_check_resume_matching() {
        let dir = tempdir().unwrap();
        let temp_path = dir.path().join("test.beam-rs.partial");

        let metadata = ResumeMetadata {
            checksum: 0xDEADBEEF,
            file_size: 2048,
            bytes_received: 1024,
            filename: "test.bin".to_string(),
        };

        let _file = create_resume_file(&temp_path, &metadata).unwrap();
        drop(_file);

        // Check with matching checksum/size
        let result = check_resume(&temp_path, 0xDEADBEEF, 2048).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_check_resume_mismatched_checksum() {
        let dir = tempdir().unwrap();
        let temp_path = dir.path().join("test.beam-rs.partial");

        let metadata = ResumeMetadata {
            checksum: 0xDEADBEEF,
            file_size: 2048,
            bytes_received: 1024,
            filename: "test.bin".to_string(),
        };

        let _file = create_resume_file(&temp_path, &metadata).unwrap();
        drop(_file);

        // Check with different checksum - should return None and delete temp file
        let result = check_resume(&temp_path, 0xCAFEBABE, 2048).unwrap();
        assert!(result.is_none());
        assert!(!temp_path.exists());
    }

    #[test]
    fn test_finalize_resume_file() {
        let dir = tempdir().unwrap();
        let temp_path = dir.path().join("test.beam-rs.partial");
        let final_path = dir.path().join("test_final.bin");

        let metadata = ResumeMetadata {
            checksum: 0x12345678,
            file_size: 100,
            bytes_received: 100,
            filename: "test.bin".to_string(),
        };

        // Create temp file with metadata and some data
        let mut file = create_resume_file(&temp_path, &metadata).unwrap();
        let test_data = b"Hello, World! This is test data for the file.";
        file.write_all(test_data).unwrap();
        file.flush().unwrap();

        let data_offset = get_data_offset();

        // Finalize
        finalize_resume_file(file, &temp_path, &final_path, data_offset).unwrap();

        // Verify final file contains only the data
        let final_contents = std::fs::read(&final_path).unwrap();
        assert_eq!(final_contents, test_data);
        assert!(!temp_path.exists());
    }
}
