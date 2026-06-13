//! AES-256-GCM encryption module for application-layer payload protection.
//!
//! beam-rs always encrypts headers and chunks with AES-256-GCM before
//! sending over any transport. This provides consistent end-to-end protection
//! regardless of the underlying protocol.
//!
//! # Nonce Strategy
//!
//! Each encryption call generates a fresh random 96-bit nonce. This guarantees
//! nonce uniqueness even if:
//! - The same chunk_num is used multiple times (e.g., retries)
//! - Different data is encrypted with the same (key, chunk_num)
//! - Control signals are sent multiple times
//!
//! The nonce is transmitted with the ciphertext (first 12 bytes), and the
//! receiver uses it directly for decryption. GCM's authentication tag ensures
//! integrity - any tampering of nonce or ciphertext causes decryption failure.
//!
//! # Random Nonce Limits (NIST SP 800-38D)
//!
//! Per NIST SP 800-38D, random 96-bit nonces have collision probability concerns:
//!
//! - **Conservative limit**: 2^32 (~4 billion) invocations per key
//! - **Birthday bound**: Collision probability becomes significant around 2^48 invocations
//!
//! With our 16 KB chunk size, the conservative 2^32 limit translates to:
//! - **~64 TiB (~70 TB)** of data per key before rotation is recommended
//!
//! ## Consequences of Exceeding the Limit
//!
//! If two encryptions under the same key use the same nonce (collision):
//! - **Confidentiality loss**: XOR of plaintexts is revealed
//! - **Authenticity loss**: Forgery attacks become possible
//! - **Catastrophic failure**: GCM security guarantees completely break down
//!
//! ## Recommendation
//!
//! Since beam-rs generates a fresh key per transfer session, this limit
//! applies per-transfer. A single transfer would need to exceed ~64 TiB to
//! approach the limit - far beyond typical use cases. For applications
//! transferring extremely large datasets, rotate keys well before reaching
//! this threshold, or consider deterministic IV/counter-based schemes.
//!
//! Reference: NIST Special Publication 800-38D, Section 8.3
//! <https://csrc.nist.gov/publications/detail/sp/800-38d/final>

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result};
use rand::RngCore;

pub const CHUNK_SIZE: usize = 16 * 1024; // 16KB chunks
/// Size of the AES-GCM nonce in bytes (96 bits)
pub const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16; // 128 bits

/// Generate a random 256-bit encryption key.
///
/// Must be called once per transfer session. The key should never be reused
/// across sessions.
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Encrypt data using AES-256-GCM with a random nonce.
///
/// Each call generates a fresh random 96-bit nonce, guaranteeing uniqueness
/// even with retries/retransmissions. This eliminates the risk of nonce reuse
/// which would be catastrophic for AES-GCM security.
///
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    // Generate random nonce for each encryption - guarantees uniqueness
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Format: nonce || ciphertext || tag (tag is included in ciphertext by aes-gcm)
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data using AES-256-GCM.
///
/// The nonce is extracted from the ciphertext (first 12 bytes).
/// Authentication is provided by the GCM tag - if the ciphertext is
/// tampered or the wrong key is used, decryption will fail.
///
/// Input format: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn decrypt(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE + TAG_SIZE {
        anyhow::bail!("Encrypted data too short");
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    // Extract nonce from ciphertext - use transmitted nonce directly
    let nonce_bytes = &encrypted[..NONCE_SIZE];
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = &encrypted[NONCE_SIZE..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
        .context("Authentication failed - data may be corrupted or tampered")?;

    Ok(plaintext)
}
