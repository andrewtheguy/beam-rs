//! SPAKE2 handshake protocol for authenticated key exchange.
//!
//! This module provides Password-Authenticated Key Exchange (PAKE) using SPAKE2.
//! Unlike simple KDF-based key derivation, SPAKE2 prevents offline dictionary attacks -
//! an attacker who captures the network traffic cannot brute-force the passphrase offline.

use anyhow::{Context, Result};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// SPAKE2 message length for Ed25519 group
const SPAKE2_MSG_LEN: usize = 33;

/// Maximum session ID length (enforced by both initiator and responder)
const MAX_SESSION_ID_LEN: usize = 256;

/// Identity string for beam protocol (used in SPAKE2 derivation)
const IDENTITY_SENDER: &[u8] = b"beam-rs-sender";
const IDENTITY_RECEIVER: &[u8] = b"beam-rs-receiver";

/// Constant-time comparison of two byte slices.
///
/// Returns true if and only if the slices have equal length and equal contents.
/// The comparison takes the same amount of time regardless of where (or whether)
/// the slices differ, preventing timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // XOR all bytes and accumulate; result is 0 iff all bytes match
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Perform SPAKE2 handshake as initiator (receiver role in paired modes).
///
/// The receiver connects first and sends their SPAKE2 message along with
/// the session ID, then receives the sender's SPAKE2 message.
///
/// # Protocol
/// 1. Send: session_id_len (2 bytes) + session_id + spake2_msg (33 bytes)
/// 2. Receive: spake2_msg (33 bytes)
/// 3. Derive shared key
///
/// # Arguments
/// * `stream` - TCP stream to sender
/// * `secret` - PIN or copied serverless session secret
/// * `session_id` - Sender node ID for this session
///
/// # Returns
/// 32-byte shared encryption key
pub async fn handshake_as_initiator<S>(
    stream: &mut S,
    secret: &str,
    session_id: &str,
) -> Result<[u8; 32]>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Start SPAKE2 as side A (receiver)
    let (state, outbound_msg) = Spake2::<Ed25519Group>::start_a(
        &Password::new(secret.as_bytes()),
        &Identity::new(IDENTITY_RECEIVER),
        &Identity::new(IDENTITY_SENDER),
    );

    // Send: session_id_len (2 bytes BE) + session_id + spake2_msg (33 bytes)
    let session_id_bytes = session_id.as_bytes();
    if session_id_bytes.len() > MAX_SESSION_ID_LEN {
        anyhow::bail!(
            "Session ID too long: {} bytes (max: {})",
            session_id_bytes.len(),
            MAX_SESSION_ID_LEN
        );
    }
    let mut msg = Vec::with_capacity(2 + session_id_bytes.len() + SPAKE2_MSG_LEN);
    msg.extend_from_slice(&(session_id_bytes.len() as u16).to_be_bytes());
    msg.extend_from_slice(session_id_bytes);
    msg.extend_from_slice(&outbound_msg);

    stream
        .write_all(&msg)
        .await
        .context("Failed to send SPAKE2 message")?;

    // Receive peer's SPAKE2 message
    let mut peer_msg = [0u8; SPAKE2_MSG_LEN];
    stream
        .read_exact(&mut peer_msg)
        .await
        .context("Failed to receive SPAKE2 message")?;

    // Derive shared key
    let key_bytes = state
        .finish(&peer_msg)
        .map_err(|_| anyhow::anyhow!("SPAKE2 key derivation failed"))?;

    let mut key = [0u8; 32];
    if key_bytes.len() != 32 {
        anyhow::bail!("Unexpected key length: {} (expected 32)", key_bytes.len());
    }
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Perform SPAKE2 handshake as responder (sender role in paired modes).
///
/// The sender waits for the receiver to connect and send their SPAKE2 message,
/// then responds with their own SPAKE2 message.
///
/// # Protocol
/// 1. Receive: session_id_len (2 bytes) + session_id + spake2_msg (33 bytes)
/// 2. Validate session_id
/// 3. Send: spake2_msg (33 bytes)
/// 4. Derive shared key
///
/// # Arguments
/// * `stream` - TCP stream from receiver
/// * `secret` - PIN or copied serverless session secret
/// * `expected_session_id` - Expected sender node ID
///
/// # Returns
/// 32-byte shared encryption key
pub async fn handshake_as_responder<S>(
    stream: &mut S,
    secret: &str,
    expected_session_id: &str,
) -> Result<[u8; 32]>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Receive: session_id_len (2 bytes BE) + session_id + spake2_msg (33 bytes)
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read session ID length")?;
    let session_id_len = u16::from_be_bytes(len_buf) as usize;

    // Sanity check on session ID length
    if session_id_len > MAX_SESSION_ID_LEN {
        anyhow::bail!(
            "Session ID too long: {} bytes (max: {})",
            session_id_len,
            MAX_SESSION_ID_LEN
        );
    }

    let mut session_id_buf = vec![0u8; session_id_len];
    stream
        .read_exact(&mut session_id_buf)
        .await
        .context("Failed to read session ID")?;
    let session_id = String::from_utf8(session_id_buf).context("Invalid session ID encoding")?;

    // Validate session ID using constant-time comparison to prevent timing attacks
    if !constant_time_eq(session_id.as_bytes(), expected_session_id.as_bytes()) {
        anyhow::bail!("Session ID mismatch");
    }

    // Receive peer's SPAKE2 message
    let mut peer_msg = [0u8; SPAKE2_MSG_LEN];
    stream
        .read_exact(&mut peer_msg)
        .await
        .context("Failed to receive SPAKE2 message")?;

    // Start SPAKE2 as side B (sender)
    // Note: Both sides must use the same identity parameters
    let (state, outbound_msg) = Spake2::<Ed25519Group>::start_b(
        &Password::new(secret.as_bytes()),
        &Identity::new(IDENTITY_RECEIVER),
        &Identity::new(IDENTITY_SENDER),
    );

    // Send our SPAKE2 message
    stream
        .write_all(&outbound_msg)
        .await
        .context("Failed to send SPAKE2 message")?;

    // Derive shared key
    let key_bytes = state
        .finish(&peer_msg)
        .map_err(|_| anyhow::anyhow!("SPAKE2 key derivation failed"))?;

    let mut key = [0u8; 32];
    if key_bytes.len() != 32 {
        anyhow::bail!("Unexpected key length: {} (expected 32)", key_bytes.len());
    }
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_handshake_same_pin() {
        let (mut client, mut server) = duplex(1024);
        let secret = "test-pin-1234";
        let session_id = "abc123def456";

        let client_handle =
            tokio::spawn(
                async move { handshake_as_initiator(&mut client, secret, session_id).await },
            );

        let server_handle =
            tokio::spawn(
                async move { handshake_as_responder(&mut server, secret, session_id).await },
            );

        let (client_result, server_result) = tokio::join!(client_handle, server_handle);
        let client_key = client_result.unwrap().unwrap();
        let server_key = server_result.unwrap().unwrap();

        // Both sides should derive the same key
        assert_eq!(client_key, server_key);
        assert_eq!(client_key.len(), 32);
    }

    #[tokio::test]
    async fn test_handshake_wrong_pin() {
        let (mut client, mut server) = duplex(1024);
        let session_id = "abc123def456";

        let client_handle =
            tokio::spawn(
                async move { handshake_as_initiator(&mut client, "pin1", session_id).await },
            );

        let server_handle =
            tokio::spawn(
                async move { handshake_as_responder(&mut server, "pin2", session_id).await },
            );

        let (client_result, server_result) = tokio::join!(client_handle, server_handle);
        let client_key = client_result.unwrap().unwrap();
        let server_key = server_result.unwrap().unwrap();

        // Keys should be different with wrong PIN
        // (actual failure happens when trying to decrypt data)
        assert_ne!(client_key, server_key);
    }

    #[tokio::test]
    async fn test_handshake_wrong_session_id() {
        let (mut client, mut server) = duplex(1024);
        let pin = "same-pin";

        let client_handle =
            tokio::spawn(
                async move { handshake_as_initiator(&mut client, pin, "transfer-1").await },
            );

        let server_handle =
            tokio::spawn(
                async move { handshake_as_responder(&mut server, pin, "transfer-2").await },
            );

        let (client_result, server_result) = tokio::join!(client_handle, server_handle);

        let client_result = client_result.unwrap();
        let server_result = server_result.unwrap();

        // Server must fail due to session ID mismatch
        assert!(
            server_result.is_err(),
            "Expected server to fail due to session ID mismatch, got {:?}",
            server_result
        );
        let server_err = server_result.unwrap_err().to_string();
        assert!(
            server_err.contains("Session ID mismatch"),
            "Expected session ID mismatch error, got: {}",
            server_err
        );

        // Client may fail too (connection closed by server) or succeed (timing dependent)
        // The important thing is the server rejected the mismatched session ID
        let _ = client_result;
    }
}
