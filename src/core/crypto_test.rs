#[cfg(test)]
mod tests {
    use crate::core::crypto::{NONCE_SIZE, decrypt, encrypt, generate_key};

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let plaintext = b"Hello, World! This is a test message.";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_multiple_encryptions_decrypt_correctly() {
        // With random nonces, even same (key, plaintext) produces valid ciphertext
        let key = generate_key();
        let plaintext = b"Same data";

        let enc1 = encrypt(&key, plaintext).unwrap();
        let enc2 = encrypt(&key, plaintext).unwrap();

        // Verify nonces have the expected length
        assert!(
            enc1.len() >= NONCE_SIZE,
            "Ciphertext must contain nonce prefix"
        );
        assert!(
            enc2.len() >= NONCE_SIZE,
            "Ciphertext must contain nonce prefix"
        );

        // Random nonces must produce distinct ciphertexts for the same plaintext
        assert_ne!(enc1, enc2, "Two encryptions of the same data must differ");

        // Both must decrypt correctly (validates encryption correctness)
        assert_eq!(decrypt(&key, &enc1).unwrap(), plaintext.as_slice());
        assert_eq!(decrypt(&key, &enc2).unwrap(), plaintext.as_slice());
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = b"Secret message";

        let encrypted = encrypt(&key1, plaintext).unwrap();

        // Decrypting with wrong key should fail (GCM authentication failure)
        let result = decrypt(&key2, &encrypted);
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_tampered_ciphertext_fails_decryption() {
        let key = generate_key();
        let plaintext = b"Integrity-protected message";

        let mut encrypted = encrypt(&key, plaintext).unwrap();

        // Flip a bit in the first ciphertext byte (right after the nonce)
        encrypted[NONCE_SIZE] ^= 0x01;

        let result = decrypt(&key, &encrypted);
        assert!(
            result.is_err(),
            "Decryption of tampered ciphertext should fail"
        );
    }

    #[test]
    fn test_retry_safety() {
        // Simulates a retry scenario: encrypting different data multiple times
        // With random nonces, this is safe (no nonce reuse)
        let key = generate_key();
        let data_v1 = b"Original data";
        let data_v2 = b"Retry with different data";

        let enc1 = encrypt(&key, data_v1).unwrap();
        let enc2 = encrypt(&key, data_v2).unwrap();

        // Verify ciphertexts have nonce prefix
        assert!(
            enc1.len() >= NONCE_SIZE,
            "Ciphertext must contain nonce prefix"
        );
        assert!(
            enc2.len() >= NONCE_SIZE,
            "Ciphertext must contain nonce prefix"
        );

        // Both decrypt correctly to their respective plaintexts
        assert_eq!(decrypt(&key, &enc1).unwrap(), data_v1.as_slice());
        assert_eq!(decrypt(&key, &enc2).unwrap(), data_v2.as_slice());
    }
}
