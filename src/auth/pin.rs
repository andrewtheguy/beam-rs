//! Short human-typable secrets used by PIN pairing.
//!
//! Nine random Crockford-base32 characters and a check character form each
//! PIN. PIN rendezvous keys are time-bucketed, while the secret used by the
//! in-band SPAKE2 exchange is the canonical PIN itself.

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::Rng;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const PIN_LEN: usize = 10;
const PIN_DATA_LEN: usize = PIN_LEN - 1;
pub const PIN_LIFETIME_SECS: u64 = 120;

const ARGON2_MEM_KIB: u32 = 64 * 1024;
const ARGON2_TIME: u32 = 3;
const ARGON2_LANES: u32 = 1;
const KDF_SALT_DOMAIN: &[u8] = b"beam-rs:pin-rendezvous:v3";

fn check_char(data: &[u8]) -> u8 {
    let mut sum = 0usize;
    for (index, byte) in data.iter().enumerate() {
        let alphabet_index = ALPHABET.iter().position(|item| item == byte).unwrap_or(0);
        sum += alphabet_index * (index + 1);
    }
    ALPHABET[sum % ALPHABET.len()]
}

pub fn generate_pin() -> String {
    let mut rng = rand::thread_rng();
    let mut output = String::with_capacity(PIN_LEN);
    while output.len() < PIN_DATA_LEN {
        output.push(ALPHABET[rng.gen_range(0..ALPHABET.len())] as char);
    }
    output.push(check_char(output.as_bytes()) as char);
    output
}

pub fn normalize_pin(input: &str) -> Option<String> {
    let mut output = String::with_capacity(PIN_LEN);
    for character in input.chars() {
        if matches!(character, ' ' | '-' | '\t') {
            continue;
        }
        let mapped = match character.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        if !ALPHABET.contains(&(mapped as u8)) {
            return None;
        }
        output.push(mapped);
        if output.len() > PIN_LEN {
            return None;
        }
    }
    if output.len() != PIN_LEN {
        return None;
    }
    let (data, check) = output.as_bytes().split_at(PIN_DATA_LEN);
    (check[0] == check_char(data)).then_some(output)
}

pub fn looks_like_pin(input: &str) -> bool {
    let canonical: Vec<char> = input
        .chars()
        .filter(|character| !matches!(character, ' ' | '-' | '\t'))
        .map(|character| match character.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        })
        .collect();
    canonical.len() == PIN_LEN
        && canonical
            .iter()
            .all(|character| ALPHABET.contains(&(*character as u8)))
}

pub fn format_pin(canonical: &str) -> String {
    if canonical.len() != PIN_LEN || !canonical.is_ascii() {
        return canonical.to_ascii_uppercase();
    }
    let midpoint = PIN_LEN / 2;
    format!("{}-{}", &canonical[..midpoint], &canonical[midpoint..])
}

pub fn current_bucket() -> u64 {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    seconds / PIN_LIFETIME_SECS
}

pub fn derive_key_material(canonical_pin: &str, bucket: u64) -> Result<[u8; 48]> {
    let params = Params::new(ARGON2_MEM_KIB, ARGON2_TIME, ARGON2_LANES, Some(48))
        .map_err(|error| anyhow::anyhow!("invalid Argon2 parameters: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salt = Vec::with_capacity(KDF_SALT_DOMAIN.len() + 8);
    salt.extend_from_slice(KDF_SALT_DOMAIN);
    salt.extend_from_slice(&bucket.to_be_bytes());
    let mut output = [0u8; 48];
    argon2
        .hash_password_into(canonical_pin.as_bytes(), &salt, &mut output)
        .map_err(|error| anyhow::anyhow!("Argon2 key derivation failed: {error}"))
        .context("deriving rendezvous key from PIN")?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pins_normalize() {
        for _ in 0..100 {
            let pin = generate_pin();
            assert_eq!(normalize_pin(&pin), Some(pin.clone()));
        }
    }

    #[test]
    fn normalization_accepts_grouping_case_and_lookalikes() {
        let canonical = "A11000000F";
        assert_eq!(normalize_pin("aiioo-ooooF").as_deref(), Some(canonical));
        assert_eq!(format_pin(canonical), "A1100-0000F");
    }

    #[test]
    fn formatting_leaves_invalid_lengths_and_non_ascii_unsplit() {
        assert_eq!(format_pin("short"), "SHORT");
        assert_eq!(format_pin("aaaaéaaaa"), "AAAAéAAAA");
    }

    #[test]
    fn normalization_rejects_bad_checksum() {
        let pin = generate_pin();
        let replacement = if pin.ends_with('0') { '1' } else { '0' };
        let invalid = format!("{}{replacement}", &pin[..PIN_DATA_LEN]);
        assert!(normalize_pin(&invalid).is_none());
        assert!(looks_like_pin(&invalid));
    }

    #[test]
    fn rendezvous_derivation_is_bucketed() {
        let pin = generate_pin();
        assert_eq!(
            derive_key_material(&pin, 42).unwrap(),
            derive_key_material(&pin, 42).unwrap()
        );
        assert_ne!(
            derive_key_material(&pin, 42).unwrap(),
            derive_key_material(&pin, 43).unwrap()
        );
    }
}
