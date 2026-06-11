//! Common PIN utilities for beam transfers.
//!
//! Provides PIN generation with an unambiguous character set
//! for use across all transport modes (mDNS, Nostr PIN exchange, etc.).
//!
//! PIN format: 11 random characters + 1 checksum character (12 total).
//! The checksum detects most typos before attempting connection.
//!
//! The checksum is position-weighted (`sum of charset_index * position mod 60`),
//! which detects both single-character substitutions and transpositions in most
//! cases. However, a substitution at position `p` goes undetected when
//! `(index_delta * p) % charset_len == 0` — roughly a 1-in-12 chance per
//! position. This is acceptable for a user-facing typo check, not a
//! cryptographic integrity guarantee.

use rand::Rng;

/// Length of the PIN code in characters (11 random + 1 checksum)
pub const PIN_LENGTH: usize = 12;

/// Character set for PIN generation (alphanumeric + safe symbols).
/// Excludes easily confused characters: 0/O, 1/I/l
pub const PIN_CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz$#@+";

/// Compute checksum character for a PIN prefix.
///
/// The checksum is computed by summing each character's charset index multiplied
/// by its 1-based position, then taking modulo charset length (60) to get the
/// checksum character index. The position weighting detects transpositions
/// (e.g., "AB" vs "BA"). A single-character substitution at position `p` is
/// undetected when `(index_delta * p) % 60 == 0`, which occurs for ~1 in 12
/// possible substitutions at each position.
pub fn compute_checksum(pin_prefix: &str) -> Option<char> {
    let mut sum: usize = 0;
    for (i, c) in pin_prefix.chars().enumerate() {
        let idx = PIN_CHARSET.iter().position(|&ch| ch == c as u8)?;
        sum += idx * (i + 1);
    }
    Some(PIN_CHARSET[sum % PIN_CHARSET.len()] as char)
}

/// Validate PIN format and checksum.
///
/// Returns true if the PIN has correct length, uses only valid characters,
/// and has a valid checksum as the last character.
pub fn validate_pin(pin: &str) -> bool {
    if pin.len() != PIN_LENGTH {
        return false;
    }
    // All chars must be from charset
    if !pin.chars().all(|c| PIN_CHARSET.contains(&(c as u8))) {
        return false;
    }
    // Verify checksum (last char)
    let prefix = &pin[..PIN_LENGTH - 1];
    let expected_checksum = compute_checksum(prefix);
    let actual_checksum = pin.chars().last();
    expected_checksum == actual_checksum
}

/// Generate a random 12-character PIN with checksum.
///
/// Uses a character set that excludes easily confused characters (0/O, 1/I/l)
/// and includes uppercase, lowercase, digits, and symbols for high entropy.
/// The last character is a checksum for early typo detection.
pub fn generate_pin() -> String {
    let mut rng = rand::thread_rng();
    let prefix: String = (0..PIN_LENGTH - 1)
        .map(|_| {
            let idx = rng.gen_range(0..PIN_CHARSET.len());
            PIN_CHARSET[idx] as char
        })
        .collect();
    let checksum = compute_checksum(&prefix).unwrap();
    format!("{}{}", prefix, checksum)
}

/// Prompt user for PIN with checksum validation.
///
/// Loops on invalid PIN, pre-filling with the previous input so user can edit it.
/// Returns the validated PIN or an error if input fails.
pub fn prompt_pin() -> std::io::Result<String> {
    use crate::ui::sink;

    let mut last_input: Option<String> = None;

    loop {
        let (prompt, initial) = match &last_input {
            Some(prev) => ("Enter corrected PIN: ", prev.as_str()),
            None => ("Enter PIN: ", ""),
        };

        let line = sink()
            .prompt_line(prompt, initial)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let pin = line.trim().to_string();

        if pin.is_empty() {
            sink().info("PIN cannot be empty.");
            continue;
        }

        if !validate_pin(&pin) {
            sink().info("Invalid PIN format or checksum.");
            last_input = Some(pin);
            continue;
        }

        return Ok(pin);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_generation() {
        let pin = generate_pin();
        assert_eq!(pin.len(), PIN_LENGTH);
        // Verify all chars are from charset
        for c in pin.chars() {
            assert!(PIN_CHARSET.contains(&(c as u8)));
        }
    }

    #[test]
    fn test_pin_generation_uniqueness() {
        let pin1 = generate_pin();
        let pin2 = generate_pin();
        // Very unlikely to be the same
        assert_ne!(pin1, pin2);
    }

    #[test]
    fn test_generated_pin_has_valid_checksum() {
        // Generate multiple PINs and verify they all pass validation
        for _ in 0..100 {
            let pin = generate_pin();
            assert!(validate_pin(&pin), "Generated PIN should be valid: {}", pin);
        }
    }

    #[test]
    fn test_checksum_computation() {
        let prefix = "AAAAAAAAAAA"; // 11 chars
        let checksum = compute_checksum(prefix);
        assert!(checksum.is_some());
        // Consistent checksum for same input
        assert_eq!(checksum, compute_checksum(prefix));
    }

    #[test]
    fn test_validate_pin_wrong_length() {
        assert!(!validate_pin("short"));
        assert!(!validate_pin("this_is_way_too_long_to_be_a_pin"));
    }

    #[test]
    fn test_validate_pin_invalid_chars() {
        // Contains '0' which is not in charset
        assert!(!validate_pin("000000000000"));
        // Contains 'O' which is not in charset
        assert!(!validate_pin("OOOOOOOOOOOO"));
    }

    #[test]
    fn test_validate_pin_wrong_checksum() {
        let pin = generate_pin();
        // Corrupt the checksum (last character)
        let mut chars: Vec<char> = pin.chars().collect();
        let last_idx = chars.len() - 1;
        // Change checksum to a different valid character
        chars[last_idx] = if chars[last_idx] == '2' { '3' } else { '2' };
        let corrupted: String = chars.into_iter().collect();
        assert!(!validate_pin(&corrupted), "Corrupted PIN should be invalid");
    }

    #[test]
    fn test_validate_pin_typo_detection() {
        // Use fixed values to avoid flakiness. A typo can coincidentally produce
        // the same checksum when (index_delta * position) % charset_len == 0.
        // Each case changes a character at a different position to exercise
        // the position-weighted checksum across the full PIN length.
        let cases: &[(&str, &str)] = &[
            // (valid prefix, typo prefix) — each typo changes one character
            // pos 0: '2' (idx 0) -> 'A' (idx 8), delta*1 = 8, 8%60 != 0
            ("23456789ABC", "A3456789ABC"),
            // pos 2: '4' (idx 2) -> 'H' (idx 15), delta*3 = 39, 39%60 != 0
            ("23456789ABC", "23H56789ABC"),
            // pos 5: '7' (idx 5) -> 'Z' (idx 31), delta*6 = 156, 156%60 = 36 != 0
            ("23456789ABC", "23456Z89ABC"),
            // pos 10: 'C' (idx 10) -> 'e' (idx 36), delta*11 = 286, 286%60 = 46 != 0
            ("23456789ABC", "23456789ABe"),
            // different base prefix, pos 3: 'f' (idx 37) -> '5' (idx 3), delta*4 = -136, 136%60 = 16 != 0
            ("RNcfWs$2qTb", "RNc5Ws$2qTb"),
            // different base prefix, pos 8: '#' (idx 57) -> 'K' (idx 17), delta*9 = -360, 360%60 = 0
            // — this would NOT change the checksum, so we use 'L' (idx 18) instead:
            // delta*9 = -351, 351%60 = 51 != 0
            ("ab3+@XYZ#Kp", "ab3+@XYZLKP"),
        ];

        for (valid_prefix, typo_prefix) in cases {
            let checksum = compute_checksum(valid_prefix).unwrap();
            let pin = format!("{}{}", valid_prefix, checksum);
            assert!(validate_pin(&pin), "Base PIN should be valid: {}", pin);

            let typo_pin = format!("{}{}", typo_prefix, checksum);
            assert!(
                !validate_pin(&typo_pin),
                "PIN with typo should be invalid: {} (from {})",
                typo_pin,
                valid_prefix
            );
        }
    }
}
