use crate::xor::Xor;
use std::collections::HashMap;

// Source:
// Lee, E. Stewart. "Essays about Computer Security" (PDF). University of Cambridge Computer Laboratory. p. 181.
// And: https://github.com/aopicier/cryptopals-rust/blob/master/challenges/src/set1/challenge03.rs
// Other sources:
//  - http://www.macfreek.nl/memory/Letter_Distribution
//  - http://www.fitaly.com/board/domper3/posts/136.html
//  - http://norvig.com/mayzner.html
//  - https://en.wikipedia.org/wiki/Letter_frequency
static EXPECTED_FREQUENCIES: [(char, f32); 29] = [
    (' ', 12.17), // Whitespace
    ('.', 6.57),  // Others
    ('#', 0.5), // Digits, I just guessed at the percentage, the '#' is a placeholder for any digit
    ('a', 6.09),
    ('b', 1.05),
    ('c', 2.84),
    ('d', 2.92),
    ('e', 11.36),
    ('f', 1.79),
    ('g', 1.38),
    ('h', 3.41),
    ('i', 5.44),
    ('j', 0.24),
    ('k', 0.41),
    ('l', 2.92),
    ('m', 2.76),
    ('n', 5.44),
    ('o', 6.00),
    ('p', 1.95),
    ('q', 0.24),
    ('r', 4.95),
    ('s', 5.68),
    ('t', 8.03),
    ('u', 2.43),
    ('v', 0.97),
    ('w', 1.38),
    ('x', 0.24),
    ('y', 1.30),
    ('z', 0.03),
];

fn count_chars(bytes: &[u8]) -> HashMap<char, usize> {
    let mut counts: HashMap<char, usize> = HashMap::new();
    for byte in bytes.to_ascii_lowercase() {
        if !byte.is_ascii() {
            continue;
        }
        if byte.is_ascii_control() {
            continue;
        }
        if let Some(byte) = match byte {
            x if x.is_ascii_alphabetic() => Some(x),
            x if x.is_ascii_punctuation() => Some(b'.'),
            x if x.is_ascii_whitespace() => Some(b' '),
            x if x.is_ascii_digit() => Some(b'#'),
            _ => panic!("unexpected byte {}", byte),
        } {
            *counts.entry(byte as char).or_insert(0) += 1;
        }
    }
    counts
}

fn is_control(byte: u8) -> bool {
    byte < 0x20 || byte == 0x7F
}

// compute mean-squared-error, see https://statisticsbyjim.com/regression/mean-squared-error-mse/
fn compute_score(bytes: &[u8]) -> u32 {
    if !bytes.is_ascii() {
        return u32::MAX;
    }
    if bytes.iter().any(|&b| is_control(b) && b != b'\n') {
        return u32::MAX;
    }
    let counts = count_chars(bytes);
    let len = bytes.len();
    (EXPECTED_FREQUENCIES.iter().fold(0f32, |acc, &(ch, freq)| {
        let expected = len as f32 * (freq / 100.0);
        let &actual = counts.get(&ch).unwrap_or(&0);
        acc + (expected - actual as f32).powi(2)
    }) / len as f32) as u32
}

#[derive(Debug, PartialEq)]
pub struct DecryptResult {
    pub score: u32,
    pub key: u8,
    pub result: String,
}

pub fn break_single_byte_xor(bytes: &[u8]) -> Option<DecryptResult> {
    let all_bytes = 0u8..=255;
    if let Some((score, key, decoded_bytes)) = all_bytes
        .map(|key| {
            let decoded_bytes = bytes.xor(&[key]);
            let score = compute_score(&decoded_bytes);
            (score, key, decoded_bytes)
        })
        .min_by_key(|&(score, _, _)| score)
    {
        if let Ok(result) = std::str::from_utf8(&decoded_bytes) {
            Some(DecryptResult {
                score,
                key,
                result: result.into(),
            })
        } else {
            None
        }
    } else {
        None
    }
}
