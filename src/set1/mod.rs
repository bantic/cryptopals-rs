use std::collections::HashMap;

use crate::{hex_2_bin, xor::Xor};

const INPUT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

// Source:
// Lee, E. Stewart. "Essays about Computer Security" (PDF). University of Cambridge Computer Laboratory. p. 181.
// And: https://github.com/aopicier/cryptopals-rust/blob/master/challenges/src/set1/challenge03.rs
static EXPECTED_FREQUENCIES: [(char, f32); 28] = [
    (' ', 12.17), // Whitespace
    ('.', 6.57),  // Others
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

fn char_counts(s: &str) -> HashMap<char, usize> {
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        if !c.is_ascii() {
            continue;
        }
        let c = match c.to_ascii_lowercase() {
            x if x.is_ascii_alphabetic() => x,
            ' ' | '\t' => ' ',
            _ => '.',
        };
        *counts.entry(c).or_default() += 1;
    }

    counts
}

fn score(s: &str) -> u32 {
    if s.chars().any(|c| c.is_control() || !c.is_ascii()) {
        return u32::MAX;
    }
    let counts = char_counts(s);
    let len = s.len();
    EXPECTED_FREQUENCIES.iter().fold(0f32, |acc, &(ch, freq)| {
        let expected_count = len as f32 * (freq / 100f32);
        let &actual_count = counts.get(&ch).unwrap_or(&0usize);
        acc + (expected_count - actual_count as f32).powi(2)
    }) as u32
}

fn bin_2_decimal(bin: &[u8]) -> u8 {
    bin.iter()
        .rev()
        .enumerate()
        .fold(0, |acc, (idx, v)| acc + (v * (1 << idx)))
}

#[test]
fn test_bin_2_decimal() {
    assert_eq!(bin_2_decimal(&[0]), 0);
    assert_eq!(bin_2_decimal(&[1]), 1);
    assert_eq!(bin_2_decimal(&[1, 0]), 2);
    assert_eq!(bin_2_decimal(&[1, 1]), 3);
    assert_eq!(bin_2_decimal(&[1, 1, 1]), 7);
    assert_eq!(bin_2_decimal(&[1, 0, 0, 0]), 8);
    assert_eq!(bin_2_decimal(&[1, 0, 0, 1]), 9);
}

fn hex_2_bytes(hex: &str) -> Vec<u8> {
    hex_2_bin(hex).chunks(8).map(bin_2_decimal).collect()
}

fn hex_2_utf8(hex: &str) -> Option<String> {
    let bytes = hex_2_bytes(hex);
    let res = std::str::from_utf8(&bytes);
    if let Ok(out) = res {
        Some(out.into())
    } else {
        None
    }
}

#[test]
fn test_hex_2_bytes() {
    assert_eq!(hex_2_bytes("0"), [0]);
    assert_eq!(hex_2_bytes("1"), [1]);
    assert_eq!(hex_2_bytes("9"), [9]);
    assert_eq!(hex_2_bytes("A"), [10]);
    assert_eq!(hex_2_bytes("10"), [16]);
    assert_eq!(hex_2_bytes("80"), [128]);
    assert_eq!(hex_2_bytes("8010"), [128, 16]);
}

pub fn challenge3() {
    println!("SET 1 CHALLENGE 3");
    if let Some((_score, key, result)) = break_single_byte_xor(INPUT) {
        println!("score {}, key {} -> {}", _score, key, result);
    } else {
        panic!("could not solve challenge 3");
    }
}

fn xor_hex_str_by_byte(s: &str, b: u8) -> Vec<u8> {
    let in_bytes = hex_2_bytes(s);
    let b_xor = vec![b; in_bytes.len()];
    in_bytes.xor(&b_xor)
}

fn break_single_byte_xor(s: &str) -> Option<(u32, u8, String)> {
    (0u8..=255)
        .map(|b| {
            let out_bytes = xor_hex_str_by_byte(s, b);
            let (_score, out_s) = match std::str::from_utf8(&out_bytes) {
                Ok(v) => (score(v), v),
                _ => (u32::MAX, ""),
            };
            (_score, b, out_s.to_string())
        })
        .min_by_key(|(_score, _, _)| *_score)
}

pub fn challenge4() {
    println!("SET 1 CHALLENGE 4");
    let input = include_str!("./data/challenge4.txt");
    for line in input.lines() {
        if let Some((_score, key, result)) = break_single_byte_xor(line) {
            if _score < u32::MAX {
                println!(
                    "line {} -> score {}, key {} -> {}",
                    line, _score, key, result
                );
            }
        }
    }
}
