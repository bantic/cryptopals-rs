use std::collections::HashMap;

use crate::{
    serializers::{from_hex, Serialize},
    xor::Xor,
};

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

pub fn challenge1() {
    println!("SET 1 CHALLENGE 1");
    dbg!(from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap().to_base64() == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

#[test]
fn test_challenge1() {
    assert_eq!(from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap().to_base64(), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

pub fn challenge2() {
    println!("SET 1 CHALLENGE 2");
    dbg!(
        from_hex("1c0111001f010100061a024b53535009181c")
            .unwrap()
            .xor(&from_hex("686974207468652062756c6c277320657965").unwrap())
            .to_hex()
            == "746865206b696420646f6e277420706c6179"
    );
}

#[test]
fn test_challenge2() {
    assert_eq!(
        from_hex("1c0111001f010100061a024b53535009181c")
            .unwrap()
            .xor(&from_hex("686974207468652062756c6c277320657965").unwrap())
            .to_hex(),
        "746865206b696420646f6e277420706c6179"
    );
}

pub fn challenge3() {
    println!("SET 1 CHALLENGE 3");
    if let Some((_score, key, result)) = break_single_byte_xor(INPUT) {
        println!("score {}, key {} -> {}", _score, key, result);
    } else {
        panic!("could not solve challenge 3");
    }
}

#[test]
fn test_challenge3() {
    assert_eq!(
        break_single_byte_xor(INPUT).unwrap().2,
        "Cooking MC's like a pound of bacon"
    );
}

fn break_single_byte_xor(s: &str) -> Option<(u32, u8, String)> {
    (0u8..=255)
        .map(|b| {
            let out_bytes = from_hex(s).unwrap().xor(&[b]);
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
