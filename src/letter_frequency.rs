use crate::xor::Xor;
use std::{collections::HashMap, iter::zip};

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

// compute mean-squared-error, see https://statisticsbyjim.com/regression/mean-squared-error-mse/
fn compute_score(bytes: &[u8]) -> u32 {
    if !bytes.is_ascii() {
        // dbg!("returning max, not ascii");
        return u32::MAX;
    }
    if bytes
        .iter()
        .any(|&b| (b.to_ascii_lowercase().is_ascii_control()) && b != b'\n')
    {
        // dbg!("returning max, control bytes");
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

fn hamming_distance(l: &[u8], r: &[u8]) -> u32 {
    if l.len() != r.len() {
        panic!("l len {} != r len {}", l.len(), r.len());
    }

    zip(l, r).map(|(l, r)| ((l ^ r) as u32).count_ones()).sum()
}

#[test]
fn test_hamming_distance() {
    assert_eq!(
        hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()),
        37
    );
}

/**
 * Given the chunks, finds the hamming distance between each of them,
 * averages those distances, and then normalizes by the size of each chunk
 */
fn normalized_hamming_distance(chunks: &[&[u8]]) -> f32 {
    let len = chunks.len();
    let size = chunks[0].len();

    if !chunks
        .iter()
        .map(|chunk| chunk.len())
        .all(|chunk_len| chunk_len == size)
    {
        panic!("Unexpectedly found differently-sized chunks for normalized_hamming_distance");
    }

    let mut dists = Vec::new();
    for i in 0..len {
        for j in (i + 1)..len {
            let l = chunks[i];
            let r = chunks[j];
            dists.push(hamming_distance(l, r));
        }
    }
    let sum: u32 = dists.iter().sum::<u32>();
    let avg_dist = sum as f32 / dists.len() as f32;
    avg_dist / size as f32
}

/**
 * return `size` number of blocks from `input`, where the first block contains the 0th byte, the size-th byte, the 2*size-th byte,
 * the second block contains the 1st byte, the size+1st byte, the 2*size+1st byte, etc.
 * The final block returned may be shorter than the others.
 */
fn transpose_input(input: &[u8], size: usize) -> Vec<Vec<u8>> {
    (0..size)
        .map(|offset| input.iter().skip(offset).step_by(size).copied().collect())
        .collect()
}

#[test]
fn test_transpose() {
    assert_eq!(
        transpose_input(&[0, 2, 3, 4, 1, 2, 3, 4], 4),
        [[0, 1], [2, 2], [3, 3], [4, 4],]
    );
    assert_eq!(
        transpose_input(&[1, 2, 3, 4, 1, 2, 3, 4], 2),
        [[1, 3, 1, 3], [2, 4, 2, 4]]
    );
    assert_eq!(
        transpose_input(&[1, 2, 3, 4, 1, 2, 3, 4], 3),
        vec![vec![1, 4, 3], vec![2, 1, 4], vec![3, 2]] // use vec! to fix type error since sub-arrays are different size
    );
    assert_eq!(
        transpose_input(&[1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5], 5),
        [[1, 1, 1], [2, 2, 2], [3, 3, 3], [4, 4, 4], [5, 5, 5]]
    );
    assert_eq!(
        transpose_input(
            &vec![1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]
                .iter()
                .cycle()
                .take(35)
                .copied()
                .collect::<Vec<u8>>(),
            7
        ),
        [
            [1, 1, 1, 1, 1],
            [2, 2, 2, 2, 2],
            [3, 3, 3, 3, 3],
            [4, 4, 4, 4, 4],
            [5, 5, 5, 5, 5],
            [6, 6, 6, 6, 6],
            [7, 7, 7, 7, 7]
        ]
    );
}

/**
 * Find possible key sizes for repeating-key xor.
 * Returns all considered keysizes in descending order of likelihood
 */
pub fn find_keysize(input: &[u8]) -> Vec<(f32, usize)> {
    let max_keysize = (40usize).min(input.len() / 4);
    let rng = 2..=max_keysize;
    let mut possibilities = rng
        .map(|keysize| {
            let chunks = input.chunks(keysize).take(4).collect::<Vec<&[u8]>>();
            (normalized_hamming_distance(&chunks), keysize)
        })
        .collect::<Vec<(f32, usize)>>();
    possibilities.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    possibilities
}

/**
 * Returns the key that breaks the input
 */
pub fn break_repeating_key_xor(input: &[u8]) -> Option<Vec<u8>> {
    let possible_keysizes = find_keysize(input);

    possible_keysizes.iter().find_map(|&(_dist, keysize)| {
        let blocks = transpose_input(input, keysize);
        if blocks.iter().any(|block| !block.is_ascii()) {
            return None;
        }
        let mut key_bytes: Vec<u8> = Vec::new();
        for block in blocks {
            dbg!(block.len());
            let res = break_single_byte_xor(&block).unwrap();
            if res.score == u32::MAX {
                return None;
            }
            key_bytes.push(res.key);
            dbg!(res.key, res.score);
        }
        Some(key_bytes)
    })
}
