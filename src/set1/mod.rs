use std::iter::zip;

use crate::{
    letter_frequency::{self, break_single_byte_xor, DecryptResult},
    serializers::{from_hex, Serialize},
    xor::Xor,
};

pub const CHALLENGE_3_INPUT: &str =
    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

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
    let bytes = from_hex(CHALLENGE_3_INPUT).unwrap();
    if let Some(dr) = letter_frequency::break_single_byte_xor(&bytes) {
        println!("key {} -> score {} -> {}", dr.key, dr.score, dr.result);
    } else {
        panic!("could not solve challenge 3");
    }
}

#[test]
fn test_challenge3() {
    assert_eq!(
        letter_frequency::break_single_byte_xor(&from_hex(CHALLENGE_3_INPUT).unwrap())
            .unwrap()
            .result,
        "Cooking MC's like a pound of bacon"
    );
}

fn solve_challenge4() -> Option<DecryptResult> {
    let input = include_str!("./data/challenge4.txt");

    input
        .lines()
        .map(str::trim_end)
        .filter_map(|line| {
            let bytes = from_hex(line).unwrap();
            break_single_byte_xor(&bytes)
        })
        .min_by_key(|decrypt_result| decrypt_result.score)
}

#[test]
fn test_challenge4() {
    assert_eq!(
        solve_challenge4(),
        Some(DecryptResult {
            score: 0,
            key: 53,
            result: "Now that the party is jumping\n".into()
        })
    );
}

pub fn challenge4() {
    println!("SET 1 CHALLENGE 4");
    if let Some(decrypt_result) = solve_challenge4() {
        println!(
            "key {} -> score {} -> {}",
            decrypt_result.key,
            decrypt_result.score,
            decrypt_result.result.trim_end()
        );
    } else {
        panic!("Could not solve challenge 4");
    }
}

const CHALLENGE_5_INPUT: &str =
    "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
const CHALLENGE_5_EXPECTED: &str= "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
const CHALLENGE_5_KEY: &str = "ICE";

#[test]
fn test_challenge5() {
    assert_eq!(solve_challenge5(), CHALLENGE_5_EXPECTED);
}

fn solve_challenge5() -> String {
    CHALLENGE_5_INPUT
        .as_bytes()
        .xor(CHALLENGE_5_KEY.as_bytes())
        .to_hex()
}

pub fn challenge5() {
    println!("SET 1 CHALLENGE 5");
    println!(
        "encode:\n\"\"\"\n{}\n\"\"\"\nwith key \"{}\" ->\n\t{}",
        CHALLENGE_5_INPUT,
        CHALLENGE_5_KEY,
        solve_challenge5()
    );
    dbg!(solve_challenge5() == CHALLENGE_5_EXPECTED);
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

pub fn challenge6() -> Result<(), String> {
    println!("SET 1 CHALLENGE 6");
    let chal_6_input = include_str!("./data/challenge6.txt");
    let chal_6_input = chal_6_input.replace('\n', "");
    let chal_6_input = crate::serializers::base64::from_base64(&chal_6_input)?;

    if let Some(key) = break_repeating_key_xor(&chal_6_input) {
        println!("{}", std::str::from_utf8(&chal_6_input.xor(&key)).unwrap());
    } else {
        eprintln!("Failed to decode!");
    }
    Ok(())
}

#[test]
fn test_challenge6() {
    let chal_6_input = include_str!("./data/challenge6.txt");
    let chal_6_input = chal_6_input.replace('\n', "");
    let chal_6_input = crate::serializers::base64::from_base64(&chal_6_input).unwrap();
    let expected = include_str!("./data/challenge6_result.txt");
    let key = break_repeating_key_xor(&chal_6_input);
    assert!(key.is_some());
    let key = key.unwrap();
    let out = std::str::from_utf8(&chal_6_input.xor(&key))
        .unwrap()
        .to_string();
    assert_eq!(out.len(), expected.len());
    assert_eq!(&out, &expected);
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

/**
 * Returns the key that breaks the input
 */
fn break_repeating_key_xor(input: &[u8]) -> Option<Vec<u8>> {
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
