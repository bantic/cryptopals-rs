use openssl::symm::{decrypt, Cipher};

use crate::{
    letter_frequency::{self, break_repeating_key_xor, break_single_byte_xor, DecryptResult},
    serializers::{base64::from_base64, from_hex, Serialize},
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

fn aes_128_ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    decrypt(Cipher::aes_128_ecb(), key, None, ciphertext).unwrap()
}

pub fn challenge7() {
    println!("SET 1 CHALLENGE 7");
    let key = "YELLOW SUBMARINE".as_bytes();
    let b64 = include_str!("./data/challenge7.txt").replace('\n', "");
    let ciphertext = from_base64(&b64).unwrap();
    let plaintext = aes_128_ecb_decrypt(&ciphertext, key);
    println!("{:?}", plaintext);
    println!("{:?}", String::from_utf8_lossy(&plaintext));
}

#[test]
fn test_challenge7() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let b64 = include_str!("./data/challenge7.txt").replace('\n', "");
    let ciphertext = from_base64(&b64).unwrap();
    let plaintext = aes_128_ecb_decrypt(&ciphertext, key);
    let expected = include_bytes!("./data/challenge7.actual.txt");
    assert_eq!(plaintext, expected);
}

fn has_repeating_block(data: &[u8], size: usize) -> bool {
    if data.len() % size != 0 {
        panic!("unexpected size of repeating block check");
    }
    let chunks = data.chunks(size).collect::<Vec<&[u8]>>();
    let len = chunks.len();
    for i in 0..len {
        for j in (i + 1)..len {
            if chunks[i] == chunks[j] {
                return true;
            }
        }
    }
    false
}

pub fn challenge8() {
    println!("SET 1 CHALLENGE 8");
    let ciphertexts = include_str!("./data/challenge8.txt")
        .lines()
        .map(|l| l.trim())
        .map(from_hex)
        .map(|r| r.unwrap())
        .collect::<Vec<Vec<u8>>>();
    for ciphertext in ciphertexts {
        if has_repeating_block(&ciphertext, 16) {
            println!(
                "found one with repeats! {:?}: {}",
                ciphertext,
                ciphertext.to_hex()
            );
        }
    }
}

#[test]
fn test_challenge8() {
    let ciphertexts = include_str!("./data/challenge8.txt")
        .lines()
        .map(|l| l.trim())
        .map(from_hex)
        .map(|r| r.unwrap())
        .collect::<Vec<Vec<u8>>>();
    let repeat = ciphertexts
        .iter()
        .find(|&l| has_repeating_block(l, 16))
        .map(|l| l.to_hex());
    assert_eq!(repeat, Some("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a".into()));
}
