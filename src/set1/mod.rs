use crate::{
    aes::{has_repeating_block, Decrypt, Mode},
    letter_frequency::{self, break_repeating_key_xor, break_single_byte_xor, DecryptResult},
    serializers::{base64, from_hex, from_hex_lines_path, Serialize},
    xor::Xor,
    MyResult,
};
use std::path::Path;

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
    let input = from_hex_lines_path(Path::new("data/challenge4.txt")).unwrap();

    input
        .iter()
        .filter_map(|bytes| break_single_byte_xor(bytes))
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

pub fn challenge6() -> MyResult<()> {
    println!("SET 1 CHALLENGE 6");
    let chal_6_input = crate::serializers::base64::from_file(Path::new("data/challenge6.txt"))?;

    if let Some(key) = break_repeating_key_xor(&chal_6_input) {
        println!("{}", std::str::from_utf8(&chal_6_input.xor(&key)).unwrap());
    } else {
        eprintln!("Failed to decode!");
    }
    Ok(())
}

#[test]
fn test_challenge6() {
    let chal_6_input =
        crate::serializers::base64::from_file(Path::new("./data/challenge6.txt")).unwrap();
    let expected =
        crate::utils::read_file_to_string(Path::new("./data/challenge6.actual.txt")).unwrap();
    let key = break_repeating_key_xor(&chal_6_input);
    assert!(key.is_some());
    let key = key.unwrap();
    let out = std::str::from_utf8(&chal_6_input.xor(&key))
        .unwrap()
        .to_string();
    assert_eq!(out.len(), expected.len());
    assert_eq!(&out, &expected);
}

pub fn challenge7() -> MyResult<()> {
    println!("SET 1 CHALLENGE 7");
    let key = "YELLOW SUBMARINE".as_bytes();
    let ciphertext = base64::from_file(Path::new("data/challenge7.txt"))?;
    let plaintext = ciphertext.decrypt(Mode::ECB, key, None)?;
    println!("{}", String::from_utf8(plaintext)?);
    Ok(())
}

#[test]
fn test_challenge7() -> MyResult<()> {
    let key = "YELLOW SUBMARINE".as_bytes();
    let ciphertext = base64::from_file(Path::new("data/challenge7.txt"))?;
    let plaintext = ciphertext.decrypt(Mode::ECB, key, None)?;
    let plaintext = String::from_utf8(plaintext)?;
    let expected = crate::utils::read_file_to_string(Path::new("./data/challenge7.actual.txt"))?;
    assert_eq!(plaintext, expected);
    Ok(())
}

pub fn challenge8() -> MyResult<()> {
    println!("SET 1 CHALLENGE 8");
    let ciphertexts = from_hex_lines_path(Path::new("data/challenge8.txt"))?;
    let repeat = ciphertexts
        .iter()
        .find(|&l| has_repeating_block(l, 16))
        .map(|l| l.to_hex());
    if let Some(s) = repeat {
        println!("Found line with repeating block: {}", s);
    } else {
        eprintln!("Failed");
    }
    Ok(())
}

#[test]
fn test_challenge8() -> MyResult<()> {
    let ciphertexts = from_hex_lines_path(Path::new("data/challenge8.txt"))?;
    let repeat = ciphertexts
        .iter()
        .find(|&l| has_repeating_block(l, 16))
        .map(|l| l.to_hex());
    assert_eq!(repeat, Some("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a".into()));
    Ok(())
}
