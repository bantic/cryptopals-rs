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
        println!("score {}, key {} -> {}", dr.score, dr.key, dr.result);
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
        println!("!!!!!! Failed");
    }
}
