use std::iter::zip;

const BASE_64_ALPHABET: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

const BASE_64_PAD: char = '=';

pub fn hex_2_base64(hex: &str) -> String {
    let out_pad_len = hex.len() % 3;
    let bits_pad_len = out_pad_len * 2;
    let mut bin = hex_2_bin(hex);
    for _ in 0..bits_pad_len {
        bin.extend([0]);
    }
    let octal = bin_2_octal(&bin);
    let b64_indices = octal
        .chunks(2)
        .map(|chunk| match chunk {
            [a, b] => 8 * a + b,
            _ => panic!("unexpected octal chunk size: {}", chunk.len()),
        })
        .collect::<Vec<u8>>();
    let mut output = b64_indices
        .iter()
        .map(|&idx| BASE_64_ALPHABET[idx as usize])
        .collect::<Vec<char>>();
    for _ in 0..out_pad_len {
        output.extend([BASE_64_PAD]);
    }
    output.into_iter().collect()
}

#[test]
fn test_hex_2_base64() {
    assert_eq!(hex_2_base64("4d616e"), "TWFu");
    assert_eq!(hex_2_base64("4d61"), "TWE=");
    assert_eq!(hex_2_base64("4d"), "TQ==");
}

#[test]
fn test_cryptopals_set_1_challenge_1() {
    assert_eq!(hex_2_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

pub fn set_1_challenge_1() {
    dbg!(hex_2_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"));
}

fn hex_2_bin(hex: &str) -> Vec<u8> {
    hex.chars()
        .map(|c| c.to_ascii_lowercase())
        .flat_map(|c| match c {
            '0' => vec![0, 0, 0, 0],
            '1' => vec![0, 0, 0, 1],
            '2' => vec![0, 0, 1, 0],
            '3' => vec![0, 0, 1, 1],
            '4' => vec![0, 1, 0, 0],
            '5' => vec![0, 1, 0, 1],
            '6' => vec![0, 1, 1, 0],
            '7' => vec![0, 1, 1, 1],
            '8' => vec![1, 0, 0, 0],
            '9' => vec![1, 0, 0, 1],
            'a' => vec![1, 0, 1, 0],
            'b' => vec![1, 0, 1, 1],
            'c' => vec![1, 1, 0, 0],
            'd' => vec![1, 1, 0, 1],
            'e' => vec![1, 1, 1, 0],
            'f' => vec![1, 1, 1, 1],
            _ => panic!("unexpected char {}", c),
        })
        .collect()
}

fn bin_2_octal(bin: &[u8]) -> Vec<u8> {
    bin.iter()
        .rev()
        .collect::<Vec<_>>()
        .chunks(3)
        .map(|chunk| match chunk {
            [&c, &b, &a] => 4 * a + 2 * b + c,
            [&c, &b] => 2 * b + c,
            [&c] => c,
            _ => panic!("unexpected size of chunk"),
        })
        .rev()
        .collect()
}

#[allow(dead_code)]
fn hex_2_octal(hex: &str) -> Vec<u8> {
    bin_2_octal(&hex_2_bin(hex))
}

#[test]
fn test_hex_2_bin() {
    assert_eq!(hex_2_bin("0"), vec![0, 0, 0, 0]);
    assert_eq!(hex_2_bin("1"), vec![0, 0, 0, 1]);
    assert_eq!(hex_2_bin("A"), vec![1, 0, 1, 0]);
    assert_eq!(hex_2_bin("a"), vec![1, 0, 1, 0]);
    assert_eq!(hex_2_bin("4D"), vec![0, 1, 0, 0, 1, 1, 0, 1]);
    assert_eq!(hex_2_bin("4d"), vec![0, 1, 0, 0, 1, 1, 0, 1]);
}

#[test]
fn test_bin_2_octal() {
    assert_eq!(bin_2_octal(&[0, 0, 1]), vec![1]);
    assert_eq!(bin_2_octal(&[0, 1, 0]), vec![2]);
    assert_eq!(bin_2_octal(&[1, 0, 0]), vec![4]);
    assert_eq!(bin_2_octal(&[1, 1, 1]), vec![7]);
    assert_eq!(bin_2_octal(&[0]), vec![0]);
    assert_eq!(bin_2_octal(&[0, 0]), vec![0]);
    assert_eq!(bin_2_octal(&[0, 0, 0]), vec![0]);
    assert_eq!(
        bin_2_octal(&[1, 0, 1, 0, 1, 1, 1, 1, 0, 0]),
        vec![1, 2, 7, 4]
    );
    assert_eq!(
        bin_2_octal(&[0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0]),
        vec![1, 2, 7, 4]
    );
    assert_eq!(
        bin_2_octal(&[0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0]),
        vec![1, 2, 7, 4]
    );
}

#[test]
fn test_hex_2_octal() {
    assert_eq!(hex_2_octal("96"), vec![2, 2, 6]);
    assert_eq!(hex_2_octal("4D"), vec![1, 1, 5]);
    assert_eq!(hex_2_octal("4d"), vec![1, 1, 5]);
    assert_eq!(hex_2_octal("4d616e"), vec![2, 3, 2, 6, 0, 5, 5, 6]);
    assert_eq!(hex_2_octal("4d61"), vec![0, 4, 6, 5, 4, 1]);
    assert_eq!(hex_2_octal("4d1fa"), vec![1, 1, 5, 0, 7, 7, 2]);
}

fn bin_2_hex(bin: &[u8]) -> String {
    bin.iter()
        .rev()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|chunk| match chunk {
            [&d, &c, &b, &a] => 8 * a + 4 * b + 2 * c + d,
            [&d, &c, &b] => 4 * b + 2 * c + d,
            [&d, &c] => 2 * c + d,
            [&d] => d,
            _ => panic!("unexpected chunk size {}", chunk.len()),
        })
        .map(decimal_2_hex)
        .rev()
        .collect()
}

#[test]
fn test_bin_2_hex() {
    assert_eq!(
        bin_2_hex(&[1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1]),
        "1c011"
    );
    assert_eq!(
        bin_2_hex(&[1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1]),
        "1c011f"
    );
}

fn decimal_2_hex(v: u8) -> char {
    match v {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        15 => 'f',
        _ => panic!("unexpected decimal {}", v),
    }
}

pub fn xor(lhs: &str, rhs: &str) -> String {
    if lhs.len() != rhs.len() {
        panic!("xor: lhs and rhs len must be equal");
    }
    let bin = zip(hex_2_bin(lhs), hex_2_bin(rhs))
        .map(|(l, r)| match (l, r) {
            (0, 0) => 0,
            (1, 0) => 1,
            (0, 1) => 1,
            (1, 1) => 0,
            _ => panic!("unexpected xor values lhs {} rhs {}", l, r),
        })
        .collect::<Vec<_>>();
    bin_2_hex(&bin)
}

pub fn set_1_challenge_2() {
    dbg!(xor(
        "1c0111001f010100061a024b53535009181c",
        "686974207468652062756c6c277320657965"
    ));
}

#[test]
fn test_cryptopals_set_1_challenge_2() {
    assert_eq!(
        xor(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965"
        ),
        "746865206b696420646f6e277420706c6179"
    );
}
