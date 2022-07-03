use crate::BASE_64_ALPHABET;
use crate::BASE_64_PAD;

pub trait Serialize {
    fn to_hex(&self) -> String;
    fn to_base64(&self) -> String;
}

fn decimal_2_hex(v: u8) -> char {
    char::from_digit(v.into(), 16).unwrap()
}

pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Hex string must be even length".into());
    }
    let mut digits = Vec::new();
    for c in s.chars() {
        digits.push(u8_from_hex_char(c)?);
    }
    Ok(digits.chunks(2).map(|c| (c[0] << 4) + c[1]).collect())
}

fn u8_from_hex_char(c: char) -> Result<u8, String> {
    match c.to_digit(16) {
        Some(i) => Ok(i as u8),
        _ => Err(format!("Could not convert hex char {} to digit", c)),
    }
}

#[test]
fn test_from_hex() -> Result<(), String> {
    assert_eq!(from_hex("09")?, [9]);
    assert_eq!(from_hex("0a")?, [10]);
    assert_eq!(from_hex("0b")?, [11]);
    assert_eq!(from_hex("0b0b")?, [11, 11]);
    assert_eq!(from_hex("0B0C")?, [11, 12]);
    assert_eq!(from_hex("FF00")?, [255, 0]);
    Ok(())
}

impl Serialize for [u8] {
    fn to_hex(&self) -> String {
        self.iter()
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

    fn to_base64(&self) -> String {
        unimplemented!("todo- tobase64")
    }
}

#[test]
fn test_bin_2_hex() {
    assert_eq!(
        [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1].to_hex(),
        "1c011"
    );
    assert_eq!(
        [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1].to_hex(),
        "1c011f"
    );
}
