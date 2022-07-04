use crate::BASE_64_ALPHABET;
use crate::BASE_64_PAD;

pub trait Serialize {
    fn to_hex(&self) -> String;
    fn to_base64(&self) -> String;
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
            .flat_map(|byte| {
                [
                    char::from_digit((byte >> 4) as u32, 16).unwrap(),
                    char::from_digit((byte & 0b00001111) as u32, 16).unwrap(),
                ]
            })
            .collect()
    }

    fn to_base64(&self) -> String {
        let mut chars: Vec<char> = self
            .chunks(3)
            .flat_map(chunk_to_base64_digits)
            .map(|digit| BASE_64_ALPHABET[digit as usize])
            .collect();
        match self.len() % 3 {
            0 => (),
            1 => {
                // final 2 chars will be 0 ("A" in base64 but should be padding chars)
                chars.pop();
                chars.pop();
                chars.push(BASE_64_PAD);
                chars.push(BASE_64_PAD);
            }
            2 => {
                // final 1 char will be 0 ("A" in base64 but should be padding chars)
                chars.pop();
                chars.push(BASE_64_PAD);
            }
            _ => (),
        };
        chars.iter().collect()
    }
}

fn chunk_to_base64_digits(chunk: &[u8]) -> Vec<u8> {
    let [a, b, c] = match *chunk {
        [a, b, c] => [a, b, c],
        [a, b] => [a, b, 0],
        [a] => [a, 0, 0],
        _ => panic!("unexpected chunk {:?}", chunk),
    };

    // https://en.wikipedia.org/wiki/Base64#Base64_table_from_RFC_4648
    vec![
        (a & 0b11111100) >> 2,                             // upper 6 of a
        ((a & 0b00000011) << 4) | ((b & 0b11110000) >> 4), // lower 2 of a, upper 4 of b
        ((b & 0b00001111) << 2) | ((c & 0b11000000) >> 6), // lower 4 of b, upper 2 of c
        (c & 0b00111111),                                  // lower 6 of c
    ]
}

#[test]
fn test_chunk_to_base64_digits() {
    assert_eq!(chunk_to_base64_digits(&[0x4d, 0x61, 0x6e]), [19, 22, 5, 46]);
    assert_eq!(chunk_to_base64_digits(&[0x4d, 0x61, 0]), [19, 22, 4, 0]);
    assert_eq!(chunk_to_base64_digits(&[0x4d, 0, 0]), [19, 16, 0, 0]);
}

#[test]
fn test_to_base64() {
    assert_eq!(&[0x4d, 0x61, 0x6e].to_base64(), "TWFu");
    assert_eq!(&[0x4d, 0x61].to_base64(), "TWE=");
    assert_eq!(&[0x4d].to_base64(), "TQ==");

    // See: https://en.wikipedia.org/wiki/Base64#Output_padding
    assert_eq!(
        // "light w"
        &[0x6c, 0x69, 0x67, 0x68, 0x74, 0x20, 0x77].to_base64(),
        "bGlnaHQgdw=="
    );
    assert_eq!(
        // "light wo"
        &[0x6c, 0x69, 0x67, 0x68, 0x74, 0x20, 0x77, 0x6f].to_base64(),
        "bGlnaHQgd28="
    );
    assert_eq!(
        // "light wor"
        &[0x6c, 0x69, 0x67, 0x68, 0x74, 0x20, 0x77, 0x6f, 0x72].to_base64(),
        "bGlnaHQgd29y"
    );
}
