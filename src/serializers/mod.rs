use crate::{utils::read_file_to_string, MyResult};
use std::path::Path;

pub mod base64;

pub trait Serialize {
    fn to_hex(&self) -> String;
    fn to_base64(&self) -> String;
}

pub fn from_hex(s: &str) -> MyResult<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err("Hex string must be even length".into());
    }
    let mut digits = Vec::new();
    for c in s.chars() {
        digits.push(u8_from_hex_char(c)?);
    }
    Ok(digits.chunks(2).map(|c| (c[0] << 4) + c[1]).collect())
}

pub fn from_hex_lines(s: &str) -> MyResult<Vec<Vec<u8>>> {
    s.lines().map(str::trim_end).map(from_hex).collect()
}

pub fn from_hex_lines_path(path: &Path) -> MyResult<Vec<Vec<u8>>> {
    from_hex_lines(&read_file_to_string(path)?)
}

fn u8_from_hex_char(c: char) -> MyResult<u8> {
    match c.to_digit(16) {
        Some(i) => Ok(i as u8),
        _ => Err(format!("Could not convert hex char {} to digit", c).into()),
    }
}

#[test]
fn test_from_hex() -> MyResult<()> {
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
        base64::to_base64(self)
    }
}
