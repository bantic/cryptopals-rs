pub trait Serialize {
    fn to_hex(&self) -> String;
}

fn decimal_2_hex(v: u8) -> char {
    char::from_digit(v.into(), 16).unwrap()
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
