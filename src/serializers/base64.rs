use std::collections::HashMap;

// https://en.wikipedia.org/wiki/Base64#Base64_table_from_RFC_4648
const ALPHABET: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

lazy_static! {
    static ref OCTET_TO_BASE64_SEXTET: HashMap<u8, u8> = {
        let mut m = HashMap::new();
        m.insert(0, 0);
        for (idx, &ch) in ALPHABET.iter().enumerate() {
            m.insert(ch as u8, idx as u8);
        }
        m
    };
}

const PAD: char = '=';

fn to_base64_sextet(ascii_byte: u8) -> u8 {
    *OCTET_TO_BASE64_SEXTET.get(&ascii_byte).unwrap()
}

fn bytes_from_base64_chunk(bytes: &[u8]) -> Vec<u8> {
    let mut sextets = Vec::with_capacity(4);
    let mut out: Vec<u8> = Vec::with_capacity(3);
    if let [a, b, c, d] = bytes[..4] {
        sextets.push(to_base64_sextet(a));
        sextets.push(to_base64_sextet(b));

        if c == PAD as u8 {
            if d != PAD as u8 {
                panic!("unexpectedly got non-pad byte after pad byte");
            }
            // ends in 2 pad bytes, drop both
        } else if d == PAD as u8 {
            // ends in 1 pad byte, drop last
            sextets.push(to_base64_sextet(c));
        } else {
            // no pad bytes, use all 4 sextets
            sextets.push(to_base64_sextet(c));
            sextets.push(to_base64_sextet(d));
        }

        let mut sextets = sextets.iter();
        let a = sextets.next().unwrap();
        let b = sextets.next().unwrap();

        // First octet: all bits of a + upper 2 bits of b
        out.push((a << 2) | ((b & 0b0110000) >> 4));

        if let Some(c) = sextets.next() {
            // Second octet: bottom 4 of b + upper 4 of c
            out.push(((b & 0b00001111) << 4) | (c & 0b00111100) >> 2);

            if let Some(d) = sextets.next() {
                // Third octet: bottom 2 of c + all 6 of d
                out.push(((c & 0b00000011) << 6) | d);
            }
        }

        out
    } else {
        panic!("expected 4 bytes in base64 chunk")
    }
}

pub fn from_base64(s: &str) -> Result<Vec<u8>, String> {
    if !s.is_ascii() {
        return Err("Base64 string must be ascii".into());
    }

    if s.len() % 4 != 0 {
        return Err(format!(
            "Base64 string len must be divisible by 4, but got len {}",
            s.len()
        ));
    }

    Ok(s.as_bytes()
        .chunks(4)
        .flat_map(bytes_from_base64_chunk)
        .collect::<Vec<u8>>())
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

pub fn to_base64(bytes: &[u8]) -> String {
    let mut chars: Vec<char> = bytes
        .chunks(3)
        .flat_map(chunk_to_base64_digits)
        .map(|digit| ALPHABET[digit as usize])
        .collect();
    match bytes.len() % 3 {
        0 => (),
        1 => {
            // final 2 chars will be 0 ("A" in base64 but should be padding chars)
            chars.pop();
            chars.pop();
            chars.push(PAD);
            chars.push(PAD);
        }
        2 => {
            // final 1 char will be 0 ("A" in base64 but should be padding chars)
            chars.pop();
            chars.push(PAD);
        }
        _ => (),
    };
    chars.iter().collect()
}

#[test]
fn test_from_base64() -> Result<(), String> {
    assert_eq!(from_base64("TWFu")?, [0x4d, 0x61, 0x6e]);
    assert_eq!(from_base64("TWE=")?, [0x4d, 0x61]);
    assert_eq!(from_base64("TQ==")?, [0x4d]);
    Ok(())
}

#[test]
fn test_to_from_base64() -> Result<(), String> {
    use crate::serializers::Serialize;
    use rand::random;

    fn get_random_bytes() -> Vec<u8> {
        let len = random::<f32>();
        let maxlen: u8 = 64;
        let len = (len * maxlen as f32) as usize;
        let mut out = Vec::new();
        for _ in 0..len {
            out.push(random());
        }
        out
    }

    // Test a handful of random byte vecs
    for _ in 0..100 {
        let bytes = get_random_bytes();
        assert_eq!(&from_base64(&bytes.to_base64())?, &bytes);
    }
    Ok(())
}

#[test]
fn test_chunk_to_base64_digits() {
    assert_eq!(chunk_to_base64_digits(&[0x4d, 0x61, 0x6e]), [19, 22, 5, 46]);
    assert_eq!(chunk_to_base64_digits(&[0x4d, 0x61, 0]), [19, 22, 4, 0]);
    assert_eq!(chunk_to_base64_digits(&[0x4d, 0, 0]), [19, 16, 0, 0]);
}

#[test]
fn test_to_base64() {
    use crate::serializers::Serialize;
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
