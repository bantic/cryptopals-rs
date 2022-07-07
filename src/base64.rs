// https://en.wikipedia.org/wiki/Base64#Base64_table_from_RFC_4648
pub const ALPHABET: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

pub const PAD: char = '=';

pub fn to_base64_sextet(ascii_byte: u8) -> u8 {
    let ch = ascii_byte as char;
    ALPHABET.iter().position(|&x| x == ch).unwrap() as u8
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

    for _ in 0..10 {
        let bytes = get_random_bytes();
        assert_eq!(&from_base64(&bytes.to_base64())?, &bytes);
    }
    Ok(())
}
