use std::path::Path;

use crate::{
    aes::{pkcs7_pad, Decrypt, Mode},
    serializers::base64,
    MyResult,
};

pub fn challenge9() {
    println!("SET 2 CHALLENGE 9");
    let input = b"YELLOW SUBMARINE";
    println!("{:?} padded to 20 is {:?}", input, pkcs7_pad(input, 20));
}

#[test]
fn test_challenge9() {
    let input = b"YELLOW SUBMARINE";
    assert_eq!(pkcs7_pad(input, 20), b"YELLOW SUBMARINE\x04\x04\x04\x04");
}

pub fn challenge10() -> MyResult<()> {
    println!("SET 2 CHALLENGE 10");
    let ciphertext = base64::from_file(Path::new("data/challenge10.txt"))?;
    let iv = &vec![0; 16];
    let key = b"YELLOW SUBMARINE";
    let result = ciphertext.decrypt(Mode::CBC, key, Some(iv))?;
    println!("{:?}", result);
    println!("{}", String::from_utf8_lossy(&result));
    Ok(())
}

#[test]
fn test_challenge10() -> MyResult<()> {
    use crate::utils::read_file_to_string;
    let ciphertext = base64::from_file(Path::new("data/challenge10.txt"))?;
    let iv = &vec![0; 16];
    let key = b"YELLOW SUBMARINE";
    let result = ciphertext.decrypt(Mode::CBC, key, Some(iv))?;
    let result = String::from_utf8_lossy(&result);
    let expected = read_file_to_string(Path::new("data/challenge10.actual.txt"))?;
    assert_eq!(result, expected);
    Ok(())
}
