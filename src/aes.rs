use crate::{xor::Xor, MyResult};
use openssl::symm::{decrypt, encrypt, Cipher};
use std::{error, fmt, iter::once};

pub enum Mode {
    CBC,
    ECB,
}

#[derive(Debug)]
enum AesError {
    IvNotAllowed,
    IvRequired,
}

impl error::Error for AesError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl fmt::Display for AesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AesError::IvNotAllowed => write!(f, "iv not allowed in this mode"),
            AesError::IvRequired => write!(f, "iv must be supplied in this mode"),
        }
    }
}

pub trait Decrypt {
    fn decrypt(&self, mode: Mode, key: &[u8], iv: Option<&[u8]>) -> MyResult<Vec<u8>>;
}

impl Decrypt for [u8] {
    fn decrypt(&self, mode: Mode, key: &[u8], iv: Option<&[u8]>) -> MyResult<Vec<u8>> {
        match mode {
            Mode::CBC => match iv {
                Some(iv) => Ok(aes_128_cbc_decrypt(self, key, iv)),
                None => Err(Box::new(AesError::IvRequired)),
            },
            Mode::ECB => match iv {
                Some(_) => Err(Box::new(AesError::IvNotAllowed)),
                None => Ok(aes_128_ecb_decrypt(self, key)),
            },
        }
    }
}

pub fn has_repeating_block(data: &[u8], size: usize) -> bool {
    if data.len() % size != 0 {
        panic!("unexpected size of repeating block check");
    }
    let chunks = data.chunks(size).collect::<Vec<&[u8]>>();
    let len = chunks.len();
    for i in 0..len {
        for j in (i + 1)..len {
            if chunks[i] == chunks[j] {
                return true;
            }
        }
    }
    false
}

fn aes_128_ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    decrypt(Cipher::aes_128_ecb(), key, None, ciphertext).unwrap()
}

pub fn pkcs7_pad(input: &[u8], size: usize) -> Vec<u8> {
    let rem_size = size - (input.len() - size * (input.len() / size));
    let pad_len = if rem_size == 0 { size } else { rem_size };
    let pad_byte = pad_len as u8;
    let mut input = input.to_vec();
    input.extend_from_slice(&vec![pad_byte; pad_len]);
    input
}

#[test]
fn test_pkcs7_pad() {
    let input = b"YELLOW SUBMARINE";
    let block = pkcs7_pad(input, 20);
    assert_eq!(block, b"YELLOW SUBMARINE\x04\x04\x04\x04");

    let input = b"YELLOW SUBMARINEYELLOW SUBMA";
    let block = pkcs7_pad(input, 16);
    assert_eq!(block, b"YELLOW SUBMARINEYELLOW SUBMA\x04\x04\x04\x04");

    let input = b"YELLOW SUBMARINE";
    let block = pkcs7_pad(input, 16);
    let expected =
        b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";
    assert_eq!(expected.len(), 32);
    assert_eq!(block, expected);

    let input = b"YELLOW SUB";
    let block = pkcs7_pad(input, 16);
    let expected = b"YELLOW SUB\x06\x06\x06\x06\x06\x06";
    assert_eq!(expected.len(), 16);
    assert_eq!(block, expected);
}

#[cfg(test)]
fn pkcs7_unpad(input: &[u8], block_size: usize) -> Vec<u8> {
    let mut output = input.to_vec();
    pkcs7_unpad_inplace(&mut output, block_size);
    output
}

fn pkcs7_unpad_inplace(input: &mut Vec<u8>, block_size: usize) {
    let last = input[input.len() - 1];
    if last as usize > block_size {
        panic!("Cannot unpad value with too-large final byte: {}", last);
    }
    for end_offset in 1..=last {
        let byte = input[input.len() - end_offset as usize];
        if byte != last {
            panic!("Bad pkc7 padding byte: {}, should be: {}", byte, last);
        }
    }
    let len = input.len();
    input.truncate(len - last as usize);
}

#[test]
fn test_pkcs7_unpad_inplace() {
    let input = b"YELLOW SUBMARINE".to_vec();
    assert_eq!(input, pkcs7_unpad(&pkcs7_pad(&input, 16), 16));
    assert_eq!(input, pkcs7_unpad(&pkcs7_pad(&input, 20), 20));

    let input = b"YELLOW SUBMARINEYELLOW SUBMAR".to_vec();
    assert_eq!(input, pkcs7_unpad(&pkcs7_pad(&input, 16), 16));
    assert_eq!(input, pkcs7_unpad(&pkcs7_pad(&input, 20), 20));
}

fn aes_128_encrypt_block(block: &[u8], key: &[u8], block_size: usize) -> Vec<u8> {
    let mut ciphertext = encrypt(Cipher::aes_128_ecb(), key, None, block).unwrap();
    ciphertext.truncate(block_size);
    ciphertext
}

fn aes_128_decrypt_block(block: &[u8], key: &[u8], block_size: usize) -> Vec<u8> {
    let padding = &pkcs7_pad(&[], block_size);
    let padding = aes_128_encrypt_block(padding, key, block_size);
    let mut input = block.to_vec();
    input.extend_from_slice(&padding);
    decrypt(Cipher::aes_128_ecb(), key, None, &input).unwrap()
}

fn aes_128_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 16;
    if ciphertext.len() % BLOCK_SIZE != 0 {
        panic!("ciphertext is not multiple of block size");
    }
    let mut plaintext: Vec<u8> = Vec::new();
    let ivs = once(iv).chain(ciphertext.chunks(BLOCK_SIZE));
    let blocks = ciphertext.chunks(BLOCK_SIZE);
    for (iv, block) in ivs.zip(blocks) {
        let decrypted = aes_128_decrypt_block(block, key, BLOCK_SIZE);
        plaintext.extend_from_slice(&decrypted.xor(iv));
    }

    pkcs7_unpad_inplace(&mut plaintext, BLOCK_SIZE);
    plaintext
}
