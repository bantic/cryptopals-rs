use openssl::symm::{decrypt, Cipher};

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

pub fn aes_128_ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    decrypt(Cipher::aes_128_ecb(), key, None, ciphertext).unwrap()
}
