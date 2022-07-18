fn pkcs7_pad(block: &[u8], size: usize) -> Vec<u8> {
    if block.len() > size {
        dbg!(block);
        panic!("Cannot pad block len {} to size {}", block.len(), size);
    }
    let rem_size = size - block.len();
    let pad_len = if rem_size == 0 { block.len() } else { rem_size };
    let pad_byte = pad_len as u8;
    let mut block = block.to_vec();
    block.extend_from_slice(&vec![pad_byte; pad_len]);
    block
}

#[test]
fn test_pkcs7_pad() {
    let input = b"YELLOW SUBMARINE";
    let block = pkcs7_pad(input, 20);
    assert_eq!(block, b"YELLOW SUBMARINE\x04\x04\x04\x04");

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

pub fn challenge9() {
    println!("SET 2 CHALLENGE 9");
    let input = b"YELLOW SUBMARINE";
    println!("{:?} padded to 20 is {:?}", input, pkcs7_pad(input, 20));
}
