use std::iter::zip;

pub trait Xor {
    fn xor(&self, _: &Self) -> Vec<u8>;
}

impl Xor for [u8] {
    fn xor(&self, other: &[u8]) -> Vec<u8> {
        self.chunks(other.len())
            .flat_map(|chunk| zip(chunk, other).map(|(l, r)| l ^ r))
            .collect()
    }
}

#[test]
fn test_xor() {
    assert_eq!([0].xor(&[0]), [0]);
    assert_eq!([0].xor(&[1]), [1]);
    assert_eq!([1].xor(&[0]), [1]);
    assert_eq!([1].xor(&[1]), [0]);

    assert_eq!([0, 1].xor(&[1]), [1, 0]);
    assert_eq!([0, 1, 0].xor(&[1]), [1, 0, 1]);
    assert_eq!([0].xor(&[1, 0]), [1]);

    assert_eq!([5].xor(&[1]), [4]);
    assert_eq!([5].xor(&[2]), [7]);
}
