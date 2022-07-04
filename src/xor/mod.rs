use std::iter::zip;

pub trait Xor {
    fn xor(&self, _: &Self) -> Vec<u8>;
}

impl Xor for [u8] {
    fn xor(&self, other: &[u8]) -> Vec<u8> {
        zip(self, other.iter().cycle())
            .map(|(l, r)| l ^ r)
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

    assert_eq!([5].xor(&[1, 0]), [4]);
    assert_eq!([5].xor(&[2]), [7]);
    assert_eq!([5, 5, 5].xor(&[2, 2, 2]), [7, 7, 7]);
    assert_eq!([5, 5, 5].xor(&[2, 2, 2, 0]), [7, 7, 7]);
}
