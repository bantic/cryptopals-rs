use std::iter::zip;

pub trait Xor {
    fn xor(&self, _: &Self) -> Self;
}

impl Xor for Vec<u8> {
    fn xor(&self, other: &Self) -> Self {
        if self.len() != other.len() {
            panic!("xor: lhs and rhs len must be equal");
        }
        zip(self, other).map(|(l, r)| l ^ r).collect()
    }
}
