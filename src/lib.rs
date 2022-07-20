#[macro_use]
extern crate lazy_static;

pub mod aes;
pub mod letter_frequency;
pub mod serializers;
pub mod xor;

pub mod set1;
pub mod set2;

pub type MyResult<T> = Result<T, Box<dyn std::error::Error>>;

pub mod utils {
    use crate::MyResult;
    use std::{fs::File, io::Read, path::Path};

    pub fn read_file_to_string(path: &Path) -> MyResult<String> {
        let mut f = File::open(path)?;
        let mut buf = String::new();
        f.read_to_string(&mut buf)?;
        Ok(buf)
    }

    pub fn read_file_to_bytes(path: &Path) -> MyResult<Vec<u8>> {
        let mut f = File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(buf)
    }
}
