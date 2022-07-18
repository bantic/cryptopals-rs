#[macro_use]
extern crate lazy_static;

pub mod aes;
pub mod letter_frequency;
pub mod serializers;
pub mod xor;

pub mod set1;
pub mod set2;

pub mod utils {
    use std::{fs::File, io::Read, path::Path};

    pub fn read_file_to_string(path: &Path) -> Result<String, String> {
        match File::open(path) {
            Ok(mut f) => {
                let mut buf: String = String::new();
                match f.read_to_string(&mut buf) {
                    Ok(_) => Ok(buf),
                    Err(e) => {
                        return Err(format!("Failed to read_to_string {}:{}", path.display(), e))
                    }
                }
            }
            Err(e) => return Err(format!("Failed to open path {}: {}", path.display(), e)),
        }
    }

    pub fn read_file_to_bytes(path: &Path) -> Result<Vec<u8>, String> {
        match File::open(path) {
            Ok(mut f) => {
                let mut buf: Vec<u8> = Vec::new();
                match f.read_to_end(&mut buf) {
                    Ok(_) => Ok(buf),
                    Err(e) => {
                        return Err(format!("Failed to read_to_bytes {}:{}", path.display(), e))
                    }
                }
            }
            Err(e) => return Err(format!("Failed to open path {}: {}", path.display(), e)),
        }
    }
}
