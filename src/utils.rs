
use tiny_keccak::{Hasher, Keccak};
use hex::encode;

#[allow(dead_code)]
pub fn get_hash_orig_keccak224(data: &str) -> String {
    let mut keccak = Keccak::v224();

    keccak.update(data.as_bytes());
    let mut result = [0u8; 28];
    keccak.finalize(&mut result);

    encode(result)
}

#[allow(dead_code)]
pub fn get_hash_orig_keccak256(data: &str) -> String {
    let mut keccak = Keccak::v256();

    keccak.update(data.as_bytes());
    let mut result = [0u8; 32];
    keccak.finalize(&mut result);

    encode(result)
}

#[allow(dead_code)]
pub fn get_hash_orig_keccak384(data: &str) -> String {
    let mut keccak = Keccak::v384();

    keccak.update(data.as_bytes());
    let mut result = [0u8; 48];
    keccak.finalize(&mut result);

    encode(result)
}

#[allow(dead_code)]
pub fn get_hash_orig_keccak512(data: &str) -> String {
    let mut keccak = Keccak::v512();

    keccak.update(data.as_bytes());
    let mut result = [0u8; 64];
    keccak.finalize(&mut result);

    encode(result)
}