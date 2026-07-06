use crate::utils::{b64u_decode, b64u_encode, random_bytes};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256};

const ITER: u32 = 200_000;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;

pub fn hash_code(plaintext: &str) -> String {
    let salt = random_bytes(SALT_LEN);
    let mut hash = vec![0u8; HASH_LEN];
    pbkdf2::<Hmac<Sha256>>(plaintext.as_bytes(), &salt, ITER, &mut hash)
        .expect("pbkdf2 length invariant");
    format!(
        "pbk2${}${}${}",
        ITER,
        b64u_encode(&salt),
        b64u_encode(&hash)
    )
}

pub fn verify_code(plaintext: &str, encoded: &str) -> bool {
    let parts: Vec<&str> = encoded.split('$').collect();
    if parts.len() != 4 || parts[0] != "pbk2" {
        return false;
    }
    let iter: u32 = match parts[1].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let salt = match b64u_decode(parts[2]) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let expected = match b64u_decode(parts[3]) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let mut got = vec![0u8; expected.len()];
    if pbkdf2::<Hmac<Sha256>>(plaintext.as_bytes(), &salt, iter, &mut got).is_err() {
        return false;
    }
    constant_time_eq(&got, &expected)
}

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
