use sha2::{Digest, Sha256};

pub fn hash_to_bn254_fq(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut hash: [u8; 32] = hasher.finalize().into();
    hash[0] &= 0b00011111; // mask 3 most significant bits
    hash
}
