use std::str::FromStr;

use bitcoin::hashes::hash160;
use bitvm::signatures::wots::{wots160, wots256, wots32};

fn secret_key_from_msk(msk: &str, var: &str) -> String {
    hash160::Hash::from_str(&format!("{msk}:{var}"))
        .unwrap()
        .to_string()
}

pub fn secret_key_for_superblock_hash(msk: &str) -> String {
    let var = "superblock_hash";
    secret_key_from_msk(msk, var)
}

pub fn secret_key_for_superblock_period_start_ts(msk: &str) -> String {
    let var = "superblock_period_start_ts";
    secret_key_from_msk(msk, var)
}

pub fn secret_key_for_bridge_out_txid(msk: &str) -> String {
    let var = "bridge_out_txid";
    secret_key_from_msk(msk, var)
}

pub fn secret_keys_for_groth16_proof_verification(msk: &str) -> (Vec<String>, Vec<String>) {
    let var = "groth16_proof_verification";
    // FIXME: should return a tuple?
    secret_key_from_msk(msk, var);
    todo!()
}

pub fn public_key_for_superblock_hash(msk: &str) -> wots256::PublicKey {
    let secret_key = secret_key_for_superblock_hash(msk);
    wots256::generate_public_key(&secret_key)
}

pub fn public_key_for_superblock_period_start_ts(msk: &str) -> wots32::PublicKey {
    let secret_key = secret_key_for_superblock_period_start_ts(msk);
    wots32::generate_public_key(&secret_key)
}
pub fn public_key_for_bridge_out_txid(msk: &str) -> wots256::PublicKey {
    let secret_key = secret_key_for_bridge_out_txid(msk);
    wots256::generate_public_key(&secret_key)
}
pub fn public_key_for_groth16_proof_verification(
    msk: &str,
) -> (Vec<wots256::PublicKey>, Vec<wots160::PublicKey>) {
    let secret_keys = secret_keys_for_groth16_proof_verification(msk);
    (
        secret_keys
            .0
            .iter()
            .map(|secret_key| wots256::generate_public_key(secret_key))
            .collect(),
        secret_keys
            .1
            .iter()
            .map(|secret_key| wots160::generate_public_key(secret_key))
            .collect(),
    )
}
