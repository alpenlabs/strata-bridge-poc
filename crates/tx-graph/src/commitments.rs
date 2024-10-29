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

pub fn secret_key_for_proof_element(msk: &str, id: u32) -> String {
    let var = &format!("proof_element_{}", id);
    secret_key_from_msk(var, id)
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

pub fn public_key_for_proof_element_160(msk: &str, id: u32) -> wots160::PublicKey {
    let secret_key = secret_key_for_proof_element(msk, id);
    wots160::generate_public_key(&secret_key)
}

pub fn public_key_for_proof_element_256(msk: &str, id: u32) -> wots256::PublicKey {
    let secret_key = secret_key_for_proof_element(msk, id);
    wots256::generate_public_key(&secret_key)
}
