#![allow(unused)]

use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};
use strata_primitives::{
    buf::Buf32,
    l1::{BitcoinAmount, XOnlyPk},
};
use strata_state::{bridge_state::DepositState, chain_state::ChainState};
use strata_zkvm::Proof;

pub const STRATA_CKP_VERIFICATION_KEY: &str =
    "0x005027dda93318eb6bb85acd3a924f9d6d63006672ed2ff14c87352acf538993";

/// Verifies the Groth16 proof posted on chain
///
/// Note: SP1Verifier::verify_groth16 is not directly used because it depends on `sp1-sdk` which
/// cannot be compiled inside guest code.
pub fn verify_groth16(proof: &Proof, vkey_hash: &[u8], committed_values_raw: &[u8]) -> bool {
    let vk_hash_str = hex::encode(vkey_hash);
    let vk_hash_str = format!("0x{}", vk_hash_str);

    // TODO: optimization
    // Groth16Verifier internally again decodes the hex encoded vkey_hash, which can be avoided
    // Skipped for now because `load_groth16_proof_from_bytes` is not available outside of the
    // crate
    Groth16Verifier::verify(
        proof.as_bytes(),
        committed_values_raw,
        &vk_hash_str,
        &GROTH16_VK_BYTES,
    )
    .is_ok()
}

#[cfg(test)]
mod test {}
