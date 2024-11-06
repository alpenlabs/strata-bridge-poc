#![allow(unused)]

use snark_bn254_verifier::Groth16Verifier;
use sp1_core_machine::io::SP1PublicValues;
use strata_primitives::{
    buf::Buf32,
    l1::{BitcoinAmount, XOnlyPk},
};
use strata_state::{bridge_state::DepositState, chain_state::ChainState};
use strata_zkvm::Proof;
use substrate_bn::Fr;

// Copied from ~/.sp1/circuits/v2.0.0/groth16_vk.bin
// This is same for all the SP1 programs that uses v2.0.0
const GROTH16_VK_BYTES: &[u8] = include_bytes!("../artifacts/groth16_vk.bin");

/// Verifies the Groth16 proof posted on chain
///
/// Note: SP1Verifier::verify_groth16 is not directly used because it depends on `sp1-sdk` which
/// cannot be compiled inside guest code.
pub fn verify_groth16(proof: &Proof, vkey_hash: &[u8], committed_values_raw: &[u8]) -> bool {
    // Convert vkey_hash to Fr, mapping the error to anyhow::Error
    let vkey_hash_fr = Fr::from_slice(vkey_hash).unwrap();

    let committed_values_digest = SP1PublicValues::from(committed_values_raw)
        .hash_bn254()
        .to_bytes_be();

    // Convert committed_values_digest to Fr, mapping the error to anyhow::Error
    let committed_values_digest_fr = Fr::from_slice(&committed_values_digest).unwrap();

    // Perform the Groth16 verification, mapping any error to anyhow::Error
    Groth16Verifier::verify(
        proof.as_bytes(),
        GROTH16_VK_BYTES,
        &[vkey_hash_fr, committed_values_digest_fr],
    )
    .unwrap()
}


#[cfg(test)]
mod test {

}
