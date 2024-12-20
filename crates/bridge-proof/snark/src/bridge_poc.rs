use ark_bn254::Fr;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use bitvm::groth16::g16;
use lazy_static::lazy_static;
use sp1_sdk::{HashableKey, ProverClient};
use strata_bridge_guest_builder::GUEST_BRIDGE_ELF;

use crate::sp1;

lazy_static! {
    pub static ref GROTH16_VERIFICATION_KEY: g16::VerifyingKey = {
        let pc = ProverClient::new();
        let (_, sp1vk) = pc.setup(GUEST_BRIDGE_ELF);

        let vkey_hash = hex::decode(sp1vk.bytes32().strip_prefix("0x").unwrap()).unwrap();

        let compile_time_public_inputs = [Fr::from_be_bytes_mod_order(&vkey_hash)];

        // embed first public input to the groth16 vk
        let mut vk = sp1::load_groth16_verifying_key_from_bytes(sp1_verifier::GROTH16_VK_BYTES.as_ref());
        let mut vk_gamma_abc_g1_0 = vk.gamma_abc_g1[0] * Fr::ONE;
        for (i, public_input) in compile_time_public_inputs.iter().enumerate() {
            vk_gamma_abc_g1_0 += vk.gamma_abc_g1[i + 1] * public_input;
        }
        let mut vk_gamma_abc_g1 = vec![vk_gamma_abc_g1_0.into_affine()];
        vk_gamma_abc_g1.extend(&vk.gamma_abc_g1[1 + compile_time_public_inputs.len()..]);
        vk.gamma_abc_g1 = vk_gamma_abc_g1;

        vk
    };
}
