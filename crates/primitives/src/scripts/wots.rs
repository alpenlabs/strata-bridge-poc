use bitcoin::Txid;
use bitvm::{
    groth16::g16,
    signatures::wots::{wots160, wots256, wots32},
};

use super::{
    commitments::{
        secret_key_for_bridge_out_txid, secret_key_for_proof_element,
        secret_key_for_superblock_hash, secret_key_for_superblock_period_start_ts,
    },
    prelude::secret_key_for_public_inputs_hash,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PublicKeys {
    pub bridge_out_txid: wots256::PublicKey,
    pub superblock_hash: wots256::PublicKey,
    pub superblock_period_start_ts: wots32::PublicKey,
    pub groth16: g16::PublicKeys,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Signatures {
    pub bridge_out_txid: wots256::Signature,
    pub superblock_hash: wots256::Signature,
    pub superblock_period_start_ts: wots32::Signature,
    pub groth16: g16::Signatures,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Assertions {
    pub bridge_out_txid: [u8; 32],
    pub superblock_hash: [u8; 32],
    pub superblock_period_start_ts: [u8; 4],
    pub groth16: g16::Assertions,
}

pub fn bridge_poc_verification_key() -> g16::VerifyingKey {
    // TODO: replace this with actual verification key
    mock::get_verifying_key()
}

pub fn get_deposit_master_secret_key(msk: &str, deposit_txid: Txid) -> String {
    format!("{}:{}", msk, deposit_txid)
}

pub fn generate_wots_public_keys(msk: &str, deposit_txid: Txid) -> PublicKeys {
    let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);
    PublicKeys {
        bridge_out_txid: wots256::generate_public_key(&secret_key_for_bridge_out_txid(
            &deposit_msk,
        )),
        superblock_hash: wots256::generate_public_key(&secret_key_for_superblock_hash(
            &deposit_msk,
        )),
        superblock_period_start_ts: wots32::generate_public_key(
            &secret_key_for_superblock_period_start_ts(&deposit_msk),
        ),
        groth16: (
            [wots256::generate_public_key(
                &secret_key_for_public_inputs_hash(&deposit_msk),
            )],
            std::array::from_fn(|i| {
                wots256::generate_public_key(&secret_key_for_proof_element(&deposit_msk, i))
            }),
            std::array::from_fn(|i| {
                wots160::generate_public_key(&secret_key_for_proof_element(&deposit_msk, i + 40))
            }),
        ),
    }
}

pub fn generate_wots_signatures(
    msk: &str,
    deposit_txid: Txid,
    assertions: Assertions,
) -> Signatures {
    let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);

    Signatures {
        bridge_out_txid: wots256::get_signature(
            &secret_key_for_bridge_out_txid(&deposit_msk),
            &assertions.bridge_out_txid,
        ),
        superblock_hash: wots256::get_signature(
            &secret_key_for_superblock_hash(&deposit_msk),
            &assertions.superblock_hash,
        ),
        superblock_period_start_ts: wots32::get_signature(
            &secret_key_for_superblock_period_start_ts(&deposit_msk),
            &assertions.superblock_period_start_ts,
        ),
        groth16: (
            [wots256::get_signature(
                &secret_key_for_public_inputs_hash(&deposit_msk),
                &assertions.groth16.0[0],
            )],
            std::array::from_fn(|i| {
                wots256::get_signature(
                    &secret_key_for_proof_element(&deposit_msk, i),
                    &assertions.groth16.1[i],
                )
            }),
            std::array::from_fn(|i| {
                wots160::get_signature(
                    &secret_key_for_proof_element(&deposit_msk, i + 40),
                    &assertions.groth16.2[i],
                )
            }),
        ),
    }
}

pub mod mock {
    use ark_bn254::{Bn254, Fr};
    use ark_ec::CurveGroup;
    use ark_ff::{Field, PrimeField};
    use ark_groth16::VerifyingKey;
    use bitvm::groth16::g16;

    use crate::scripts::sp1g16::{self, hash_bn254_be_bytes};

    type E = Bn254;
    pub type BridgeProofPublicParams = ([u8; 32], [u8; 32], [u8; 32], u32);

    pub const PUBLIC_INPUTS: BridgeProofPublicParams = (
        [
            26, 43, 60, 77, 94, 111, 112, 129, 146, 163, 180, 197, 214, 231, 248, 9, 27, 44, 61,
            78, 95, 96, 113, 130, 147, 164, 181, 198, 215, 232, 249, 10,
        ],
        [
            170, 187, 204, 221, 238, 255, 32, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187,
            204, 221, 238, 255, 32, 17, 34, 51, 68, 85, 102, 119, 136, 153,
        ],
        [
            16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 32, 17, 34, 51,
            68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 32,
        ],
        3735928559u32,
    );

    // 0x003998612a8eb3617ad4faa89dc49e9e4ebcf07f4c42164810407b58c7a96cdc
    pub const VKEY_HASH: [u8; 32] = [
        0, 57, 152, 97, 42, 142, 179, 97, 122, 212, 250, 168, 157, 196, 158, 158, 78, 188, 240,
        127, 76, 66, 22, 72, 16, 64, 123, 88, 199, 169, 108, 220,
    ];

    pub fn get_verifying_key() -> VerifyingKey<E> {
        let compile_time_public_inputs = [Fr::from_be_bytes_mod_order(&VKEY_HASH)];

        let mut vk = sp1g16::load_groth16_verifying_key_from_bytes(sp1g16::GROTH16_VK_BYTES);

        let mut vk_gamma_abc_g1_0 = vk.gamma_abc_g1[0] * Fr::ONE;
        for (i, public_input) in compile_time_public_inputs.iter().enumerate() {
            vk_gamma_abc_g1_0 += vk.gamma_abc_g1[i + 1] * public_input;
        }
        let mut vk_gamma_abc_g1 = vec![vk_gamma_abc_g1_0.into_affine()];
        vk_gamma_abc_g1.extend(&vk.gamma_abc_g1[1 + compile_time_public_inputs.len()..]);
        vk.gamma_abc_g1 = vk_gamma_abc_g1;

        vk
    }

    #[expect(unused)]
    pub fn get_proof_and_public_inputs() -> (g16::Proof, g16::PublicInputs) {
        pub const PROOF_BYTES: [u8; 256] = [
            6, 71, 147, 246, 51, 1, 231, 159, 239, 5, 46, 114, 116, 30, 13, 149, 247, 149, 106,
            238, 236, 38, 13, 219, 218, 71, 196, 119, 8, 114, 19, 190, 2, 30, 105, 22, 27, 100,
            219, 125, 44, 78, 22, 130, 23, 59, 252, 76, 179, 100, 39, 13, 23, 210, 71, 10, 229,
            248, 193, 208, 129, 78, 25, 56, 9, 70, 52, 36, 4, 67, 215, 250, 135, 220, 89, 143, 241,
            178, 180, 75, 82, 19, 217, 6, 172, 42, 191, 160, 170, 147, 255, 236, 162, 125, 107, 54,
            17, 100, 54, 105, 133, 195, 97, 79, 70, 213, 106, 11, 65, 93, 194, 98, 13, 237, 133,
            133, 9, 85, 152, 44, 246, 153, 169, 53, 212, 162, 128, 209, 43, 142, 179, 212, 117, 9,
            7, 103, 110, 41, 42, 201, 175, 72, 26, 246, 106, 98, 153, 232, 179, 225, 227, 148, 19,
            62, 214, 245, 214, 64, 97, 169, 31, 11, 200, 130, 211, 66, 39, 237, 47, 191, 42, 99,
            205, 116, 10, 229, 3, 36, 207, 31, 149, 81, 16, 233, 237, 94, 248, 50, 238, 29, 88, 99,
            1, 243, 112, 142, 6, 78, 214, 193, 18, 199, 229, 63, 12, 209, 107, 136, 72, 90, 84,
            212, 72, 145, 109, 0, 103, 38, 89, 216, 176, 120, 154, 35, 25, 175, 152, 247, 139, 36,
            145, 89, 187, 179, 132, 73, 186, 14, 28, 79, 100, 72, 96, 114, 235, 75, 253, 62, 251,
            173, 136, 97, 67, 18, 90, 135,
        ];

        // pub const PUBLIC_INPUT_BYTES: [u8; 32 * 3 + 4] = [
        //     26, 43, 60, 77, 94, 111, 112, 129, 146, 163, 180, 197, 214, 231, 248, 9, 27, 44, 61,
        //     78, 95, 96, 113, 130, 147, 164, 181, 198, 215, 232, 249, 10, 170, 187, 204, 221, 238,
        //     255, 32, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 32,
        // 17,     34, 51, 68, 85, 102, 119, 136, 153, 16, 32, 48, 64, 80, 96, 112, 128,
        // 144, 160, 176,     192, 208, 224, 240, 32, 17, 34, 51, 68, 85, 102, 119, 136,
        // 153, 170, 187, 204, 221,     238, 255, 32, 239, 190, 173, 222,
        // ];

        let public_data_bytes = bincode::serialize(&PUBLIC_INPUTS).unwrap();
        let public_data_hash = hash_bn254_be_bytes(&public_data_bytes);

        let proof = sp1g16::load_groth16_proof_from_bytes(&PROOF_BYTES);
        let public_inputs = [Fr::from_be_bytes_mod_order(&public_data_hash)];

        (proof, public_inputs)
    }
}

pub mod _mock {
    use ark_bn254::{Bn254, Fr};
    use ark_ec::CurveGroup;
    use ark_ff::{Field, PrimeField};
    use ark_groth16::VerifyingKey;
    use bitvm::groth16::g16;

    use crate::scripts::sp1g16;

    type E = Bn254;

    // 0x00288dca96fa670c0292be7bd684999e0e8a6b000abf9730a6fa1b039731b59b
    const VKEY_HASH: [u8; 32] = [
        0, 40, 141, 202, 150, 250, 103, 12, 2, 146, 190, 123, 214, 132, 153, 158, 14, 138, 107, 0,
        10, 191, 151, 48, 166, 250, 27, 3, 151, 49, 181, 155,
    ];

    pub fn get_verifying_key() -> VerifyingKey<E> {
        let compile_time_public_inputs = [Fr::from_be_bytes_mod_order(&VKEY_HASH)];

        let mut vk = sp1g16::load_groth16_verifying_key_from_bytes(sp1g16::GROTH16_VK_BYTES);

        let mut vk_gamma_abc_g1_0 = vk.gamma_abc_g1[0] * Fr::ONE;
        for (i, public_input) in compile_time_public_inputs.iter().enumerate() {
            vk_gamma_abc_g1_0 += vk.gamma_abc_g1[i + 1] * public_input;
        }
        let mut vk_gamma_abc_g1 = vec![vk_gamma_abc_g1_0.into_affine()];
        vk_gamma_abc_g1.extend(&vk.gamma_abc_g1[1 + compile_time_public_inputs.len()..]);
        vk.gamma_abc_g1 = vk_gamma_abc_g1;

        vk
    }

    #[expect(unused)]
    pub fn get_proof_and_public_inputs() -> (g16::Proof, g16::PublicInputs) {
        const PROOF_BYTES: [u8; 256] = [
            3, 19, 181, 171, 106, 36, 254, 91, 176, 187, 23, 155, 242, 49, 77, 18, 29, 61, 133,
            124, 173, 153, 46, 211, 86, 5, 150, 151, 220, 122, 45, 149, 27, 255, 221, 181, 253, 53,
            170, 120, 140, 182, 233, 163, 0, 254, 244, 56, 60, 172, 169, 1, 73, 102, 4, 194, 124,
            178, 79, 214, 3, 132, 72, 225, 15, 184, 72, 216, 152, 16, 211, 198, 116, 226, 163, 80,
            58, 15, 115, 198, 161, 41, 222, 197, 138, 32, 197, 2, 176, 242, 33, 253, 86, 55, 162,
            37, 1, 146, 31, 61, 150, 61, 163, 188, 13, 200, 103, 178, 233, 242, 182, 185, 170, 228,
            73, 186, 112, 228, 46, 212, 153, 136, 255, 174, 213, 218, 44, 183, 19, 96, 129, 89, 14,
            204, 7, 110, 69, 213, 130, 175, 61, 230, 32, 45, 160, 147, 11, 203, 115, 249, 220, 168,
            41, 1, 54, 3, 136, 124, 229, 209, 14, 129, 39, 137, 91, 37, 64, 122, 221, 168, 63, 237,
            61, 39, 210, 12, 127, 199, 198, 174, 167, 248, 43, 248, 37, 250, 6, 15, 165, 108, 139,
            223, 30, 178, 183, 158, 238, 43, 172, 134, 237, 174, 80, 111, 220, 77, 193, 20, 66, 80,
            139, 217, 42, 186, 62, 204, 20, 6, 106, 227, 105, 144, 168, 18, 12, 23, 198, 77, 246,
            57, 79, 171, 234, 6, 202, 144, 181, 116, 229, 165, 196, 214, 184, 74, 81, 191, 144, 60,
            239, 1, 67, 58, 7, 54, 51, 203,
        ];

        const PUBLIC_INPUT_BYTES: [u8; 84] = [
            32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let proof = sp1g16::load_groth16_proof_from_bytes(&PROOF_BYTES);
        let public_inputs = [Fr::from_be_bytes_mod_order(&sp1g16::hash_bn254_be_bytes(
            &PUBLIC_INPUT_BYTES,
        ))];

        (proof, public_inputs)
    }
}

mod __mock {
    #![allow(unused)]
    #![allow(dead_code)]
    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ff::AdditiveGroup;
    use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::test_rng;
    use bitvm::groth16::g16;
    use rand::{RngCore, SeedableRng};

    type E = Bn254;

    #[derive(Clone, Debug)]
    pub struct DummyCircuit {
        pub a: Option<Fr>, // Private input a
        pub b: Option<Fr>, // Private input b
        pub c: Fr,         // Public output: a + b = 0
        pub d: Fr,         // Public output: a * b
    }

    impl ConstraintSynthesizer<Fr> for DummyCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            // Allocate private inputs a and b as witnesses
            let a = FpVar::new_witness(cs.clone(), || {
                self.a.ok_or(SynthesisError::AssignmentMissing)
            })?;
            let b = FpVar::new_witness(cs.clone(), || {
                self.b.ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Allocate public outputs c, d, and e
            let c = FpVar::new_input(cs.clone(), || Ok(self.c))?;
            let d = FpVar::new_input(cs.clone(), || Ok(self.d))?;

            // Enforce the constraints: c = a * b, d = a + b, e = a - b
            let computed_c = &a + &b;
            let computed_d = &a * &b;

            computed_c.enforce_equal(&c)?;
            computed_d.enforce_equal(&d)?;

            Ok(())
        }
    }

    fn compile_circuit() -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit {
            a: None,
            b: None,
            c: Fr::ZERO,
            d: Fr::ZERO,
        };
        Groth16::<E>::setup(circuit, &mut rng).unwrap()
    }

    pub fn get_verifying_key() -> VerifyingKey<E> {
        let (_, vk) = compile_circuit();
        vk
    }

    pub fn get_proving_key() -> ProvingKey<E> {
        let (pk, _) = compile_circuit();
        pk
    }

    pub fn get_proof() -> (g16::Proof, g16::PublicInputs) {
        let (a, b) = (5, -5);
        let (c, d) = (a + b, a * b);

        let circuit = DummyCircuit {
            a: Some(Fr::from(a)),
            b: Some(Fr::from(b)),
            c: Fr::from(c),
            d: Fr::from(d),
        };

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let pk = get_proving_key();

        let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
        let public_inputs = [circuit.d];

        (proof, public_inputs)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Instant};

    use ark_bn254::{Fq, Fr};
    use ark_ff::{BigInteger, PrimeField, UniformRand};
    use ark_std::test_rng;
    use bitcoin::{hashes::Hash, ScriptBuf};
    use bitvm::{
        groth16::g16,
        hash::sha256::sha256,
        pseudo::NMUL,
        signatures::wots::{wots160, wots256},
        treepp::*,
    };
    use rand::{RngCore, SeedableRng};

    use super::*;

    const WOTS_MSK: &str = "helloworld";

    #[test]
    fn test_groth16_compile() {
        let bridge_poc_vk = bridge_poc_verification_key();
        let partial_disprove_scripts = g16::compile_verifier(bridge_poc_vk);
        save_partial_disprove_scripts(&partial_disprove_scripts);
        println!(
            "script.lens: {:?}",
            partial_disprove_scripts.map(|script| script.len())
        );
    }

    fn save_partial_disprove_scripts(scripts: &[Script; g16::N_TAPLEAVES]) {
        for (index, script) in scripts.iter().enumerate() {
            let path = format!("data/partial-disprove-scripts/{index}");
            fs::write(path, script.clone().compile().to_bytes()).unwrap();
            print!("{}, ", index);
        }
        println!();
    }

    fn read_partial_disprove_scripts() -> [Script; g16::N_TAPLEAVES] {
        let scripts = std::array::from_fn(|index| {
            let path = format!("data/partial-disprove-scripts/{index}");
            let script_buf = ScriptBuf::from_bytes(fs::read(path).unwrap());
            script!().push_script(script_buf)
        });
        scripts
    }

    #[test]
    fn test_full_verification() {
        let bridge_poc_vk = bridge_poc_verification_key();
        let deposit_txid = mock_txid();

        println!("Generating assertions");
        // let assertions: Assertions = {
        //     let (proof, public_inputs) = mock::get_proof_and_public_inputs();
        //     let groth16_assertions =
        //         g16::generate_proof_assertions(bridge_poc_vk, proof, public_inputs);
        //     let assertions = Assertions {
        //         bridge_out_txid: mock::PUBLIC_INPUTS.2,
        //         superblock_hash: mock::PUBLIC_INPUTS.1,
        //         superblock_period_start_ts: mock::PUBLIC_INPUTS.3.to_le_bytes(),
        //         groth16: groth16_assertions,
        //     };
        //     println!("{:?}", assertions);
        //     assertions
        // };
        // return;
        let assertions = mock_assertions();

        println!("Generating wots public keys");
        let public_keys = generate_wots_public_keys(WOTS_MSK, deposit_txid).groth16;

        println!("Reading partial disprove scripts");
        let partial_disprove_scripts = &read_partial_disprove_scripts();

        println!("    Generating wots signatures for assertions");
        let signatures = generate_wots_signatures(WOTS_MSK, deposit_txid, assertions).groth16;

        match g16::verify_signed_assertions(bridge_poc_vk.clone(), public_keys, signatures) {
            Some((i, witness_script)) => {
                println!("    Assertions (invalidated={i}) is invalid!");

                let tapleaf_script =
                    g16::generate_disprove_scripts(public_keys, partial_disprove_scripts)[i]
                        .clone();

                let script = script! {
                    { witness_script }
                    { tapleaf_script }
                };
                let res = execute_script(script);
                assert!(
                    res.success,
                    "    Assertion: Disprove script should not fail!"
                );
            }
            None => println!("    Assertions is valid!"),
        }
    }

    #[test]
    fn _test_full_verification() {
        let bridge_poc_vk = bridge_poc_verification_key();

        println!("Generating assertions");
        // let assertions = {
        //     let (proof, public_inputs) = mock::get_proof_and_public_inputs();
        //     let groth16_assertions =
        //         g16::generate_proof_assertions(bridge_poc_vk, proof, public_inputs);
        //     let assertions = Assertions {
        //         bridge_out_txid: [0u8; 32],
        //         superblock_hash: [0u8; 32],
        //         superblock_period_start_ts: [0u8; 4],
        //         groth16: groth16_assertions,
        //     };
        //     println!("{:?}", assertions);
        //     assertions
        // };
        // return;

        let deposit_txid = mock_txid();

        println!("Generating wots public keys");
        let public_keys = generate_wots_public_keys(WOTS_MSK, deposit_txid).groth16;

        println!("Reading partial disprove scripts");
        let partial_disprove_scripts = &read_partial_disprove_scripts();

        fn invalidate_groth16_assertions(mut assertions: Assertions, i: usize) -> Assertions {
            match i {
                0 => assertions.groth16.0[i] = [0u8; 32],
                1..=g16::N_VERIFIER_FQS => assertions.groth16.1[i - 1] = [0u8; 32],
                _ => assertions.groth16.2[i - g16::N_VERIFIER_FQS - 1] = [0u8; 20],
            };
            assertions
        }

        // for i in 0..g16::N_VERIFIER_PUBLIC_INPUTS + g16::N_VERIFIER_FQS + g16::N_VERIFIER_HASHES
        // {
        for i in [0, 1, 2, 39, 40, 41, 42, 610, 611, 612, 613, 614] {
            println!("Verifying signed assertions (invalidated={i})");
            let assertions = invalidate_groth16_assertions(mock_assertions(), i);

            println!("    Generating wots signatures for assertions (invalidated={i}");
            let signatures = generate_wots_signatures(WOTS_MSK, deposit_txid, assertions).groth16;

            match g16::verify_signed_assertions(bridge_poc_vk.clone(), public_keys, signatures) {
                Some((tapleaf_index, witness_script)) => {
                    println!("    Assertions (invalidated={i}) is invalid!");

                    let tapleaf_script =
                        g16::generate_disprove_scripts(public_keys, partial_disprove_scripts)
                            [tapleaf_index]
                            .clone();

                    let script = script! {
                        { witness_script }
                        { tapleaf_script }
                    };
                    let res = execute_script(script);
                    assert!(
                        res.success,
                        "    Assertion (invalidated={i}): Disprove script should not fail!"
                    );
                }
                None => println!("    Assertions (invalidated={i}) is valid!"),
            }
        }
    }

    pub fn mock_assertions() -> Assertions {
        Assertions {
            bridge_out_txid: [
                16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 32, 17, 34,
                51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 32,
            ],
            superblock_hash: [
                170, 187, 204, 221, 238, 255, 32, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187,
                204, 221, 238, 255, 32, 17, 34, 51, 68, 85, 102, 119, 136, 153,
            ],
            superblock_period_start_ts: [239, 190, 173, 222],
            groth16: (
                [[
                    80, 109, 248, 180, 9, 193, 114, 154, 115, 169, 168, 240, 183, 156, 241, 46, 0,
                    195, 134, 12, 230, 246, 101, 202, 24, 228, 13, 116, 183, 37, 201, 128,
                ]],
                [
                    [
                        32, 225, 150, 97, 177, 70, 189, 215, 194, 228, 97, 40, 113, 179, 207, 196,
                        59, 70, 114, 208, 113, 45, 116, 160, 94, 143, 28, 13, 24, 228, 145, 131,
                    ],
                    [
                        96, 116, 57, 111, 51, 16, 126, 249, 254, 80, 226, 39, 71, 225, 208, 89,
                        127, 89, 166, 238, 206, 98, 208, 189, 173, 116, 76, 119, 128, 39, 49, 235,
                    ],
                    [
                        240, 139, 128, 162, 203, 153, 92, 90, 10, 188, 127, 103, 144, 247, 55, 26,
                        119, 219, 52, 83, 16, 160, 35, 134, 98, 131, 68, 77, 215, 26, 184, 145,
                    ],
                    [
                        240, 30, 23, 130, 108, 52, 158, 77, 207, 155, 147, 94, 58, 143, 108, 79,
                        20, 61, 5, 156, 206, 76, 49, 152, 101, 131, 209, 114, 251, 17, 111, 44,
                    ],
                    [
                        145, 250, 137, 127, 184, 66, 25, 149, 187, 59, 72, 148, 171, 224, 193, 244,
                        70, 132, 6, 39, 190, 180, 223, 227, 191, 218, 136, 22, 52, 33, 165, 120,
                    ],
                    [
                        16, 63, 7, 232, 96, 228, 109, 28, 33, 124, 94, 243, 192, 29, 182, 136, 132,
                        165, 69, 77, 132, 25, 214, 0, 118, 98, 149, 141, 11, 135, 169, 50,
                    ],
                    [
                        32, 171, 23, 202, 95, 71, 145, 29, 67, 196, 135, 153, 98, 86, 118, 172,
                        133, 62, 85, 92, 5, 150, 47, 11, 224, 120, 177, 110, 108, 208, 71, 194,
                    ],
                    [
                        225, 99, 169, 10, 77, 201, 103, 76, 126, 35, 75, 81, 176, 51, 82, 110, 192,
                        182, 37, 163, 154, 24, 148, 74, 103, 84, 97, 11, 171, 105, 57, 40,
                    ],
                    [
                        129, 216, 224, 184, 99, 122, 85, 93, 126, 81, 105, 56, 38, 236, 11, 160,
                        69, 142, 138, 80, 101, 80, 6, 117, 118, 90, 212, 63, 146, 126, 30, 183,
                    ],
                    [
                        96, 164, 236, 136, 194, 195, 41, 184, 125, 230, 250, 210, 31, 132, 241,
                        209, 194, 102, 225, 1, 208, 220, 200, 208, 112, 188, 71, 65, 227, 42, 218,
                        215,
                    ],
                    [
                        145, 238, 53, 75, 23, 76, 217, 196, 116, 214, 196, 204, 240, 81, 196, 249,
                        255, 112, 88, 19, 11, 23, 17, 99, 68, 204, 23, 156, 169, 51, 251, 29,
                    ],
                    [
                        33, 169, 132, 163, 219, 58, 78, 48, 110, 207, 124, 176, 27, 142, 147, 5,
                        130, 55, 81, 39, 165, 145, 44, 13, 120, 47, 30, 90, 90, 97, 123, 188,
                    ],
                    [
                        96, 103, 186, 243, 203, 58, 129, 88, 46, 223, 108, 105, 173, 197, 153, 231,
                        189, 94, 20, 242, 18, 153, 178, 55, 84, 232, 100, 75, 45, 246, 238, 54,
                    ],
                    [
                        226, 143, 6, 31, 142, 209, 81, 50, 15, 56, 94, 100, 153, 34, 2, 144, 239,
                        51, 78, 251, 251, 199, 133, 58, 216, 167, 118, 34, 62, 82, 128, 105,
                    ],
                    [
                        32, 141, 185, 167, 91, 26, 164, 115, 237, 49, 150, 149, 140, 10, 218, 196,
                        199, 254, 191, 247, 199, 143, 140, 33, 210, 188, 236, 237, 32, 152, 193,
                        235,
                    ],
                    [
                        177, 232, 205, 211, 7, 103, 193, 240, 233, 158, 127, 66, 232, 231, 238, 93,
                        77, 156, 22, 43, 173, 157, 247, 94, 35, 12, 98, 86, 20, 20, 7, 120,
                    ],
                    [
                        192, 162, 33, 111, 115, 67, 206, 6, 237, 155, 16, 115, 12, 94, 224, 4, 29,
                        169, 182, 159, 191, 14, 238, 76, 195, 29, 94, 60, 110, 179, 136, 2,
                    ],
                    [
                        130, 115, 39, 95, 12, 100, 150, 239, 154, 161, 207, 5, 113, 26, 211, 98,
                        180, 152, 36, 70, 247, 84, 150, 103, 13, 255, 107, 253, 20, 240, 15, 50,
                    ],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                    [
                        160, 96, 227, 85, 32, 27, 105, 111, 244, 72, 62, 209, 148, 234, 236, 241,
                        68, 140, 120, 179, 152, 114, 29, 214, 196, 0, 57, 239, 68, 170, 204, 86,
                    ],
                    [
                        65, 127, 9, 187, 93, 56, 86, 243, 104, 130, 118, 254, 33, 42, 228, 123,
                        153, 66, 135, 45, 234, 254, 197, 237, 251, 9, 73, 151, 19, 35, 91, 54,
                    ],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                    [
                        178, 232, 59, 77, 87, 144, 112, 118, 230, 146, 162, 156, 250, 132, 161,
                        111, 166, 38, 153, 142, 59, 30, 62, 73, 49, 227, 109, 95, 109, 4, 22, 154,
                    ],
                    [
                        241, 176, 140, 40, 61, 36, 114, 222, 242, 251, 162, 54, 220, 71, 160, 94,
                        48, 66, 252, 241, 89, 21, 1, 158, 222, 229, 143, 35, 238, 209, 133, 54,
                    ],
                    [
                        144, 100, 67, 66, 64, 52, 125, 175, 120, 205, 149, 248, 31, 43, 75, 180,
                        37, 49, 157, 96, 202, 162, 251, 10, 170, 57, 255, 206, 42, 215, 182, 99,
                    ],
                    [
                        17, 70, 99, 150, 88, 60, 22, 244, 100, 93, 166, 176, 20, 213, 44, 38, 208,
                        222, 88, 88, 144, 85, 137, 194, 111, 153, 154, 83, 77, 42, 8, 29,
                    ],
                    [
                        34, 139, 129, 64, 11, 140, 132, 11, 27, 22, 145, 230, 23, 71, 235, 79, 227,
                        158, 213, 159, 116, 40, 173, 244, 115, 174, 155, 86, 107, 240, 89, 16,
                    ],
                    [
                        178, 115, 175, 9, 3, 42, 66, 125, 93, 92, 30, 18, 128, 254, 24, 80, 232,
                        196, 242, 194, 127, 88, 163, 30, 199, 165, 97, 135, 57, 219, 76, 214,
                    ],
                    [
                        194, 20, 125, 1, 18, 172, 145, 224, 26, 193, 80, 89, 28, 136, 42, 216, 162,
                        162, 174, 74, 36, 93, 24, 69, 232, 202, 156, 241, 63, 33, 112, 31,
                    ],
                    [
                        65, 37, 5, 45, 122, 145, 139, 113, 60, 108, 198, 177, 25, 220, 187, 212,
                        239, 84, 200, 177, 156, 120, 229, 60, 237, 51, 203, 101, 46, 144, 118, 12,
                    ],
                    [
                        17, 77, 67, 233, 10, 203, 58, 168, 23, 249, 19, 102, 163, 173, 31, 86, 208,
                        149, 26, 182, 16, 134, 53, 36, 99, 114, 160, 67, 186, 185, 164, 215,
                    ],
                    [
                        34, 207, 163, 31, 76, 71, 71, 130, 34, 20, 32, 180, 212, 30, 16, 165, 123,
                        231, 70, 203, 37, 122, 165, 133, 57, 73, 207, 126, 191, 82, 183, 63,
                    ],
                ],
                [
                    [
                        131, 14, 6, 209, 3, 127, 133, 160, 204, 182, 190, 108, 80, 125, 0, 33, 179,
                        254, 90, 191,
                    ],
                    [
                        126, 121, 218, 116, 53, 83, 198, 164, 162, 181, 86, 244, 241, 139, 208,
                        111, 59, 33, 158, 234,
                    ],
                    [
                        212, 227, 142, 165, 122, 209, 239, 43, 204, 24, 158, 70, 20, 164, 163, 124,
                        45, 1, 13, 163,
                    ],
                    [
                        196, 123, 77, 144, 164, 244, 216, 24, 187, 92, 43, 53, 8, 227, 154, 209,
                        70, 249, 156, 25,
                    ],
                    [
                        81, 173, 157, 193, 190, 169, 69, 64, 134, 135, 98, 116, 82, 74, 213, 240,
                        128, 135, 30, 162,
                    ],
                    [
                        41, 96, 163, 78, 226, 27, 34, 213, 50, 126, 78, 164, 231, 164, 224, 230,
                        218, 130, 110, 248,
                    ],
                    [
                        180, 50, 186, 242, 56, 8, 8, 215, 255, 60, 98, 194, 195, 249, 24, 100, 102,
                        6, 105, 241,
                    ],
                    [
                        210, 74, 186, 249, 35, 82, 152, 11, 183, 91, 74, 2, 188, 96, 104, 255, 172,
                        170, 32, 122,
                    ],
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    [
                        188, 223, 2, 45, 221, 23, 60, 138, 26, 142, 10, 199, 190, 51, 154, 151, 65,
                        168, 230, 181,
                    ],
                    [
                        63, 121, 192, 225, 117, 128, 105, 254, 180, 129, 204, 63, 107, 183, 160,
                        75, 214, 90, 37, 201,
                    ],
                    [
                        191, 44, 135, 36, 210, 222, 167, 81, 41, 55, 179, 0, 179, 50, 28, 26, 206,
                        46, 207, 193,
                    ],
                    [
                        213, 101, 158, 244, 75, 7, 18, 62, 187, 104, 193, 223, 15, 119, 119, 184,
                        139, 100, 241, 47,
                    ],
                    [
                        105, 78, 160, 128, 243, 239, 239, 108, 206, 123, 61, 54, 184, 247, 199,
                        185, 4, 218, 96, 75,
                    ],
                    [
                        218, 138, 7, 114, 108, 97, 66, 95, 56, 92, 15, 251, 91, 117, 96, 96, 79,
                        87, 248, 151,
                    ],
                    [
                        190, 53, 50, 132, 211, 195, 71, 47, 242, 189, 114, 163, 102, 203, 10, 95,
                        224, 167, 33, 133,
                    ],
                    [
                        75, 250, 66, 139, 114, 23, 196, 129, 42, 157, 167, 27, 2, 187, 36, 168,
                        112, 101, 226, 86,
                    ],
                    [
                        40, 169, 150, 110, 248, 69, 41, 79, 103, 83, 72, 191, 21, 212, 7, 154, 77,
                        247, 88, 56,
                    ],
                    [
                        147, 31, 180, 174, 255, 246, 160, 86, 250, 22, 77, 46, 226, 152, 200, 22,
                        105, 91, 45, 163,
                    ],
                    [
                        183, 224, 32, 192, 182, 241, 120, 246, 14, 145, 249, 20, 198, 48, 52, 230,
                        59, 156, 78, 63,
                    ],
                    [
                        37, 13, 149, 104, 153, 153, 31, 137, 229, 220, 208, 176, 0, 164, 10, 84,
                        179, 1, 64, 44,
                    ],
                    [
                        3, 152, 2, 140, 206, 1, 151, 253, 11, 211, 74, 174, 34, 44, 212, 0, 162,
                        251, 9, 65,
                    ],
                    [
                        181, 95, 62, 79, 117, 73, 243, 28, 55, 39, 39, 69, 56, 88, 124, 226, 141,
                        132, 63, 136,
                    ],
                    [
                        111, 108, 85, 38, 221, 12, 151, 214, 12, 179, 24, 193, 217, 190, 210, 131,
                        19, 191, 219, 137,
                    ],
                    [
                        6, 117, 114, 216, 116, 62, 154, 47, 139, 176, 104, 3, 15, 71, 237, 101,
                        131, 178, 58, 173,
                    ],
                    [
                        48, 166, 6, 108, 46, 78, 146, 243, 192, 165, 142, 191, 156, 249, 121, 224,
                        54, 86, 62, 243,
                    ],
                    [
                        87, 0, 148, 20, 11, 141, 66, 176, 243, 177, 139, 186, 128, 35, 151, 183,
                        68, 184, 123, 137,
                    ],
                    [
                        3, 11, 81, 113, 180, 61, 193, 79, 154, 159, 85, 40, 39, 49, 136, 82, 225,
                        142, 245, 177,
                    ],
                    [
                        104, 123, 4, 88, 133, 133, 207, 235, 148, 57, 245, 188, 37, 76, 165, 173,
                        50, 172, 111, 168,
                    ],
                    [
                        83, 223, 106, 185, 14, 195, 119, 23, 188, 225, 177, 172, 235, 57, 210, 3,
                        46, 63, 144, 136,
                    ],
                    [
                        36, 4, 64, 125, 220, 157, 189, 181, 70, 68, 122, 95, 52, 74, 54, 2, 82,
                        172, 110, 248,
                    ],
                    [
                        191, 31, 135, 216, 218, 239, 74, 182, 158, 237, 80, 133, 33, 84, 50, 216,
                        149, 26, 194, 3,
                    ],
                    [
                        60, 79, 82, 10, 145, 81, 238, 133, 196, 233, 109, 246, 237, 177, 75, 94,
                        229, 242, 89, 97,
                    ],
                    [
                        84, 182, 247, 30, 242, 93, 216, 221, 122, 254, 178, 234, 38, 57, 12, 241,
                        145, 84, 219, 71,
                    ],
                    [
                        7, 75, 126, 149, 240, 66, 179, 27, 148, 228, 207, 153, 31, 37, 162, 255,
                        11, 1, 21, 13,
                    ],
                    [
                        32, 174, 194, 200, 179, 26, 99, 225, 66, 226, 172, 163, 26, 172, 86, 113,
                        36, 187, 195, 177,
                    ],
                    [
                        103, 140, 152, 76, 114, 150, 158, 177, 84, 58, 30, 80, 136, 16, 107, 48,
                        219, 156, 159, 38,
                    ],
                    [
                        242, 176, 34, 79, 161, 174, 37, 245, 249, 117, 246, 100, 45, 100, 173, 50,
                        75, 213, 88, 171,
                    ],
                    [
                        68, 15, 99, 28, 56, 234, 29, 53, 27, 26, 45, 211, 130, 134, 54, 220, 246,
                        15, 136, 216,
                    ],
                    [
                        6, 101, 51, 235, 234, 77, 46, 141, 126, 166, 254, 215, 135, 174, 19, 196,
                        201, 24, 241, 25,
                    ],
                    [
                        189, 43, 149, 23, 38, 229, 59, 169, 175, 169, 93, 150, 11, 18, 233, 77,
                        125, 140, 25, 195,
                    ],
                    [
                        37, 25, 161, 107, 227, 49, 217, 109, 111, 79, 212, 119, 240, 193, 87, 45,
                        78, 188, 38, 244,
                    ],
                    [
                        177, 79, 138, 31, 234, 231, 186, 113, 42, 101, 107, 232, 209, 184, 142, 27,
                        12, 125, 225, 11,
                    ],
                    [
                        49, 142, 183, 117, 171, 60, 174, 225, 217, 172, 177, 214, 79, 253, 152,
                        245, 216, 190, 241, 15,
                    ],
                    [
                        204, 20, 58, 199, 143, 28, 97, 6, 238, 132, 92, 234, 200, 133, 109, 34, 88,
                        67, 159, 146,
                    ],
                    [
                        244, 215, 190, 187, 170, 10, 220, 193, 100, 136, 67, 123, 41, 199, 172,
                        239, 194, 183, 82, 141,
                    ],
                    [
                        88, 206, 110, 45, 37, 218, 74, 67, 27, 116, 162, 234, 196, 96, 50, 232,
                        189, 158, 144, 158,
                    ],
                    [
                        0, 67, 239, 110, 201, 10, 121, 255, 3, 62, 54, 111, 48, 27, 233, 29, 129,
                        36, 184, 149,
                    ],
                    [
                        192, 41, 221, 88, 51, 55, 119, 182, 194, 238, 130, 248, 139, 64, 52, 81,
                        122, 62, 30, 34,
                    ],
                    [
                        250, 9, 41, 41, 226, 33, 177, 195, 229, 114, 209, 181, 82, 73, 131, 159,
                        115, 1, 73, 187,
                    ],
                    [
                        43, 144, 172, 35, 181, 247, 153, 227, 68, 131, 200, 17, 112, 114, 147, 193,
                        62, 91, 100, 97,
                    ],
                    [
                        53, 78, 169, 119, 16, 64, 150, 52, 31, 178, 123, 144, 65, 195, 237, 151, 4,
                        81, 161, 219,
                    ],
                    [
                        73, 112, 59, 132, 133, 91, 76, 5, 246, 171, 104, 87, 129, 21, 62, 51, 34,
                        237, 74, 163,
                    ],
                    [
                        31, 16, 156, 61, 161, 54, 107, 13, 35, 118, 100, 108, 6, 60, 181, 34, 182,
                        194, 187, 10,
                    ],
                    [
                        227, 13, 74, 93, 60, 243, 106, 233, 91, 47, 234, 204, 71, 84, 75, 3, 30,
                        109, 199, 171,
                    ],
                    [
                        83, 116, 229, 220, 145, 68, 64, 114, 194, 201, 141, 133, 156, 205, 184,
                        118, 161, 230, 9, 159,
                    ],
                    [
                        53, 231, 193, 107, 116, 56, 109, 87, 200, 224, 18, 204, 133, 143, 187, 243,
                        29, 253, 158, 236,
                    ],
                    [
                        120, 165, 37, 215, 229, 112, 127, 6, 54, 208, 107, 229, 101, 101, 90, 220,
                        216, 250, 245, 136,
                    ],
                    [
                        127, 204, 94, 230, 223, 209, 64, 236, 37, 148, 50, 184, 25, 23, 58, 250,
                        231, 149, 252, 207,
                    ],
                    [
                        211, 220, 39, 50, 177, 200, 24, 45, 219, 108, 213, 152, 11, 117, 184, 222,
                        120, 226, 112, 111,
                    ],
                    [
                        34, 52, 77, 163, 190, 109, 205, 145, 101, 56, 49, 58, 205, 157, 100, 162,
                        0, 182, 175, 132,
                    ],
                    [
                        137, 64, 141, 105, 19, 245, 250, 185, 70, 126, 249, 170, 11, 73, 25, 238,
                        22, 83, 200, 25,
                    ],
                    [
                        64, 236, 172, 55, 198, 164, 197, 109, 38, 140, 169, 1, 252, 78, 167, 219,
                        10, 89, 96, 140,
                    ],
                    [
                        56, 21, 49, 48, 3, 154, 140, 105, 65, 232, 172, 197, 200, 103, 141, 19, 26,
                        28, 11, 53,
                    ],
                    [
                        193, 27, 4, 48, 249, 137, 236, 97, 116, 58, 242, 150, 222, 159, 58, 64,
                        251, 234, 124, 57,
                    ],
                    [
                        151, 131, 234, 177, 180, 225, 195, 61, 155, 100, 199, 159, 233, 109, 161,
                        175, 22, 233, 5, 69,
                    ],
                    [
                        195, 150, 194, 234, 166, 97, 9, 210, 251, 237, 181, 184, 180, 184, 42, 190,
                        143, 249, 94, 156,
                    ],
                    [
                        106, 53, 35, 62, 233, 145, 224, 97, 147, 129, 154, 178, 38, 84, 206, 161,
                        21, 147, 232, 6,
                    ],
                    [
                        158, 175, 157, 105, 147, 92, 163, 69, 255, 52, 12, 52, 219, 10, 37, 7, 181,
                        16, 84, 187,
                    ],
                    [
                        45, 33, 26, 145, 159, 72, 92, 154, 195, 232, 222, 179, 20, 211, 2, 91, 178,
                        152, 56, 13,
                    ],
                    [
                        78, 100, 176, 155, 61, 153, 103, 71, 165, 193, 43, 199, 202, 252, 93, 172,
                        187, 74, 216, 48,
                    ],
                    [
                        99, 1, 200, 115, 155, 94, 113, 220, 243, 44, 200, 232, 108, 81, 99, 129,
                        219, 56, 32, 179,
                    ],
                    [
                        116, 184, 180, 186, 145, 29, 248, 156, 170, 141, 27, 1, 60, 163, 191, 30,
                        5, 229, 117, 122,
                    ],
                    [
                        104, 166, 251, 28, 127, 248, 99, 186, 234, 19, 243, 160, 137, 59, 221, 186,
                        118, 160, 104, 58,
                    ],
                    [
                        160, 180, 12, 137, 156, 7, 154, 130, 29, 100, 3, 84, 35, 50, 31, 101, 156,
                        180, 130, 227,
                    ],
                    [
                        229, 12, 179, 36, 130, 169, 142, 12, 91, 106, 109, 241, 134, 76, 124, 250,
                        82, 26, 109, 94,
                    ],
                    [
                        52, 229, 122, 155, 224, 107, 164, 196, 234, 250, 125, 171, 118, 38, 200,
                        79, 24, 37, 103, 15,
                    ],
                    [
                        128, 40, 208, 53, 255, 10, 123, 25, 16, 212, 52, 64, 17, 53, 250, 130, 50,
                        205, 6, 245,
                    ],
                    [
                        58, 246, 144, 110, 7, 252, 241, 27, 94, 127, 102, 125, 164, 132, 102, 49,
                        250, 101, 176, 120,
                    ],
                    [
                        49, 128, 67, 95, 243, 198, 73, 247, 103, 111, 78, 195, 99, 80, 122, 232,
                        31, 164, 173, 55,
                    ],
                    [
                        76, 139, 217, 17, 122, 113, 7, 124, 198, 191, 84, 99, 140, 43, 232, 37,
                        189, 126, 201, 49,
                    ],
                    [
                        15, 109, 195, 48, 75, 220, 80, 181, 100, 195, 5, 162, 155, 150, 146, 207,
                        99, 245, 9, 43,
                    ],
                    [
                        134, 231, 11, 10, 188, 231, 147, 232, 212, 48, 244, 150, 159, 87, 167, 191,
                        78, 116, 160, 115,
                    ],
                    [
                        41, 31, 234, 255, 231, 129, 31, 200, 7, 231, 13, 183, 176, 205, 128, 253,
                        134, 250, 253, 8,
                    ],
                    [
                        74, 9, 79, 46, 56, 103, 71, 120, 7, 182, 106, 127, 55, 191, 130, 14, 140,
                        233, 131, 231,
                    ],
                    [
                        111, 198, 35, 31, 130, 200, 187, 229, 153, 235, 73, 150, 195, 10, 84, 190,
                        38, 237, 66, 36,
                    ],
                    [
                        222, 108, 29, 176, 105, 29, 79, 225, 164, 171, 53, 138, 140, 3, 193, 2,
                        124, 52, 233, 244,
                    ],
                    [
                        201, 102, 76, 255, 192, 102, 108, 228, 27, 126, 79, 200, 167, 99, 91, 31,
                        147, 148, 67, 71,
                    ],
                    [
                        21, 247, 0, 198, 200, 44, 37, 247, 70, 68, 161, 183, 246, 160, 42, 223, 36,
                        116, 131, 215,
                    ],
                    [
                        120, 158, 78, 123, 185, 182, 205, 182, 33, 51, 209, 66, 72, 16, 245, 207,
                        160, 177, 195, 68,
                    ],
                    [
                        243, 105, 138, 4, 157, 41, 198, 177, 217, 217, 53, 119, 82, 244, 208, 196,
                        104, 162, 24, 221,
                    ],
                    [
                        152, 44, 35, 44, 171, 240, 181, 100, 249, 8, 225, 152, 116, 45, 253, 18,
                        163, 144, 63, 223,
                    ],
                    [
                        159, 182, 145, 157, 109, 29, 178, 64, 178, 72, 62, 14, 1, 126, 129, 74,
                        138, 159, 150, 239,
                    ],
                    [
                        170, 195, 212, 193, 173, 235, 120, 196, 81, 87, 12, 236, 250, 234, 85, 176,
                        175, 14, 182, 19,
                    ],
                    [
                        227, 3, 142, 51, 156, 198, 11, 71, 200, 92, 84, 198, 14, 103, 136, 94, 193,
                        120, 88, 122,
                    ],
                    [
                        160, 44, 180, 243, 232, 116, 79, 18, 17, 45, 128, 71, 76, 22, 188, 155, 80,
                        98, 101, 132,
                    ],
                    [
                        147, 238, 59, 114, 23, 67, 112, 76, 3, 8, 138, 139, 179, 232, 118, 12, 157,
                        90, 0, 59,
                    ],
                    [
                        112, 6, 79, 197, 215, 198, 100, 118, 17, 232, 160, 99, 34, 202, 105, 112,
                        67, 92, 112, 71,
                    ],
                    [
                        1, 201, 167, 185, 7, 111, 67, 44, 136, 124, 9, 194, 233, 104, 238, 106, 2,
                        130, 147, 184,
                    ],
                    [
                        141, 135, 70, 127, 177, 231, 29, 136, 164, 113, 93, 239, 218, 41, 33, 118,
                        80, 189, 63, 120,
                    ],
                    [
                        251, 28, 193, 23, 95, 196, 92, 63, 234, 54, 20, 109, 1, 16, 170, 120, 234,
                        175, 25, 85,
                    ],
                    [
                        203, 157, 150, 95, 27, 2, 51, 120, 48, 33, 187, 210, 108, 207, 106, 92, 83,
                        69, 178, 162,
                    ],
                    [
                        192, 243, 28, 133, 176, 194, 173, 93, 170, 100, 237, 194, 149, 50, 34, 250,
                        247, 128, 164, 16,
                    ],
                    [
                        162, 140, 86, 7, 231, 120, 115, 166, 46, 254, 130, 194, 46, 162, 58, 114,
                        137, 59, 200, 178,
                    ],
                    [
                        204, 175, 234, 15, 0, 131, 240, 87, 27, 58, 27, 7, 165, 58, 121, 25, 151,
                        97, 133, 34,
                    ],
                    [
                        127, 122, 56, 107, 72, 16, 54, 45, 26, 175, 3, 108, 53, 49, 38, 193, 130,
                        18, 86, 130,
                    ],
                    [
                        196, 187, 75, 213, 30, 102, 174, 240, 76, 146, 192, 159, 71, 183, 79, 176,
                        173, 6, 121, 3,
                    ],
                    [
                        232, 163, 123, 171, 105, 248, 104, 42, 239, 148, 7, 139, 149, 231, 61, 92,
                        239, 253, 5, 36,
                    ],
                    [
                        88, 167, 43, 228, 27, 171, 200, 242, 68, 163, 11, 145, 181, 136, 160, 131,
                        255, 77, 38, 123,
                    ],
                    [
                        185, 56, 28, 166, 0, 123, 145, 226, 185, 150, 175, 138, 235, 212, 180, 28,
                        74, 45, 146, 151,
                    ],
                    [
                        32, 13, 202, 36, 190, 150, 174, 67, 89, 41, 250, 234, 247, 73, 83, 253,
                        104, 219, 74, 147,
                    ],
                    [
                        159, 18, 110, 11, 51, 27, 207, 86, 58, 120, 188, 96, 25, 64, 18, 81, 64,
                        84, 199, 189,
                    ],
                    [
                        55, 246, 125, 43, 176, 191, 37, 24, 231, 170, 222, 168, 227, 131, 237, 238,
                        159, 92, 83, 85,
                    ],
                    [
                        241, 93, 164, 137, 204, 241, 152, 222, 221, 82, 54, 92, 10, 188, 197, 180,
                        222, 63, 57, 156,
                    ],
                    [
                        232, 53, 169, 238, 20, 184, 10, 181, 93, 211, 214, 31, 71, 55, 100, 104,
                        199, 106, 120, 127,
                    ],
                    [
                        253, 180, 151, 15, 201, 20, 163, 155, 24, 166, 95, 105, 216, 15, 106, 108,
                        40, 247, 19, 78,
                    ],
                    [
                        146, 235, 17, 133, 137, 94, 193, 88, 221, 150, 112, 122, 83, 211, 58, 137,
                        41, 127, 205, 175,
                    ],
                    [
                        83, 120, 227, 87, 183, 139, 90, 79, 162, 95, 245, 232, 101, 249, 23, 168,
                        195, 14, 203, 160,
                    ],
                    [
                        99, 190, 57, 226, 149, 155, 214, 205, 103, 32, 58, 63, 65, 163, 142, 231,
                        146, 198, 174, 177,
                    ],
                    [
                        201, 171, 56, 126, 113, 160, 8, 28, 31, 172, 218, 152, 110, 119, 181, 147,
                        217, 132, 3, 148,
                    ],
                    [
                        185, 56, 235, 254, 229, 19, 160, 59, 239, 213, 27, 180, 235, 157, 96, 252,
                        27, 104, 83, 66,
                    ],
                    [
                        41, 79, 124, 163, 192, 241, 28, 111, 134, 215, 74, 185, 114, 69, 49, 203,
                        135, 20, 175, 99,
                    ],
                    [
                        70, 179, 145, 183, 23, 127, 89, 135, 165, 191, 145, 248, 10, 190, 224, 75,
                        17, 214, 193, 225,
                    ],
                    [
                        152, 38, 242, 163, 224, 215, 113, 236, 186, 206, 179, 127, 229, 72, 196,
                        124, 181, 43, 80, 107,
                    ],
                    [
                        133, 201, 21, 110, 1, 19, 230, 147, 175, 225, 82, 250, 11, 53, 15, 158, 81,
                        60, 202, 174,
                    ],
                    [
                        61, 164, 6, 90, 208, 117, 80, 122, 248, 137, 100, 59, 196, 73, 48, 190, 5,
                        158, 208, 255,
                    ],
                    [
                        237, 201, 36, 36, 97, 26, 203, 224, 213, 83, 31, 68, 152, 88, 186, 73, 76,
                        42, 196, 58,
                    ],
                    [
                        14, 44, 144, 79, 188, 235, 204, 67, 74, 246, 119, 148, 97, 218, 195, 149,
                        65, 123, 179, 134,
                    ],
                    [
                        32, 97, 81, 7, 201, 58, 175, 221, 38, 221, 243, 177, 72, 242, 137, 181, 70,
                        245, 98, 154,
                    ],
                    [
                        69, 161, 236, 90, 239, 32, 187, 49, 55, 0, 29, 15, 119, 213, 125, 81, 231,
                        14, 4, 18,
                    ],
                    [
                        3, 60, 198, 145, 33, 187, 94, 227, 164, 190, 118, 168, 248, 143, 115, 18,
                        205, 35, 109, 66,
                    ],
                    [
                        57, 176, 29, 43, 173, 49, 77, 233, 227, 193, 111, 110, 137, 2, 105, 198,
                        253, 173, 236, 0,
                    ],
                    [
                        172, 88, 236, 188, 231, 55, 58, 221, 212, 109, 7, 77, 136, 141, 24, 156,
                        119, 117, 225, 255,
                    ],
                    [
                        112, 67, 90, 109, 240, 14, 73, 154, 183, 50, 195, 81, 246, 191, 219, 54,
                        25, 220, 202, 67,
                    ],
                    [
                        33, 248, 35, 137, 18, 173, 172, 174, 172, 48, 77, 25, 157, 179, 63, 57, 23,
                        127, 28, 145,
                    ],
                    [
                        201, 248, 4, 26, 0, 151, 8, 117, 149, 186, 89, 57, 61, 217, 13, 159, 173,
                        236, 45, 61,
                    ],
                    [
                        136, 178, 53, 99, 25, 204, 184, 231, 140, 217, 199, 250, 46, 222, 82, 30,
                        112, 179, 227, 137,
                    ],
                    [
                        184, 219, 169, 103, 13, 88, 179, 165, 234, 81, 77, 76, 245, 194, 222, 216,
                        88, 241, 23, 63,
                    ],
                    [
                        186, 29, 115, 187, 172, 176, 209, 242, 223, 109, 221, 89, 203, 125, 187,
                        148, 125, 92, 177, 96,
                    ],
                    [
                        95, 82, 185, 25, 198, 250, 53, 214, 162, 39, 231, 117, 80, 150, 130, 176,
                        4, 145, 166, 15,
                    ],
                    [
                        23, 26, 62, 10, 13, 167, 46, 152, 194, 112, 190, 172, 177, 233, 186, 123,
                        204, 23, 59, 137,
                    ],
                    [
                        40, 1, 148, 107, 187, 94, 65, 166, 147, 60, 60, 211, 121, 175, 141, 231,
                        29, 65, 99, 21,
                    ],
                    [
                        36, 41, 46, 105, 42, 33, 234, 41, 194, 201, 111, 165, 226, 61, 63, 165, 34,
                        115, 142, 138,
                    ],
                    [
                        122, 106, 99, 86, 225, 80, 119, 166, 189, 158, 52, 19, 159, 101, 127, 120,
                        5, 139, 41, 223,
                    ],
                    [
                        121, 170, 46, 123, 189, 187, 140, 161, 110, 200, 26, 197, 237, 181, 251,
                        120, 97, 98, 169, 151,
                    ],
                    [
                        175, 215, 225, 196, 146, 79, 48, 83, 134, 177, 89, 59, 41, 132, 72, 2, 4,
                        140, 223, 117,
                    ],
                    [
                        251, 247, 91, 23, 85, 124, 107, 124, 82, 143, 197, 47, 50, 35, 42, 7, 219,
                        206, 214, 130,
                    ],
                    [
                        25, 197, 40, 117, 34, 185, 27, 152, 126, 58, 234, 79, 87, 20, 92, 50, 235,
                        181, 188, 48,
                    ],
                    [
                        135, 188, 166, 192, 38, 35, 158, 95, 111, 74, 191, 56, 25, 134, 243, 231,
                        149, 190, 127, 81,
                    ],
                    [
                        34, 47, 90, 34, 29, 36, 53, 229, 23, 237, 130, 65, 215, 91, 133, 14, 57, 0,
                        131, 121,
                    ],
                    [
                        217, 148, 184, 0, 132, 5, 150, 126, 201, 231, 203, 212, 134, 33, 36, 159,
                        206, 156, 216, 89,
                    ],
                    [
                        38, 96, 236, 20, 212, 134, 130, 252, 29, 23, 172, 14, 213, 29, 227, 210,
                        19, 108, 118, 205,
                    ],
                    [
                        143, 181, 105, 32, 49, 82, 192, 234, 169, 204, 86, 108, 65, 181, 143, 153,
                        198, 139, 245, 179,
                    ],
                    [
                        163, 10, 237, 14, 83, 43, 213, 212, 103, 30, 112, 186, 129, 46, 125, 127,
                        146, 5, 76, 119,
                    ],
                    [
                        51, 210, 150, 138, 17, 152, 163, 157, 40, 43, 106, 175, 11, 105, 210, 157,
                        248, 95, 233, 233,
                    ],
                    [
                        18, 193, 127, 175, 25, 0, 125, 2, 174, 130, 15, 142, 156, 69, 53, 178, 16,
                        238, 65, 128,
                    ],
                    [
                        190, 201, 206, 16, 161, 148, 177, 199, 213, 163, 26, 190, 18, 253, 163,
                        157, 5, 188, 24, 125,
                    ],
                    [
                        28, 140, 235, 10, 190, 66, 170, 203, 29, 83, 163, 18, 110, 45, 117, 238,
                        115, 126, 22, 80,
                    ],
                    [
                        3, 156, 109, 55, 124, 173, 51, 206, 214, 203, 0, 7, 119, 168, 196, 130,
                        107, 47, 31, 143,
                    ],
                    [
                        25, 148, 153, 222, 199, 209, 105, 252, 61, 124, 189, 6, 13, 87, 39, 24,
                        152, 39, 181, 52,
                    ],
                    [
                        194, 56, 68, 15, 51, 25, 57, 246, 9, 207, 22, 131, 125, 139, 51, 17, 51,
                        49, 240, 139,
                    ],
                    [
                        58, 34, 159, 198, 93, 122, 217, 72, 147, 245, 67, 237, 190, 92, 115, 85,
                        71, 239, 162, 202,
                    ],
                    [
                        110, 88, 219, 192, 165, 97, 138, 112, 145, 38, 13, 118, 132, 165, 14, 24,
                        148, 38, 116, 59,
                    ],
                    [
                        12, 115, 109, 170, 156, 8, 168, 218, 110, 170, 209, 231, 157, 34, 108, 95,
                        57, 74, 22, 228,
                    ],
                    [
                        90, 8, 162, 206, 41, 189, 35, 0, 201, 204, 230, 201, 194, 12, 44, 12, 192,
                        157, 50, 199,
                    ],
                    [
                        127, 200, 190, 118, 79, 24, 185, 107, 75, 195, 198, 236, 126, 165, 213, 75,
                        164, 156, 253, 74,
                    ],
                    [
                        151, 225, 110, 109, 40, 94, 147, 97, 111, 105, 118, 57, 71, 22, 225, 98,
                        76, 249, 248, 221,
                    ],
                    [
                        11, 44, 203, 205, 110, 107, 118, 65, 196, 5, 6, 37, 115, 201, 32, 56, 23,
                        243, 27, 64,
                    ],
                    [
                        242, 70, 54, 162, 180, 132, 118, 91, 10, 75, 152, 106, 120, 92, 5, 252, 89,
                        230, 142, 186,
                    ],
                    [
                        23, 54, 247, 188, 229, 133, 35, 45, 127, 8, 177, 66, 213, 24, 129, 26, 174,
                        97, 201, 158,
                    ],
                    [
                        225, 234, 107, 140, 31, 217, 72, 94, 134, 83, 82, 240, 79, 52, 63, 75, 39,
                        133, 171, 33,
                    ],
                    [
                        123, 113, 112, 178, 53, 28, 44, 42, 1, 187, 175, 248, 241, 233, 42, 120,
                        133, 104, 40, 103,
                    ],
                    [
                        160, 245, 45, 79, 110, 139, 217, 76, 248, 67, 0, 149, 145, 11, 224, 113,
                        132, 47, 241, 198,
                    ],
                    [
                        53, 251, 184, 136, 140, 242, 182, 14, 239, 119, 92, 99, 155, 178, 167, 88,
                        192, 218, 27, 65,
                    ],
                    [
                        237, 158, 33, 226, 168, 92, 204, 63, 39, 112, 239, 162, 163, 19, 60, 221,
                        92, 233, 105, 27,
                    ],
                    [
                        122, 66, 106, 213, 73, 187, 66, 248, 59, 53, 155, 137, 114, 131, 145, 29,
                        229, 108, 180, 165,
                    ],
                    [
                        46, 116, 130, 94, 170, 166, 250, 14, 153, 88, 162, 147, 220, 250, 165, 44,
                        53, 17, 154, 244,
                    ],
                    [
                        23, 15, 156, 57, 36, 253, 219, 180, 166, 70, 101, 228, 113, 146, 169, 183,
                        196, 149, 250, 7,
                    ],
                    [
                        199, 5, 58, 57, 130, 3, 96, 207, 111, 51, 73, 105, 37, 149, 7, 31, 175, 90,
                        119, 89,
                    ],
                    [
                        84, 85, 75, 44, 40, 117, 199, 159, 179, 159, 10, 206, 78, 160, 145, 174,
                        229, 237, 161, 96,
                    ],
                    [
                        206, 33, 102, 255, 221, 226, 21, 152, 201, 102, 237, 61, 167, 81, 247, 8,
                        130, 91, 56, 19,
                    ],
                    [
                        226, 199, 116, 238, 166, 170, 148, 45, 210, 113, 103, 153, 126, 245, 137,
                        94, 71, 110, 149, 17,
                    ],
                    [
                        61, 194, 201, 20, 174, 93, 188, 27, 77, 98, 141, 38, 49, 124, 134, 9, 90,
                        23, 94, 134,
                    ],
                    [
                        77, 87, 24, 216, 222, 165, 233, 82, 24, 59, 211, 171, 115, 92, 62, 141,
                        242, 209, 137, 144,
                    ],
                    [
                        73, 183, 92, 60, 50, 208, 182, 206, 46, 73, 154, 147, 225, 62, 213, 1, 149,
                        150, 138, 214,
                    ],
                    [
                        201, 174, 3, 127, 102, 56, 249, 28, 22, 39, 147, 131, 159, 41, 157, 50,
                        175, 211, 73, 108,
                    ],
                    [
                        180, 110, 50, 170, 63, 242, 4, 9, 230, 244, 151, 54, 152, 123, 251, 233,
                        255, 46, 66, 35,
                    ],
                    [
                        136, 146, 60, 108, 53, 186, 88, 159, 174, 68, 250, 211, 78, 115, 88, 169,
                        10, 35, 161, 209,
                    ],
                    [
                        3, 41, 103, 104, 247, 30, 192, 153, 84, 168, 144, 74, 91, 152, 16, 18, 206,
                        210, 160, 245,
                    ],
                    [
                        101, 246, 59, 11, 130, 215, 126, 98, 222, 214, 219, 20, 74, 208, 77, 124,
                        83, 140, 25, 249,
                    ],
                    [
                        88, 246, 246, 52, 71, 83, 69, 166, 211, 172, 173, 0, 49, 74, 184, 128, 45,
                        151, 59, 46,
                    ],
                    [
                        149, 181, 45, 147, 53, 169, 66, 235, 251, 254, 254, 56, 165, 82, 90, 100,
                        250, 144, 245, 145,
                    ],
                    [
                        5, 204, 230, 134, 68, 100, 195, 7, 97, 67, 171, 80, 170, 200, 112, 212,
                        164, 111, 206, 55,
                    ],
                    [
                        128, 194, 212, 172, 143, 186, 166, 125, 105, 229, 165, 163, 230, 95, 76, 9,
                        76, 224, 144, 84,
                    ],
                    [
                        51, 102, 234, 157, 217, 101, 55, 66, 85, 17, 128, 14, 136, 28, 27, 163, 33,
                        70, 1, 196,
                    ],
                    [
                        149, 207, 213, 44, 61, 227, 0, 29, 102, 229, 126, 232, 130, 49, 136, 153,
                        123, 40, 60, 112,
                    ],
                    [
                        100, 59, 253, 29, 214, 57, 164, 66, 231, 48, 20, 205, 148, 131, 247, 254,
                        206, 45, 45, 199,
                    ],
                    [
                        45, 213, 219, 103, 205, 119, 122, 209, 191, 138, 16, 95, 71, 165, 66, 78,
                        114, 44, 125, 247,
                    ],
                    [
                        215, 14, 48, 101, 173, 194, 185, 178, 109, 209, 158, 186, 161, 99, 94, 163,
                        127, 7, 141, 242,
                    ],
                    [
                        39, 44, 83, 6, 208, 86, 215, 75, 14, 89, 56, 241, 244, 188, 198, 190, 225,
                        113, 139, 219,
                    ],
                    [
                        104, 2, 156, 113, 64, 131, 10, 31, 91, 144, 9, 233, 102, 214, 158, 178, 3,
                        142, 53, 153,
                    ],
                    [
                        53, 189, 32, 45, 106, 151, 232, 246, 95, 36, 201, 57, 223, 206, 88, 129,
                        118, 248, 130, 3,
                    ],
                    [
                        80, 111, 224, 176, 67, 206, 220, 251, 182, 56, 255, 3, 95, 144, 93, 92, 26,
                        180, 152, 201,
                    ],
                    [
                        12, 76, 102, 223, 222, 224, 232, 40, 150, 64, 105, 177, 28, 100, 174, 150,
                        0, 92, 71, 24,
                    ],
                    [
                        121, 175, 225, 192, 25, 146, 93, 41, 219, 26, 164, 86, 243, 162, 9, 6, 4,
                        86, 59, 49,
                    ],
                    [
                        141, 88, 22, 206, 3, 131, 108, 227, 89, 169, 21, 33, 65, 155, 155, 143, 96,
                        150, 75, 23,
                    ],
                    [
                        45, 146, 53, 30, 165, 115, 81, 205, 24, 208, 76, 41, 202, 7, 151, 95, 47,
                        186, 132, 220,
                    ],
                    [
                        75, 91, 189, 76, 208, 149, 197, 154, 195, 205, 238, 222, 140, 34, 16, 167,
                        252, 24, 208, 63,
                    ],
                    [
                        150, 141, 82, 193, 49, 194, 11, 229, 61, 187, 45, 13, 26, 26, 225, 252,
                        224, 92, 94, 111,
                    ],
                    [
                        215, 239, 188, 104, 11, 177, 39, 181, 74, 148, 252, 155, 203, 70, 190, 89,
                        70, 86, 250, 250,
                    ],
                    [
                        85, 148, 4, 65, 39, 191, 143, 150, 34, 199, 211, 120, 239, 47, 55, 8, 65,
                        17, 167, 63,
                    ],
                    [
                        142, 5, 201, 3, 38, 106, 33, 71, 1, 173, 197, 16, 116, 206, 150, 201, 157,
                        191, 135, 45,
                    ],
                    [
                        56, 116, 82, 223, 14, 83, 24, 135, 73, 200, 227, 170, 77, 3, 20, 102, 251,
                        28, 17, 151,
                    ],
                    [
                        122, 143, 30, 76, 219, 58, 15, 172, 243, 248, 188, 244, 211, 32, 248, 9,
                        245, 45, 34, 163,
                    ],
                    [
                        33, 28, 212, 216, 41, 116, 13, 236, 17, 185, 152, 184, 80, 28, 54, 6, 219,
                        14, 183, 219,
                    ],
                    [
                        105, 202, 82, 163, 138, 104, 219, 212, 193, 92, 7, 221, 228, 192, 161, 106,
                        212, 94, 93, 56,
                    ],
                    [
                        97, 121, 36, 206, 177, 117, 141, 2, 96, 154, 227, 61, 20, 158, 243, 40, 29,
                        38, 244, 147,
                    ],
                    [
                        26, 124, 37, 90, 20, 129, 193, 85, 175, 21, 34, 159, 143, 29, 216, 247, 20,
                        140, 178, 110,
                    ],
                    [
                        157, 216, 235, 191, 228, 191, 207, 118, 38, 130, 90, 52, 195, 12, 117, 146,
                        38, 216, 111, 96,
                    ],
                    [
                        26, 114, 233, 134, 3, 41, 124, 220, 235, 216, 95, 103, 253, 201, 82, 138,
                        28, 31, 246, 86,
                    ],
                    [
                        233, 29, 12, 63, 241, 145, 141, 153, 103, 103, 13, 117, 136, 195, 213, 177,
                        76, 3, 60, 74,
                    ],
                    [
                        75, 79, 93, 254, 173, 37, 77, 226, 205, 107, 133, 154, 101, 21, 200, 242,
                        118, 237, 212, 118,
                    ],
                    [
                        80, 35, 97, 157, 240, 41, 229, 223, 183, 226, 34, 96, 215, 212, 247, 122,
                        84, 38, 63, 203,
                    ],
                    [
                        145, 106, 229, 159, 163, 236, 185, 37, 25, 124, 137, 26, 1, 154, 3, 204,
                        144, 52, 184, 77,
                    ],
                    [
                        66, 190, 210, 70, 254, 237, 191, 124, 20, 243, 129, 167, 35, 233, 125, 107,
                        141, 114, 10, 189,
                    ],
                    [
                        217, 154, 70, 47, 199, 229, 242, 95, 186, 20, 105, 143, 124, 97, 123, 205,
                        99, 200, 88, 21,
                    ],
                    [
                        207, 193, 125, 50, 84, 205, 126, 251, 142, 85, 119, 19, 31, 35, 178, 122,
                        73, 220, 87, 248,
                    ],
                    [
                        178, 138, 52, 143, 50, 48, 198, 2, 226, 93, 91, 90, 239, 189, 117, 115, 56,
                        112, 21, 113,
                    ],
                    [
                        178, 191, 209, 9, 215, 57, 219, 117, 178, 220, 42, 175, 192, 62, 26, 36,
                        133, 155, 90, 136,
                    ],
                    [
                        174, 16, 249, 115, 187, 144, 231, 170, 89, 141, 113, 125, 123, 163, 239,
                        141, 86, 85, 212, 213,
                    ],
                    [
                        70, 156, 189, 185, 183, 182, 105, 85, 189, 203, 10, 226, 82, 8, 76, 199,
                        78, 6, 161, 27,
                    ],
                    [
                        78, 196, 103, 113, 7, 94, 20, 202, 249, 242, 80, 39, 191, 16, 157, 155,
                        220, 44, 113, 115,
                    ],
                    [
                        218, 46, 24, 218, 238, 122, 84, 103, 136, 167, 25, 44, 112, 171, 147, 77,
                        160, 220, 134, 196,
                    ],
                    [
                        121, 115, 62, 176, 218, 17, 119, 137, 191, 121, 93, 140, 222, 121, 159,
                        252, 122, 155, 168, 204,
                    ],
                    [
                        242, 219, 34, 61, 141, 47, 2, 154, 65, 140, 233, 228, 66, 212, 169, 154,
                        121, 186, 11, 52,
                    ],
                    [
                        140, 28, 202, 1, 186, 212, 104, 184, 154, 26, 9, 185, 115, 79, 57, 41, 42,
                        255, 166, 129,
                    ],
                    [
                        220, 60, 17, 69, 255, 195, 212, 196, 141, 175, 95, 101, 71, 14, 192, 69,
                        223, 123, 35, 98,
                    ],
                    [
                        51, 246, 193, 118, 39, 231, 114, 137, 99, 210, 28, 146, 42, 114, 113, 244,
                        55, 134, 0, 30,
                    ],
                    [
                        25, 156, 225, 34, 206, 165, 42, 19, 67, 84, 29, 187, 220, 39, 105, 237, 82,
                        85, 9, 244,
                    ],
                    [
                        39, 235, 131, 172, 101, 229, 24, 50, 41, 254, 252, 161, 246, 244, 26, 111,
                        209, 118, 221, 0,
                    ],
                    [
                        221, 35, 85, 251, 184, 88, 5, 186, 147, 243, 221, 82, 147, 39, 35, 68, 248,
                        116, 201, 186,
                    ],
                    [
                        43, 249, 129, 217, 61, 62, 243, 163, 151, 109, 90, 177, 202, 213, 146, 95,
                        226, 110, 95, 88,
                    ],
                    [
                        222, 173, 37, 125, 214, 81, 129, 79, 35, 160, 16, 30, 128, 26, 31, 217,
                        167, 26, 255, 42,
                    ],
                    [
                        163, 19, 160, 75, 1, 133, 166, 5, 140, 96, 55, 5, 72, 220, 140, 178, 127,
                        17, 144, 186,
                    ],
                    [
                        228, 210, 73, 41, 222, 210, 65, 225, 203, 0, 172, 183, 8, 102, 178, 51,
                        222, 170, 61, 201,
                    ],
                    [
                        160, 217, 4, 206, 182, 239, 253, 61, 203, 154, 131, 173, 5, 231, 199, 122,
                        219, 140, 247, 227,
                    ],
                    [
                        107, 122, 246, 12, 189, 61, 69, 148, 129, 82, 196, 158, 255, 2, 223, 174,
                        95, 86, 113, 224,
                    ],
                    [
                        7, 18, 29, 75, 52, 12, 0, 133, 158, 32, 159, 246, 35, 135, 245, 171, 184,
                        51, 53, 12,
                    ],
                    [
                        51, 181, 60, 65, 217, 81, 76, 172, 65, 5, 87, 116, 64, 125, 127, 92, 15,
                        128, 247, 92,
                    ],
                    [
                        111, 77, 89, 218, 83, 164, 54, 219, 193, 177, 89, 40, 178, 143, 230, 37,
                        114, 125, 245, 4,
                    ],
                    [
                        226, 249, 120, 227, 21, 177, 116, 199, 210, 78, 245, 252, 89, 215, 35, 100,
                        78, 67, 89, 200,
                    ],
                    [
                        101, 252, 250, 199, 160, 238, 170, 24, 106, 85, 138, 226, 212, 108, 72, 1,
                        124, 152, 45, 21,
                    ],
                    [
                        206, 103, 27, 10, 85, 168, 163, 204, 229, 81, 60, 219, 32, 175, 163, 23,
                        64, 8, 42, 115,
                    ],
                    [
                        132, 3, 6, 145, 20, 140, 191, 206, 219, 158, 135, 130, 182, 109, 75, 166,
                        16, 44, 247, 166,
                    ],
                    [
                        114, 179, 175, 88, 143, 162, 180, 244, 122, 150, 237, 57, 120, 158, 251,
                        233, 85, 226, 38, 205,
                    ],
                    [
                        86, 162, 29, 26, 178, 254, 224, 101, 120, 167, 254, 167, 31, 118, 54, 115,
                        144, 102, 47, 75,
                    ],
                    [
                        36, 141, 99, 207, 113, 50, 120, 207, 121, 86, 87, 137, 37, 169, 244, 97,
                        105, 203, 157, 60,
                    ],
                    [
                        71, 18, 14, 159, 8, 188, 67, 185, 199, 114, 76, 238, 80, 205, 83, 157, 157,
                        17, 16, 152,
                    ],
                    [
                        56, 9, 144, 107, 186, 80, 48, 90, 92, 87, 111, 45, 190, 145, 88, 228, 242,
                        60, 14, 230,
                    ],
                    [
                        124, 253, 102, 246, 19, 100, 237, 33, 201, 4, 238, 29, 40, 112, 252, 118,
                        51, 159, 9, 149,
                    ],
                    [
                        49, 103, 206, 194, 129, 184, 93, 124, 203, 246, 2, 167, 12, 21, 178, 59,
                        105, 201, 23, 112,
                    ],
                    [
                        53, 135, 18, 155, 128, 70, 19, 192, 27, 112, 209, 176, 108, 65, 55, 86,
                        112, 115, 205, 25,
                    ],
                    [
                        209, 10, 232, 70, 249, 1, 111, 23, 213, 140, 224, 208, 232, 80, 85, 52,
                        129, 45, 70, 250,
                    ],
                    [
                        87, 166, 12, 203, 163, 226, 98, 204, 156, 119, 211, 40, 239, 177, 5, 77,
                        134, 242, 26, 163,
                    ],
                    [
                        32, 11, 11, 214, 248, 38, 92, 11, 234, 243, 34, 117, 178, 181, 187, 201,
                        93, 150, 95, 249,
                    ],
                    [
                        77, 200, 34, 243, 8, 124, 105, 158, 56, 147, 239, 126, 67, 83, 11, 250,
                        149, 189, 126, 100,
                    ],
                    [
                        136, 228, 138, 195, 242, 31, 212, 114, 6, 233, 219, 197, 210, 219, 245,
                        173, 247, 42, 223, 246,
                    ],
                    [
                        125, 154, 184, 126, 202, 132, 253, 140, 131, 14, 133, 162, 242, 121, 144,
                        7, 225, 242, 91, 242,
                    ],
                    [
                        123, 162, 76, 166, 27, 224, 89, 15, 255, 45, 194, 115, 196, 28, 177, 104,
                        146, 118, 175, 201,
                    ],
                    [
                        222, 221, 30, 84, 51, 21, 51, 68, 60, 225, 87, 97, 57, 56, 52, 234, 110,
                        134, 188, 181,
                    ],
                    [
                        48, 2, 231, 46, 240, 192, 74, 21, 162, 13, 9, 207, 130, 197, 38, 167, 41,
                        156, 203, 147,
                    ],
                    [
                        69, 114, 172, 85, 164, 195, 38, 190, 130, 161, 158, 224, 217, 248, 41, 72,
                        189, 108, 25, 37,
                    ],
                    [
                        218, 199, 58, 203, 246, 159, 139, 78, 94, 171, 46, 142, 100, 209, 83, 225,
                        226, 218, 176, 252,
                    ],
                    [
                        97, 144, 184, 253, 32, 170, 113, 178, 114, 111, 82, 77, 201, 0, 214, 207,
                        189, 182, 228, 25,
                    ],
                    [
                        213, 153, 254, 1, 126, 24, 0, 157, 212, 93, 187, 174, 196, 15, 176, 193,
                        145, 253, 175, 90,
                    ],
                    [
                        23, 152, 148, 244, 126, 213, 223, 51, 183, 252, 252, 61, 145, 158, 164, 0,
                        124, 40, 141, 231,
                    ],
                    [
                        173, 158, 65, 181, 251, 157, 222, 245, 56, 209, 84, 194, 112, 235, 104, 76,
                        57, 190, 91, 172,
                    ],
                    [
                        208, 246, 72, 120, 132, 246, 248, 82, 144, 117, 73, 104, 180, 224, 55, 51,
                        59, 241, 172, 43,
                    ],
                    [
                        209, 220, 151, 122, 116, 101, 52, 111, 43, 54, 221, 31, 158, 147, 154, 216,
                        86, 40, 132, 24,
                    ],
                    [
                        197, 155, 21, 153, 232, 101, 119, 11, 221, 214, 9, 196, 69, 155, 233, 166,
                        125, 100, 112, 187,
                    ],
                    [
                        166, 80, 45, 49, 84, 123, 195, 246, 10, 247, 218, 162, 148, 30, 77, 112,
                        252, 27, 45, 82,
                    ],
                    [
                        20, 115, 98, 171, 180, 107, 22, 142, 17, 111, 209, 144, 136, 27, 92, 198,
                        168, 41, 147, 30,
                    ],
                    [
                        250, 201, 51, 153, 38, 217, 58, 30, 4, 180, 90, 7, 216, 0, 141, 42, 152, 2,
                        14, 217,
                    ],
                    [
                        129, 57, 85, 128, 138, 43, 8, 94, 148, 152, 191, 4, 158, 245, 247, 40, 215,
                        68, 25, 27,
                    ],
                    [
                        50, 228, 143, 152, 212, 16, 142, 54, 0, 116, 113, 211, 93, 99, 170, 85, 93,
                        205, 174, 193,
                    ],
                    [
                        229, 231, 49, 106, 61, 110, 61, 158, 37, 86, 82, 200, 251, 143, 182, 188,
                        25, 196, 7, 71,
                    ],
                    [
                        255, 11, 195, 153, 108, 173, 154, 8, 202, 251, 3, 144, 209, 143, 6, 49,
                        137, 132, 5, 87,
                    ],
                    [
                        42, 134, 28, 47, 250, 154, 4, 224, 136, 72, 168, 228, 244, 136, 245, 61,
                        74, 68, 216, 246,
                    ],
                    [
                        103, 108, 220, 46, 203, 213, 69, 83, 93, 165, 172, 125, 235, 89, 141, 159,
                        42, 209, 99, 146,
                    ],
                    [
                        120, 30, 240, 78, 57, 221, 83, 9, 146, 137, 19, 158, 91, 45, 225, 189, 252,
                        213, 138, 200,
                    ],
                    [
                        232, 51, 58, 215, 252, 20, 144, 169, 213, 114, 122, 215, 86, 233, 7, 153,
                        67, 166, 67, 247,
                    ],
                    [
                        1, 5, 138, 187, 175, 226, 9, 52, 51, 157, 97, 117, 136, 221, 101, 204, 111,
                        21, 136, 42,
                    ],
                    [
                        174, 190, 52, 69, 229, 46, 209, 152, 89, 94, 73, 70, 156, 3, 217, 82, 66,
                        221, 174, 35,
                    ],
                    [
                        103, 209, 137, 161, 249, 47, 144, 44, 23, 219, 36, 251, 242, 199, 207, 15,
                        84, 141, 184, 98,
                    ],
                    [
                        118, 103, 119, 125, 15, 252, 64, 103, 137, 196, 193, 158, 66, 115, 133, 6,
                        81, 114, 81, 255,
                    ],
                    [
                        47, 248, 213, 117, 212, 165, 227, 87, 82, 66, 215, 252, 57, 29, 169, 117,
                        23, 121, 99, 66,
                    ],
                    [
                        245, 136, 90, 252, 84, 32, 26, 167, 126, 113, 166, 182, 236, 0, 126, 88,
                        63, 181, 228, 218,
                    ],
                    [
                        131, 161, 196, 185, 167, 35, 47, 129, 200, 46, 91, 123, 33, 171, 14, 95,
                        254, 188, 181, 4,
                    ],
                    [
                        87, 123, 180, 237, 69, 160, 29, 208, 23, 146, 18, 149, 169, 88, 104, 46,
                        151, 162, 73, 229,
                    ],
                    [
                        148, 192, 169, 132, 102, 121, 142, 71, 35, 151, 17, 237, 224, 157, 237, 58,
                        177, 194, 160, 191,
                    ],
                    [
                        163, 119, 163, 74, 233, 49, 202, 253, 143, 234, 36, 158, 115, 95, 25, 211,
                        202, 137, 14, 247,
                    ],
                    [
                        255, 114, 63, 121, 88, 214, 160, 122, 184, 80, 135, 228, 148, 149, 66, 102,
                        55, 125, 122, 141,
                    ],
                    [
                        109, 31, 73, 52, 33, 64, 9, 93, 118, 200, 202, 115, 41, 234, 128, 54, 51,
                        10, 179, 87,
                    ],
                    [
                        224, 204, 176, 2, 74, 150, 240, 146, 181, 48, 141, 16, 226, 199, 254, 36,
                        80, 51, 24, 145,
                    ],
                    [
                        84, 137, 79, 68, 121, 70, 52, 8, 243, 242, 178, 93, 131, 42, 139, 134, 219,
                        54, 42, 57,
                    ],
                    [
                        171, 39, 158, 34, 201, 35, 208, 79, 231, 46, 245, 238, 33, 252, 38, 105,
                        47, 167, 253, 120,
                    ],
                    [
                        204, 133, 118, 10, 54, 235, 7, 60, 171, 255, 40, 96, 252, 183, 192, 41,
                        238, 125, 110, 204,
                    ],
                    [
                        9, 80, 83, 148, 80, 73, 82, 74, 206, 202, 22, 179, 231, 179, 42, 175, 157,
                        253, 178, 66,
                    ],
                    [
                        144, 213, 75, 170, 233, 173, 45, 215, 166, 250, 47, 128, 206, 82, 205, 151,
                        9, 161, 87, 21,
                    ],
                    [
                        16, 52, 81, 193, 234, 95, 167, 116, 20, 182, 19, 104, 249, 123, 64, 4, 127,
                        238, 38, 69,
                    ],
                    [
                        253, 13, 87, 121, 157, 26, 76, 48, 105, 149, 82, 217, 98, 59, 88, 250, 150,
                        181, 150, 146,
                    ],
                    [
                        133, 86, 245, 215, 211, 170, 84, 219, 38, 10, 209, 26, 167, 144, 177, 135,
                        237, 179, 206, 127,
                    ],
                    [
                        129, 197, 168, 33, 184, 121, 197, 9, 137, 181, 252, 185, 161, 8, 230, 183,
                        2, 110, 99, 89,
                    ],
                    [
                        166, 220, 213, 143, 67, 89, 54, 79, 172, 194, 243, 91, 215, 231, 179, 98,
                        54, 245, 216, 33,
                    ],
                    [
                        195, 206, 12, 89, 154, 82, 92, 153, 54, 200, 119, 113, 96, 72, 9, 182, 87,
                        126, 43, 150,
                    ],
                    [
                        95, 29, 165, 251, 183, 61, 60, 220, 96, 255, 156, 23, 255, 25, 32, 105,
                        208, 220, 184, 51,
                    ],
                    [
                        228, 38, 240, 235, 41, 18, 120, 152, 141, 243, 131, 99, 72, 175, 199, 68,
                        153, 123, 150, 199,
                    ],
                    [
                        23, 99, 230, 164, 252, 159, 78, 238, 44, 167, 120, 65, 8, 250, 253, 141,
                        52, 245, 158, 1,
                    ],
                    [
                        95, 105, 2, 129, 254, 170, 194, 210, 185, 15, 131, 83, 60, 65, 60, 3, 167,
                        255, 201, 24,
                    ],
                    [
                        59, 140, 240, 94, 126, 193, 169, 116, 109, 72, 248, 235, 53, 73, 128, 238,
                        173, 92, 149, 64,
                    ],
                    [
                        97, 142, 202, 89, 12, 246, 212, 178, 114, 71, 225, 175, 116, 139, 203, 77,
                        232, 51, 93, 184,
                    ],
                    [
                        167, 11, 41, 186, 187, 140, 184, 102, 64, 166, 127, 252, 69, 195, 33, 40,
                        194, 34, 111, 55,
                    ],
                    [
                        40, 0, 16, 53, 66, 1, 107, 44, 108, 218, 209, 98, 185, 5, 244, 82, 120, 49,
                        149, 15,
                    ],
                    [
                        248, 191, 50, 96, 74, 176, 157, 102, 144, 178, 159, 75, 66, 149, 206, 164,
                        194, 87, 70, 251,
                    ],
                    [
                        233, 159, 194, 217, 202, 69, 202, 121, 200, 239, 215, 40, 91, 183, 28, 220,
                        3, 119, 40, 44,
                    ],
                    [
                        170, 97, 207, 243, 77, 97, 107, 135, 201, 71, 25, 152, 143, 6, 250, 237,
                        28, 194, 178, 180,
                    ],
                    [
                        238, 16, 23, 115, 67, 146, 217, 7, 91, 115, 109, 112, 102, 62, 171, 221,
                        252, 189, 213, 92,
                    ],
                    [
                        104, 53, 240, 42, 18, 159, 199, 205, 91, 207, 225, 131, 238, 127, 203, 165,
                        89, 49, 121, 85,
                    ],
                    [
                        86, 232, 151, 55, 59, 23, 109, 8, 122, 10, 83, 250, 147, 145, 117, 50, 96,
                        9, 89, 40,
                    ],
                    [
                        185, 71, 0, 47, 250, 12, 102, 221, 74, 52, 157, 13, 26, 76, 18, 122, 68,
                        223, 38, 124,
                    ],
                    [
                        167, 189, 128, 22, 109, 250, 119, 167, 110, 197, 34, 246, 174, 242, 116,
                        245, 63, 210, 198, 18,
                    ],
                    [
                        21, 71, 157, 13, 174, 22, 227, 201, 171, 181, 17, 222, 198, 147, 38, 120,
                        167, 15, 36, 57,
                    ],
                    [
                        136, 225, 155, 164, 166, 15, 84, 252, 155, 71, 186, 154, 14, 179, 100, 60,
                        65, 41, 20, 70,
                    ],
                    [
                        170, 249, 236, 83, 166, 170, 136, 51, 114, 243, 12, 142, 104, 223, 180, 86,
                        136, 136, 169, 67,
                    ],
                    [
                        224, 7, 43, 174, 104, 206, 84, 71, 36, 144, 204, 171, 154, 23, 116, 123,
                        119, 52, 215, 199,
                    ],
                    [
                        210, 227, 98, 94, 34, 43, 3, 166, 91, 167, 151, 92, 50, 219, 132, 0, 249,
                        237, 161, 162,
                    ],
                    [
                        161, 41, 237, 213, 38, 48, 20, 79, 128, 41, 96, 56, 24, 168, 121, 46, 42,
                        15, 231, 250,
                    ],
                    [
                        191, 12, 52, 10, 11, 208, 15, 76, 11, 173, 103, 237, 164, 99, 80, 3, 120,
                        77, 166, 29,
                    ],
                    [
                        156, 149, 51, 32, 68, 216, 215, 180, 177, 231, 76, 33, 213, 248, 35, 5,
                        232, 176, 185, 195,
                    ],
                    [
                        212, 235, 164, 25, 79, 15, 169, 0, 49, 110, 227, 110, 61, 57, 201, 227, 52,
                        187, 226, 61,
                    ],
                    [
                        46, 36, 99, 8, 181, 211, 102, 51, 141, 5, 128, 50, 192, 80, 30, 40, 170,
                        64, 246, 106,
                    ],
                    [
                        223, 106, 246, 141, 94, 233, 137, 81, 28, 200, 92, 143, 193, 233, 217, 41,
                        109, 185, 2, 56,
                    ],
                    [
                        34, 139, 164, 162, 84, 222, 88, 87, 252, 89, 153, 65, 188, 7, 236, 74, 204,
                        70, 173, 197,
                    ],
                    [
                        77, 29, 57, 179, 165, 224, 216, 163, 55, 21, 246, 238, 33, 6, 133, 111,
                        119, 152, 168, 139,
                    ],
                    [
                        22, 182, 111, 243, 145, 84, 112, 94, 195, 179, 226, 170, 0, 173, 76, 243,
                        195, 211, 188, 183,
                    ],
                    [
                        20, 83, 152, 77, 206, 201, 239, 130, 11, 165, 224, 190, 34, 190, 202, 83,
                        100, 203, 175, 7,
                    ],
                    [
                        58, 144, 172, 61, 19, 138, 244, 138, 97, 124, 223, 100, 89, 22, 42, 56,
                        197, 246, 150, 98,
                    ],
                    [
                        223, 201, 77, 152, 111, 234, 89, 183, 137, 147, 84, 183, 78, 17, 65, 22,
                        76, 109, 246, 112,
                    ],
                    [
                        103, 37, 216, 29, 110, 91, 202, 14, 133, 16, 34, 53, 190, 132, 118, 56,
                        202, 86, 26, 158,
                    ],
                    [
                        21, 30, 58, 231, 191, 130, 190, 81, 143, 155, 64, 150, 119, 207, 42, 50,
                        52, 90, 228, 146,
                    ],
                    [
                        29, 85, 30, 58, 76, 0, 149, 26, 206, 106, 13, 53, 142, 228, 227, 140, 69,
                        222, 104, 110,
                    ],
                    [
                        57, 82, 184, 140, 174, 95, 220, 54, 250, 209, 127, 122, 186, 5, 110, 52,
                        116, 53, 66, 101,
                    ],
                    [
                        56, 194, 139, 189, 221, 227, 219, 172, 44, 102, 113, 60, 85, 169, 238, 59,
                        192, 39, 137, 31,
                    ],
                    [
                        4, 203, 32, 24, 136, 51, 40, 229, 48, 89, 122, 216, 118, 25, 3, 128, 39,
                        216, 126, 189,
                    ],
                    [
                        32, 13, 201, 100, 192, 47, 237, 145, 172, 116, 69, 65, 43, 38, 135, 64, 13,
                        101, 52, 2,
                    ],
                    [
                        31, 74, 254, 39, 67, 210, 104, 200, 166, 209, 77, 171, 242, 238, 185, 16,
                        229, 120, 79, 76,
                    ],
                    [
                        36, 244, 138, 181, 200, 163, 100, 58, 84, 196, 38, 167, 138, 89, 156, 207,
                        149, 208, 138, 125,
                    ],
                    [
                        254, 161, 113, 90, 218, 121, 181, 123, 84, 97, 46, 221, 137, 80, 40, 141,
                        139, 196, 252, 227,
                    ],
                    [
                        69, 211, 225, 103, 11, 91, 9, 225, 147, 206, 57, 168, 181, 62, 126, 239,
                        35, 196, 24, 237,
                    ],
                    [
                        22, 11, 94, 11, 184, 216, 142, 148, 73, 59, 1, 81, 154, 97, 99, 247, 6,
                        206, 155, 158,
                    ],
                    [
                        215, 131, 222, 144, 170, 89, 171, 30, 200, 252, 96, 241, 247, 153, 114,
                        215, 15, 183, 183, 116,
                    ],
                    [
                        216, 206, 250, 2, 99, 3, 0, 48, 160, 140, 137, 107, 182, 151, 56, 59, 246,
                        33, 160, 243,
                    ],
                    [
                        250, 143, 240, 4, 19, 182, 113, 93, 218, 198, 137, 183, 63, 246, 9, 177,
                        34, 194, 20, 173,
                    ],
                    [
                        52, 189, 36, 214, 30, 229, 183, 171, 37, 35, 169, 217, 136, 35, 17, 12, 23,
                        154, 194, 100,
                    ],
                    [
                        158, 207, 23, 24, 125, 200, 69, 200, 8, 0, 75, 240, 187, 42, 28, 46, 130,
                        131, 183, 23,
                    ],
                    [
                        222, 100, 243, 51, 111, 58, 223, 182, 166, 103, 183, 241, 53, 1, 32, 43,
                        28, 183, 249, 166,
                    ],
                    [
                        166, 46, 193, 155, 241, 164, 24, 76, 81, 142, 134, 36, 186, 107, 114, 218,
                        217, 113, 88, 209,
                    ],
                    [
                        104, 137, 30, 240, 177, 130, 121, 79, 116, 243, 80, 234, 137, 23, 150, 166,
                        174, 245, 154, 82,
                    ],
                    [
                        93, 47, 54, 79, 215, 152, 93, 74, 3, 97, 129, 23, 32, 148, 160, 81, 1, 229,
                        76, 97,
                    ],
                    [
                        224, 188, 230, 200, 218, 126, 63, 77, 33, 41, 203, 68, 130, 10, 9, 51, 100,
                        8, 18, 54,
                    ],
                    [
                        126, 9, 186, 77, 240, 45, 130, 115, 250, 141, 74, 7, 250, 152, 96, 30, 137,
                        233, 48, 96,
                    ],
                    [
                        235, 181, 108, 44, 203, 6, 84, 142, 97, 195, 144, 30, 153, 229, 79, 50,
                        121, 29, 136, 255,
                    ],
                    [
                        245, 230, 233, 61, 210, 123, 205, 201, 170, 30, 102, 111, 102, 71, 56, 96,
                        141, 188, 23, 226,
                    ],
                    [
                        113, 86, 90, 30, 221, 196, 228, 176, 50, 138, 51, 95, 246, 166, 22, 105,
                        184, 50, 80, 220,
                    ],
                    [
                        143, 140, 32, 59, 176, 17, 167, 209, 217, 40, 211, 47, 11, 14, 200, 114,
                        24, 205, 14, 63,
                    ],
                    [
                        157, 23, 61, 5, 122, 61, 142, 190, 41, 147, 253, 231, 53, 122, 151, 76,
                        132, 224, 232, 127,
                    ],
                    [
                        95, 32, 151, 248, 227, 126, 197, 3, 186, 84, 246, 87, 44, 196, 148, 102,
                        32, 71, 242, 3,
                    ],
                    [
                        82, 237, 92, 35, 211, 89, 226, 146, 254, 250, 238, 58, 206, 230, 99, 167,
                        118, 253, 53, 160,
                    ],
                    [
                        92, 12, 122, 27, 56, 41, 119, 58, 106, 227, 158, 251, 245, 23, 106, 127,
                        213, 16, 20, 49,
                    ],
                    [
                        64, 229, 243, 250, 203, 135, 100, 112, 249, 245, 177, 241, 13, 239, 242,
                        158, 159, 174, 62, 225,
                    ],
                    [
                        34, 115, 156, 142, 64, 145, 211, 231, 135, 212, 74, 141, 133, 0, 167, 110,
                        57, 44, 197, 198,
                    ],
                    [
                        190, 126, 172, 133, 199, 39, 238, 125, 25, 233, 93, 27, 85, 48, 223, 116,
                        255, 209, 199, 87,
                    ],
                    [
                        243, 4, 95, 79, 219, 199, 120, 251, 221, 203, 56, 125, 52, 217, 12, 195,
                        186, 87, 26, 38,
                    ],
                    [
                        143, 46, 23, 229, 38, 107, 225, 113, 245, 227, 163, 53, 169, 243, 147, 51,
                        184, 90, 2, 161,
                    ],
                    [
                        75, 8, 61, 113, 170, 133, 181, 67, 253, 78, 250, 21, 41, 205, 175, 206,
                        143, 252, 93, 219,
                    ],
                    [
                        180, 86, 40, 38, 5, 41, 209, 110, 91, 240, 131, 243, 91, 35, 249, 94, 102,
                        221, 189, 40,
                    ],
                    [
                        227, 134, 233, 254, 185, 212, 62, 145, 175, 99, 15, 99, 67, 98, 68, 117,
                        198, 141, 185, 127,
                    ],
                    [
                        204, 240, 56, 99, 132, 163, 22, 158, 168, 94, 123, 224, 219, 47, 190, 123,
                        68, 31, 133, 85,
                    ],
                    [
                        196, 79, 177, 139, 205, 137, 8, 155, 130, 136, 75, 211, 219, 157, 136, 68,
                        104, 67, 104, 64,
                    ],
                    [
                        62, 178, 15, 157, 240, 193, 107, 221, 100, 22, 248, 170, 224, 89, 155, 231,
                        10, 1, 49, 171,
                    ],
                    [
                        135, 244, 59, 49, 120, 84, 13, 165, 107, 154, 178, 217, 162, 31, 28, 13,
                        154, 31, 191, 8,
                    ],
                    [
                        1, 84, 37, 193, 112, 219, 30, 177, 12, 151, 154, 250, 219, 185, 39, 173,
                        232, 178, 217, 48,
                    ],
                    [
                        183, 99, 125, 163, 139, 254, 213, 179, 29, 169, 7, 58, 112, 34, 182, 219,
                        11, 65, 10, 194,
                    ],
                    [
                        231, 83, 156, 112, 52, 185, 214, 175, 89, 38, 203, 115, 224, 133, 114, 4,
                        39, 47, 144, 98,
                    ],
                    [
                        135, 198, 234, 171, 27, 104, 177, 56, 196, 0, 83, 127, 83, 240, 37, 186,
                        237, 168, 93, 7,
                    ],
                    [
                        49, 63, 14, 19, 84, 62, 107, 19, 0, 70, 182, 133, 146, 35, 182, 108, 1, 90,
                        134, 33,
                    ],
                    [
                        209, 28, 22, 135, 61, 73, 54, 191, 31, 65, 32, 248, 102, 33, 203, 69, 22,
                        117, 97, 144,
                    ],
                    [
                        137, 74, 67, 148, 44, 191, 111, 217, 38, 230, 117, 198, 118, 173, 142, 223,
                        35, 30, 109, 164,
                    ],
                    [
                        78, 217, 127, 115, 159, 108, 203, 202, 232, 235, 97, 206, 35, 121, 233, 14,
                        207, 35, 223, 109,
                    ],
                    [
                        236, 73, 13, 149, 153, 182, 127, 10, 72, 246, 41, 29, 46, 66, 25, 104, 194,
                        145, 232, 14,
                    ],
                    [
                        104, 218, 61, 88, 21, 81, 45, 218, 217, 202, 4, 188, 68, 233, 149, 145,
                        197, 1, 52, 167,
                    ],
                    [
                        138, 216, 188, 255, 41, 193, 249, 53, 105, 1, 234, 157, 171, 221, 177, 187,
                        31, 51, 224, 114,
                    ],
                    [
                        84, 133, 79, 72, 244, 144, 8, 42, 37, 66, 114, 39, 120, 117, 244, 248, 39,
                        196, 213, 232,
                    ],
                    [
                        57, 188, 50, 178, 94, 153, 134, 121, 174, 252, 0, 60, 122, 165, 226, 208,
                        119, 189, 94, 77,
                    ],
                    [
                        39, 112, 36, 171, 220, 48, 97, 180, 144, 149, 104, 235, 58, 39, 98, 182,
                        87, 210, 74, 175,
                    ],
                    [
                        90, 58, 123, 241, 32, 94, 24, 123, 21, 223, 149, 80, 188, 92, 218, 231, 60,
                        240, 198, 249,
                    ],
                    [
                        14, 8, 53, 221, 120, 160, 244, 165, 116, 120, 131, 1, 158, 111, 91, 237,
                        40, 91, 254, 180,
                    ],
                    [
                        13, 98, 196, 38, 252, 124, 137, 34, 231, 194, 220, 143, 155, 243, 112, 162,
                        6, 39, 44, 135,
                    ],
                    [
                        122, 103, 83, 43, 92, 142, 33, 15, 1, 212, 200, 6, 88, 164, 210, 131, 1,
                        199, 1, 216,
                    ],
                    [
                        205, 245, 116, 36, 159, 249, 159, 231, 83, 47, 154, 118, 61, 146, 53, 154,
                        209, 180, 102, 211,
                    ],
                    [
                        44, 90, 153, 46, 182, 49, 147, 153, 100, 253, 207, 225, 208, 44, 235, 100,
                        22, 254, 254, 181,
                    ],
                    [
                        227, 235, 224, 28, 86, 31, 207, 193, 179, 231, 87, 226, 145, 184, 83, 114,
                        24, 10, 137, 141,
                    ],
                    [
                        162, 92, 44, 198, 202, 56, 145, 74, 49, 82, 40, 152, 230, 246, 141, 126,
                        30, 196, 98, 240,
                    ],
                    [
                        117, 180, 253, 51, 239, 199, 40, 146, 180, 12, 29, 62, 169, 72, 222, 169,
                        89, 74, 177, 113,
                    ],
                    [
                        63, 73, 9, 97, 129, 178, 133, 187, 35, 15, 63, 101, 160, 61, 124, 131, 197,
                        203, 87, 112,
                    ],
                    [
                        139, 145, 255, 216, 116, 211, 123, 175, 57, 183, 102, 25, 94, 22, 89, 161,
                        122, 25, 88, 2,
                    ],
                    [
                        135, 14, 6, 180, 124, 195, 43, 154, 162, 221, 192, 189, 171, 9, 191, 222,
                        37, 247, 128, 123,
                    ],
                    [
                        114, 167, 211, 53, 8, 78, 77, 76, 230, 181, 254, 116, 25, 140, 31, 219, 16,
                        35, 13, 156,
                    ],
                    [
                        100, 107, 4, 150, 240, 51, 118, 135, 141, 77, 130, 164, 108, 134, 206, 249,
                        197, 128, 255, 67,
                    ],
                    [
                        218, 208, 223, 248, 157, 87, 1, 129, 109, 122, 178, 73, 196, 104, 118, 62,
                        28, 182, 136, 44,
                    ],
                    [
                        161, 92, 115, 232, 26, 199, 187, 59, 10, 244, 131, 150, 196, 240, 11, 45,
                        93, 255, 198, 132,
                    ],
                    [
                        200, 2, 234, 79, 182, 193, 123, 254, 172, 30, 52, 248, 24, 75, 248, 158,
                        71, 119, 42, 75,
                    ],
                    [
                        39, 159, 195, 147, 54, 57, 153, 17, 123, 149, 187, 106, 210, 174, 0, 58,
                        155, 100, 0, 213,
                    ],
                    [
                        196, 82, 25, 193, 202, 167, 10, 155, 195, 7, 139, 226, 112, 11, 244, 142,
                        176, 68, 14, 216,
                    ],
                    [
                        116, 174, 18, 136, 92, 247, 60, 73, 153, 65, 164, 156, 115, 169, 174, 155,
                        15, 75, 165, 72,
                    ],
                    [
                        138, 222, 15, 84, 184, 194, 225, 33, 113, 130, 84, 118, 117, 117, 114, 128,
                        79, 231, 114, 70,
                    ],
                    [
                        164, 62, 30, 84, 151, 148, 35, 16, 244, 79, 236, 239, 3, 253, 48, 190, 232,
                        49, 16, 170,
                    ],
                    [
                        33, 12, 164, 214, 34, 241, 117, 226, 193, 231, 187, 242, 171, 82, 228, 101,
                        189, 227, 250, 235,
                    ],
                    [
                        111, 119, 25, 156, 238, 221, 213, 168, 182, 20, 51, 156, 207, 240, 98, 208,
                        200, 195, 59, 255,
                    ],
                    [
                        105, 219, 223, 47, 35, 183, 166, 218, 175, 5, 92, 22, 30, 171, 90, 159,
                        138, 230, 120, 78,
                    ],
                    [
                        208, 231, 176, 133, 182, 57, 75, 103, 135, 110, 0, 32, 116, 70, 106, 98,
                        212, 135, 131, 17,
                    ],
                    [
                        91, 202, 81, 211, 203, 19, 214, 160, 208, 101, 55, 41, 221, 201, 209, 175,
                        237, 58, 206, 37,
                    ],
                    [
                        249, 107, 232, 114, 102, 153, 231, 74, 236, 94, 6, 206, 34, 205, 248, 152,
                        117, 5, 162, 199,
                    ],
                    [
                        27, 72, 145, 214, 214, 244, 9, 28, 50, 161, 116, 44, 173, 164, 17, 48, 157,
                        213, 143, 15,
                    ],
                    [
                        192, 66, 149, 154, 245, 111, 63, 4, 38, 42, 211, 129, 176, 140, 234, 44,
                        154, 30, 160, 92,
                    ],
                    [
                        180, 81, 20, 152, 124, 120, 210, 133, 224, 45, 152, 54, 205, 252, 74, 68,
                        129, 84, 216, 71,
                    ],
                    [
                        91, 89, 239, 158, 40, 118, 38, 229, 98, 45, 100, 40, 159, 227, 92, 24, 42,
                        141, 90, 136,
                    ],
                    [
                        190, 154, 30, 220, 224, 21, 189, 179, 239, 46, 177, 156, 205, 177, 247,
                        103, 120, 199, 231, 249,
                    ],
                    [
                        135, 116, 111, 122, 199, 30, 239, 167, 84, 67, 93, 25, 114, 245, 52, 140,
                        240, 238, 52, 175,
                    ],
                    [
                        37, 206, 90, 178, 246, 129, 34, 167, 27, 248, 74, 13, 147, 143, 1, 142,
                        142, 155, 151, 227,
                    ],
                    [
                        92, 202, 218, 190, 253, 224, 193, 99, 231, 255, 24, 194, 35, 21, 177, 117,
                        185, 54, 143, 131,
                    ],
                    [
                        201, 246, 130, 151, 49, 14, 190, 185, 78, 57, 87, 46, 16, 102, 70, 212,
                        195, 35, 4, 16,
                    ],
                    [
                        13, 30, 102, 222, 56, 151, 194, 212, 88, 64, 91, 44, 73, 5, 151, 99, 75,
                        75, 180, 87,
                    ],
                    [
                        231, 19, 59, 152, 109, 184, 180, 1, 0, 174, 80, 252, 73, 237, 2, 215, 234,
                        51, 102, 146,
                    ],
                    [
                        107, 235, 76, 120, 182, 104, 49, 44, 11, 36, 156, 160, 110, 174, 75, 170,
                        64, 20, 190, 160,
                    ],
                    [
                        84, 254, 237, 166, 148, 95, 6, 248, 94, 248, 168, 127, 190, 78, 207, 253,
                        30, 84, 36, 170,
                    ],
                    [
                        38, 154, 110, 73, 139, 95, 96, 223, 233, 12, 38, 64, 160, 221, 56, 251, 71,
                        171, 240, 212,
                    ],
                    [
                        168, 54, 55, 171, 230, 108, 135, 253, 38, 216, 112, 54, 111, 214, 123, 66,
                        183, 6, 134, 46,
                    ],
                    [
                        194, 27, 210, 99, 68, 152, 32, 238, 8, 124, 128, 100, 65, 194, 23, 145, 79,
                        170, 89, 53,
                    ],
                    [
                        45, 182, 7, 215, 120, 15, 68, 88, 183, 81, 84, 166, 153, 147, 247, 117, 19,
                        218, 78, 214,
                    ],
                    [
                        247, 216, 20, 211, 154, 129, 107, 63, 59, 161, 176, 131, 49, 185, 128, 183,
                        42, 48, 84, 96,
                    ],
                    [
                        160, 99, 71, 88, 165, 130, 118, 69, 207, 248, 119, 51, 114, 153, 60, 118,
                        19, 72, 54, 25,
                    ],
                    [
                        175, 181, 163, 237, 95, 193, 206, 150, 38, 242, 34, 244, 13, 241, 11, 142,
                        218, 214, 67, 30,
                    ],
                    [
                        213, 186, 98, 42, 180, 195, 170, 8, 42, 73, 114, 222, 233, 242, 203, 214,
                        120, 49, 198, 170,
                    ],
                    [
                        10, 36, 160, 86, 65, 143, 26, 169, 229, 230, 21, 69, 105, 170, 134, 211,
                        202, 24, 113, 238,
                    ],
                    [
                        146, 74, 43, 108, 44, 72, 227, 238, 20, 64, 171, 18, 36, 155, 109, 205,
                        174, 243, 47, 36,
                    ],
                    [
                        75, 34, 238, 180, 64, 137, 138, 117, 164, 230, 178, 242, 165, 124, 179, 92,
                        173, 34, 181, 140,
                    ],
                    [
                        161, 249, 87, 25, 249, 233, 141, 82, 209, 101, 48, 199, 55, 232, 150, 247,
                        145, 121, 82, 162,
                    ],
                    [
                        86, 117, 71, 112, 185, 205, 123, 253, 178, 157, 170, 161, 111, 186, 113,
                        197, 208, 184, 1, 68,
                    ],
                    [
                        215, 147, 139, 222, 54, 1, 226, 12, 120, 60, 73, 148, 226, 149, 113, 230,
                        70, 149, 214, 28,
                    ],
                    [
                        109, 239, 105, 185, 67, 201, 40, 240, 71, 73, 27, 164, 127, 163, 101, 116,
                        109, 214, 212, 53,
                    ],
                    [
                        22, 155, 134, 215, 111, 10, 149, 54, 142, 230, 96, 128, 55, 241, 107, 205,
                        242, 231, 152, 236,
                    ],
                    [
                        167, 173, 199, 3, 116, 194, 134, 20, 191, 6, 178, 50, 160, 126, 74, 151,
                        185, 164, 214, 155,
                    ],
                    [
                        69, 223, 68, 189, 210, 122, 232, 114, 88, 196, 135, 173, 21, 74, 198, 240,
                        222, 110, 238, 168,
                    ],
                    [
                        157, 221, 235, 233, 5, 102, 45, 34, 61, 144, 52, 22, 30, 142, 32, 218, 231,
                        196, 136, 191,
                    ],
                    [
                        130, 242, 224, 243, 127, 57, 206, 168, 178, 15, 94, 233, 34, 183, 17, 84,
                        66, 240, 8, 111,
                    ],
                    [
                        96, 3, 196, 68, 74, 60, 155, 244, 113, 88, 220, 51, 230, 232, 69, 107, 61,
                        154, 76, 135,
                    ],
                    [
                        29, 74, 27, 19, 12, 139, 190, 243, 162, 83, 26, 137, 227, 162, 151, 195,
                        112, 67, 43, 186,
                    ],
                    [
                        222, 20, 102, 198, 121, 68, 235, 243, 167, 231, 216, 31, 65, 223, 9, 15,
                        94, 86, 26, 239,
                    ],
                    [
                        153, 188, 128, 81, 216, 62, 153, 41, 153, 19, 46, 177, 177, 99, 118, 106,
                        185, 122, 57, 11,
                    ],
                    [
                        2, 53, 104, 86, 17, 242, 203, 151, 245, 198, 244, 231, 177, 111, 7, 178,
                        148, 138, 238, 51,
                    ],
                    [
                        247, 104, 204, 99, 94, 68, 178, 223, 255, 43, 71, 206, 134, 252, 147, 160,
                        149, 39, 215, 130,
                    ],
                    [
                        38, 249, 65, 206, 102, 131, 119, 149, 131, 52, 78, 191, 205, 26, 119, 96,
                        249, 181, 5, 146,
                    ],
                    [
                        91, 177, 51, 232, 229, 142, 138, 53, 211, 88, 49, 39, 153, 171, 19, 246,
                        168, 72, 18, 213,
                    ],
                    [
                        15, 99, 217, 41, 57, 205, 1, 73, 247, 255, 172, 135, 160, 40, 148, 232,
                        128, 141, 22, 194,
                    ],
                    [
                        78, 33, 144, 24, 155, 89, 9, 110, 58, 29, 59, 14, 156, 33, 6, 12, 138, 214,
                        11, 104,
                    ],
                    [
                        171, 98, 60, 66, 99, 250, 9, 18, 255, 156, 55, 164, 188, 115, 50, 138, 134,
                        182, 107, 185,
                    ],
                    [
                        158, 247, 217, 2, 33, 106, 115, 253, 40, 32, 144, 153, 134, 4, 209, 166,
                        177, 130, 133, 33,
                    ],
                    [
                        2, 149, 164, 129, 230, 100, 45, 83, 137, 100, 219, 158, 225, 80, 86, 250,
                        17, 176, 98, 140,
                    ],
                    [
                        72, 170, 58, 95, 197, 220, 255, 240, 170, 77, 85, 25, 71, 72, 152, 84, 30,
                        120, 243, 185,
                    ],
                    [
                        113, 14, 162, 52, 64, 131, 122, 135, 94, 214, 234, 117, 69, 62, 115, 173,
                        120, 192, 162, 146,
                    ],
                    [
                        229, 233, 219, 41, 180, 22, 153, 68, 70, 105, 235, 132, 222, 32, 60, 165,
                        21, 44, 169, 168,
                    ],
                    [
                        248, 61, 102, 44, 107, 94, 48, 213, 225, 223, 159, 201, 2, 144, 142, 11,
                        248, 175, 254, 134,
                    ],
                    [
                        112, 65, 171, 189, 91, 194, 172, 92, 149, 177, 41, 140, 118, 87, 231, 135,
                        165, 71, 89, 53,
                    ],
                    [
                        23, 28, 65, 184, 102, 31, 16, 220, 175, 55, 141, 126, 80, 3, 41, 70, 95,
                        60, 58, 187,
                    ],
                    [
                        250, 123, 148, 134, 86, 219, 11, 23, 143, 13, 0, 92, 148, 160, 35, 36, 54,
                        5, 165, 246,
                    ],
                    [
                        217, 141, 132, 177, 197, 188, 108, 164, 126, 124, 85, 225, 240, 196, 42,
                        180, 137, 69, 158, 215,
                    ],
                    [
                        103, 253, 172, 194, 114, 98, 77, 100, 94, 125, 212, 98, 109, 196, 122, 98,
                        189, 182, 235, 121,
                    ],
                    [
                        182, 94, 49, 179, 97, 254, 75, 58, 227, 132, 105, 25, 71, 84, 4, 75, 74,
                        178, 247, 136,
                    ],
                    [
                        3, 185, 185, 140, 172, 209, 254, 165, 204, 19, 74, 90, 244, 130, 110, 105,
                        224, 77, 48, 248,
                    ],
                    [
                        108, 113, 126, 188, 89, 16, 83, 172, 35, 207, 81, 153, 126, 110, 101, 80,
                        160, 71, 167, 221,
                    ],
                    [
                        194, 12, 1, 30, 205, 192, 144, 11, 120, 33, 248, 200, 49, 172, 142, 218,
                        114, 252, 72, 79,
                    ],
                    [
                        155, 225, 76, 18, 37, 93, 194, 74, 124, 215, 108, 124, 177, 121, 55, 148,
                        177, 49, 141, 115,
                    ],
                    [
                        229, 64, 223, 219, 26, 221, 226, 186, 167, 145, 124, 15, 220, 111, 48, 165,
                        34, 82, 76, 181,
                    ],
                    [
                        215, 215, 82, 97, 207, 66, 37, 138, 44, 249, 214, 71, 217, 205, 27, 100,
                        128, 119, 212, 162,
                    ],
                    [
                        136, 166, 91, 9, 243, 250, 173, 135, 141, 82, 115, 26, 45, 69, 187, 164,
                        235, 216, 118, 241,
                    ],
                    [
                        73, 43, 93, 120, 132, 238, 40, 108, 142, 212, 14, 66, 197, 87, 34, 236, 21,
                        90, 7, 215,
                    ],
                    [
                        68, 152, 203, 11, 151, 167, 91, 136, 65, 80, 195, 58, 92, 13, 35, 124, 181,
                        54, 126, 121,
                    ],
                    [
                        145, 97, 184, 23, 163, 158, 69, 240, 158, 185, 39, 231, 53, 214, 144, 11,
                        77, 122, 108, 215,
                    ],
                    [
                        219, 220, 154, 59, 248, 225, 13, 177, 129, 127, 164, 117, 154, 50, 156,
                        165, 235, 118, 88, 165,
                    ],
                    [
                        54, 61, 24, 127, 72, 69, 216, 127, 110, 44, 57, 60, 5, 77, 149, 225, 248,
                        38, 103, 180,
                    ],
                    [
                        58, 221, 239, 228, 114, 227, 45, 8, 151, 43, 65, 125, 110, 50, 235, 113,
                        10, 83, 54, 152,
                    ],
                    [
                        183, 248, 49, 102, 94, 176, 152, 75, 78, 148, 165, 112, 13, 84, 159, 57,
                        139, 156, 250, 88,
                    ],
                    [
                        215, 167, 105, 4, 157, 165, 86, 33, 74, 14, 209, 88, 10, 192, 49, 133, 196,
                        158, 48, 26,
                    ],
                    [
                        44, 0, 137, 83, 175, 5, 83, 81, 107, 53, 136, 22, 140, 67, 29, 59, 7, 231,
                        146, 93,
                    ],
                    [
                        11, 87, 169, 177, 215, 78, 49, 175, 53, 51, 195, 54, 43, 32, 173, 47, 195,
                        89, 154, 110,
                    ],
                    [
                        20, 103, 11, 230, 39, 48, 91, 91, 46, 139, 242, 107, 88, 141, 45, 137, 85,
                        24, 76, 48,
                    ],
                    [
                        82, 53, 178, 193, 62, 11, 57, 204, 123, 35, 26, 26, 61, 205, 169, 182, 73,
                        94, 69, 163,
                    ],
                    [
                        193, 49, 97, 15, 77, 219, 12, 76, 124, 12, 123, 241, 206, 69, 130, 195, 36,
                        207, 84, 170,
                    ],
                    [
                        82, 59, 138, 43, 99, 20, 198, 139, 82, 212, 172, 23, 252, 188, 10, 140,
                        115, 217, 20, 156,
                    ],
                    [
                        159, 30, 226, 140, 197, 170, 98, 59, 201, 52, 229, 0, 214, 122, 157, 32,
                        149, 73, 192, 109,
                    ],
                    [
                        89, 40, 25, 194, 198, 169, 68, 71, 147, 74, 168, 115, 173, 70, 111, 18,
                        204, 244, 16, 67,
                    ],
                    [
                        121, 188, 33, 101, 195, 119, 170, 188, 161, 106, 96, 169, 189, 209, 242,
                        46, 111, 72, 146, 239,
                    ],
                    [
                        96, 128, 175, 23, 130, 163, 100, 45, 182, 118, 243, 4, 27, 58, 132, 22, 46,
                        227, 183, 87,
                    ],
                    [
                        242, 206, 192, 203, 134, 147, 102, 83, 192, 149, 60, 114, 201, 150, 113,
                        192, 201, 202, 106, 116,
                    ],
                    [
                        88, 119, 24, 34, 150, 95, 194, 50, 3, 132, 99, 101, 46, 71, 101, 58, 214,
                        186, 102, 23,
                    ],
                    [
                        189, 75, 69, 85, 189, 43, 111, 179, 92, 127, 199, 212, 47, 247, 64, 77,
                        242, 4, 125, 74,
                    ],
                    [
                        17, 30, 90, 124, 152, 17, 19, 214, 51, 254, 141, 116, 30, 124, 14, 38, 120,
                        238, 214, 187,
                    ],
                    [
                        244, 218, 34, 43, 151, 136, 164, 60, 201, 249, 140, 134, 28, 60, 195, 169,
                        49, 25, 69, 216,
                    ],
                    [
                        28, 162, 108, 44, 246, 199, 71, 78, 120, 86, 6, 70, 83, 143, 39, 63, 152,
                        134, 18, 221,
                    ],
                    [
                        174, 169, 151, 179, 99, 144, 238, 37, 219, 112, 217, 22, 242, 168, 36, 22,
                        255, 14, 168, 5,
                    ],
                    [
                        84, 152, 110, 151, 202, 172, 19, 91, 252, 142, 131, 138, 126, 201, 3, 203,
                        187, 156, 239, 243,
                    ],
                    [
                        87, 216, 247, 187, 147, 58, 188, 68, 103, 178, 110, 169, 36, 158, 193, 91,
                        152, 62, 219, 29,
                    ],
                    [
                        244, 92, 168, 254, 114, 209, 104, 226, 54, 234, 251, 121, 236, 84, 42, 112,
                        56, 227, 78, 62,
                    ],
                    [
                        138, 73, 171, 45, 146, 174, 167, 247, 122, 161, 119, 138, 77, 225, 147,
                        139, 235, 158, 154, 80,
                    ],
                    [
                        66, 198, 26, 15, 150, 188, 46, 76, 239, 223, 151, 239, 207, 16, 70, 51, 79,
                        129, 221, 196,
                    ],
                    [
                        15, 24, 232, 139, 154, 98, 218, 111, 114, 80, 78, 82, 58, 79, 145, 69, 200,
                        15, 151, 158,
                    ],
                    [
                        201, 236, 145, 53, 166, 118, 44, 133, 244, 208, 160, 186, 114, 16, 83, 40,
                        37, 38, 193, 96,
                    ],
                    [
                        75, 252, 61, 132, 183, 109, 180, 172, 126, 144, 240, 146, 198, 242, 71, 31,
                        31, 34, 178, 185,
                    ],
                    [
                        25, 27, 79, 105, 99, 12, 221, 197, 184, 51, 82, 200, 112, 57, 247, 78, 6,
                        2, 166, 90,
                    ],
                    [
                        139, 107, 211, 25, 255, 185, 48, 172, 170, 147, 63, 84, 170, 0, 39, 2, 89,
                        243, 35, 196,
                    ],
                    [
                        225, 243, 162, 235, 203, 119, 131, 194, 16, 36, 181, 49, 34, 205, 138, 38,
                        90, 118, 8, 222,
                    ],
                    [
                        181, 78, 171, 226, 12, 198, 63, 229, 107, 100, 218, 69, 176, 94, 144, 18,
                        160, 192, 177, 51,
                    ],
                    [
                        110, 169, 165, 186, 126, 82, 163, 215, 234, 43, 234, 16, 26, 248, 13, 47,
                        255, 50, 192, 190,
                    ],
                    [
                        93, 101, 106, 101, 32, 197, 190, 254, 165, 198, 140, 115, 17, 6, 42, 113,
                        194, 254, 182, 183,
                    ],
                    [
                        136, 60, 79, 237, 253, 251, 139, 253, 95, 16, 92, 179, 254, 90, 248, 125,
                        115, 34, 6, 249,
                    ],
                    [
                        184, 228, 78, 107, 232, 204, 98, 249, 234, 90, 2, 236, 143, 17, 192, 226,
                        142, 249, 139, 81,
                    ],
                    [
                        11, 247, 86, 133, 81, 133, 91, 209, 60, 114, 29, 214, 131, 196, 105, 134,
                        232, 73, 242, 0,
                    ],
                    [
                        220, 21, 224, 221, 119, 231, 75, 203, 123, 163, 97, 95, 19, 230, 235, 242,
                        249, 243, 106, 244,
                    ],
                    [
                        135, 163, 98, 51, 127, 30, 195, 102, 9, 208, 238, 3, 32, 38, 170, 98, 125,
                        156, 87, 207,
                    ],
                    [
                        81, 173, 157, 193, 190, 169, 69, 64, 134, 135, 98, 116, 82, 74, 213, 240,
                        128, 135, 30, 162,
                    ],
                    [
                        41, 96, 163, 78, 226, 27, 34, 213, 50, 126, 78, 164, 231, 164, 224, 230,
                        218, 130, 110, 248,
                    ],
                    [
                        243, 247, 24, 18, 98, 106, 10, 255, 208, 245, 134, 143, 140, 116, 226, 233,
                        192, 245, 70, 145,
                    ],
                    [
                        138, 138, 17, 171, 182, 192, 21, 207, 142, 61, 69, 238, 59, 195, 245, 202,
                        162, 36, 162, 68,
                    ],
                    [
                        198, 235, 178, 36, 25, 40, 185, 145, 146, 208, 140, 238, 163, 153, 79, 175,
                        99, 194, 155, 217,
                    ],
                    [
                        185, 19, 15, 150, 65, 24, 219, 84, 225, 176, 32, 93, 14, 59, 101, 149, 45,
                        79, 237, 33,
                    ],
                    [
                        94, 155, 246, 82, 196, 77, 169, 83, 77, 154, 111, 36, 5, 181, 30, 118, 47,
                        68, 168, 218,
                    ],
                    [
                        89, 199, 7, 2, 166, 57, 77, 14, 7, 30, 47, 65, 200, 108, 105, 146, 140,
                        163, 174, 159,
                    ],
                    [
                        80, 213, 84, 181, 7, 123, 64, 4, 231, 98, 159, 85, 233, 88, 176, 241, 21,
                        250, 172, 132,
                    ],
                    [
                        119, 103, 14, 248, 215, 29, 239, 150, 188, 160, 224, 205, 186, 129, 226,
                        42, 198, 225, 12, 31,
                    ],
                    [
                        79, 229, 152, 0, 150, 217, 231, 235, 0, 166, 129, 97, 197, 49, 6, 29, 189,
                        238, 210, 189,
                    ],
                    [
                        212, 251, 160, 54, 182, 44, 94, 23, 88, 76, 230, 103, 141, 156, 26, 102,
                        154, 80, 161, 59,
                    ],
                    [
                        16, 239, 187, 115, 199, 164, 46, 115, 193, 8, 201, 1, 201, 65, 192, 236,
                        226, 231, 229, 254,
                    ],
                    [
                        134, 241, 68, 144, 254, 126, 126, 177, 58, 17, 139, 240, 212, 13, 160, 139,
                        189, 133, 8, 32,
                    ],
                    [
                        208, 250, 35, 209, 148, 30, 142, 79, 75, 95, 57, 112, 233, 8, 253, 20, 169,
                        238, 69, 9,
                    ],
                    [
                        103, 41, 0, 193, 226, 174, 5, 10, 252, 67, 86, 21, 112, 81, 42, 156, 20,
                        223, 26, 191,
                    ],
                    [
                        115, 205, 103, 255, 118, 252, 127, 185, 142, 47, 197, 185, 226, 60, 153,
                        116, 33, 62, 214, 239,
                    ],
                    [
                        3, 37, 18, 54, 154, 115, 100, 37, 43, 244, 141, 70, 125, 5, 166, 91, 240,
                        182, 132, 246,
                    ],
                    [
                        183, 91, 125, 230, 195, 151, 140, 54, 120, 108, 96, 240, 174, 158, 245, 9,
                        149, 94, 67, 168,
                    ],
                    [
                        145, 83, 164, 28, 115, 203, 237, 212, 83, 130, 36, 243, 60, 53, 62, 188,
                        211, 168, 189, 1,
                    ],
                    [
                        18, 193, 191, 111, 78, 182, 78, 64, 216, 195, 150, 12, 4, 61, 250, 208,
                        172, 36, 16, 98,
                    ],
                    [
                        4, 43, 170, 21, 172, 49, 32, 152, 85, 208, 121, 138, 162, 219, 56, 122, 14,
                        170, 164, 67,
                    ],
                    [
                        34, 7, 41, 160, 235, 95, 194, 139, 50, 145, 253, 13, 101, 105, 39, 57, 13,
                        107, 187, 179,
                    ],
                    [
                        89, 197, 169, 245, 211, 184, 49, 67, 4, 165, 160, 222, 142, 13, 226, 102,
                        152, 1, 40, 211,
                    ],
                    [
                        211, 91, 146, 249, 13, 252, 231, 188, 251, 199, 148, 199, 193, 119, 246,
                        167, 45, 136, 31, 100,
                    ],
                    [
                        122, 130, 172, 244, 77, 142, 139, 113, 162, 99, 45, 91, 51, 156, 114, 97,
                        198, 17, 22, 71,
                    ],
                    [
                        11, 45, 67, 67, 187, 223, 194, 158, 224, 158, 26, 143, 35, 3, 130, 212, 54,
                        52, 114, 5,
                    ],
                    [
                        127, 184, 250, 197, 164, 170, 6, 141, 4, 204, 192, 230, 194, 2, 134, 101,
                        87, 239, 130, 170,
                    ],
                    [
                        255, 76, 209, 170, 92, 233, 107, 214, 160, 49, 205, 70, 138, 237, 62, 109,
                        142, 216, 58, 251,
                    ],
                    [
                        51, 91, 156, 168, 17, 190, 202, 139, 75, 85, 215, 11, 202, 122, 209, 73,
                        37, 22, 38, 247,
                    ],
                    [
                        179, 49, 95, 240, 118, 84, 211, 104, 155, 12, 82, 158, 186, 179, 215, 179,
                        32, 136, 18, 204,
                    ],
                    [
                        151, 77, 132, 211, 69, 81, 202, 251, 150, 62, 9, 32, 167, 69, 84, 228, 97,
                        65, 254, 215,
                    ],
                    [
                        32, 11, 72, 53, 93, 133, 45, 229, 239, 121, 139, 184, 178, 69, 168, 144,
                        186, 172, 88, 144,
                    ],
                    [
                        15, 189, 184, 200, 253, 227, 86, 103, 210, 207, 91, 214, 33, 180, 24, 233,
                        191, 237, 98, 148,
                    ],
                ],
            ),
        }
    }

    fn from_wots256_signature<F: PrimeField>(signature: wots256::Signature) -> F {
        let nibbles = &signature.map(|(_sig, digit)| digit)[0..wots256::M_DIGITS as usize];
        let bytes = nibbles
            .chunks(2)
            .rev()
            .map(|bn| (bn[0] << 4) + bn[1])
            .collect::<Vec<u8>>();
        F::from_le_bytes_mod_order(&bytes)
    }

    #[expect(dead_code)]
    fn from_wots160_signature<F: PrimeField>(signature: wots160::Signature) -> F {
        let nibbles = &signature.map(|(_sig, digit)| digit)[0..wots160::M_DIGITS as usize];
        let bytes = nibbles
            .chunks(2)
            .rev()
            .map(|bn| (bn[0] << 4) + bn[1])
            .collect::<Vec<u8>>();
        F::from_le_bytes_mod_order(&bytes)
    }

    #[test]
    fn test_fq_from_wots_signature() {
        let secret = "0011";

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let fq = Fq::rand(&mut rng);
        let signature = wots256::get_signature(secret, &fq.into_bigint().to_bytes_le());
        let fq_s = from_wots256_signature::<Fq>(signature);
        assert_eq!(fq, fq_s);

        let fr = Fr::rand(&mut rng);
        let signature = wots256::get_signature(secret, &fr.into_bigint().to_bytes_le());
        let fr_s = from_wots256_signature::<Fr>(signature);
        assert_eq!(fr, fr_s);
    }

    #[test]
    fn test_hash_public_inputs() {
        let msk = "helloworld";

        let public_inputs: ([u8; 32], [u8; 32], u32) = (
            std::array::from_fn(|i| i as u8),
            std::array::from_fn(|i| 2 * i as u8),
            0x12345678,
        );

        let public_inputs_hash: [u8; 32] = [
            10, 147, 218, 229, 179, 32, 184, 74, 205, 238, 18, 254, 120, 22, 115, 172, 108, 142,
            198, 161, 226, 103, 173, 53, 157, 114, 60, 179, 155, 37, 36, 29,
        ];

        let _data = &[
            32, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
            18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46,
            48, 50, 52, 54, 56, 58, 60, 62, 120, 86, 52, 18,
        ];

        fn hash_2fq_bn254() -> Script {
            script! {
                for i in 1..=3 {
                    { 1 << (8 - i) }
                    OP_2DUP
                    OP_GREATERTHAN
                    OP_IF
                        OP_SUB
                    OP_ELSE
                        OP_DROP
                    OP_ENDIF
                }
            }
        }

        let public_inputs_hash_public_key =
            wots256::generate_public_key(&secret_key_for_public_inputs_hash(msk));

        let public_keys = (
            wots256::generate_public_key(&secret_key_for_superblock_hash(msk)),
            wots256::generate_public_key(&secret_key_for_bridge_out_txid(msk)),
            wots32::generate_public_key(&secret_key_for_superblock_period_start_ts(msk)),
        );

        let witness_script = script! {
            { wots256::sign(&secret_key_for_public_inputs_hash(msk), &public_inputs_hash) }
            { wots32::sign(&secret_key_for_superblock_period_start_ts(msk), &public_inputs.2.to_le_bytes()) }
            { wots256::sign(&secret_key_for_bridge_out_txid(msk), &public_inputs.1) }
            { wots256::sign(&secret_key_for_superblock_hash(msk), &public_inputs.0) }
        };

        fn raw_hash_padding() -> Script {
            script! {
                for b in [0; 7] { {b} } 32
            }
        }

        let locking_script = script! {
            { wots256::checksig_verify(public_keys.0) }
            for _ in 0..32 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }

            { wots256::checksig_verify(public_keys.1) }
            for _ in 0..32 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }

            { wots32::checksig_verify(public_keys.2) }
            for _ in 0..4 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }

            { wots256::checksig_verify(public_inputs_hash_public_key) }
            for _ in 0..32 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }

            for _ in 0..32 { OP_FROMALTSTACK }
            for _ in 0..4 { OP_FROMALTSTACK }
            for _ in 0..32 { OP_FROMALTSTACK } raw_hash_padding
            for _ in 0..32 { OP_FROMALTSTACK } raw_hash_padding

            { sha256(84) }
            { hash_2fq_bn254() }

            // verify that hashes don't match
            for i in (1..32).rev() {
                {i + 1} OP_ROLL OP_EQUAL OP_TOALTSTACK
            }
            OP_EQUAL
            for _ in 1..32 { OP_FROMALTSTACK OP_BOOLAND }
            OP_NOT
        };

        let script = script! {
            { witness_script }
            { locking_script }
        };

        let res = execute_script(script);

        for i in 0..res.final_stack.len() {
            println!("{i:3}: {:?}", res.final_stack.get(i));
        }
    }

    #[test]
    fn test_generate_disprove_scripts_duration() {
        let start = Instant::now();
        let partial_disprove_scripts = &read_partial_disprove_scripts();
        println!(
            "read_partial_disprove_scripts: {:?}",
            Instant::now() - start
        );

        let public_keys = generate_wots_public_keys("msk", mock_txid());

        let start = Instant::now();
        g16::generate_disprove_scripts(public_keys.groth16, partial_disprove_scripts);
        println!("generate_disprove_scripts: {:?}", Instant::now() - start);
    }

    fn mock_txid() -> Txid {
        Txid::from_slice(&[0u8; 32]).unwrap()
    }
}
