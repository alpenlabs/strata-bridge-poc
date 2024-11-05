use bitcoin::Txid;
use bitvm::{
    groth16::g16,
    signatures::wots::{wots160, wots256, wots32},
    treepp::*,
};

use super::{
    commitments::{
        secret_key_for_bridge_out_txid, secret_key_for_proof_element,
        secret_key_for_superblock_hash, secret_key_for_superblock_period_start_ts,
    },
    prelude::secret_key_for_public_inputs_hash,
};

#[derive(Debug, Clone, Copy)]
pub struct PublicKeys {
    pub bridge_out_txid: wots256::PublicKey,
    pub superblock_hash: wots256::PublicKey,
    pub superblock_period_start_ts: wots32::PublicKey,
    pub groth16: g16::WotsPublicKeys,
}

#[derive(Debug, Clone, Copy)]
pub struct Signatures {
    pub bridge_out_txid: wots256::Signature,
    pub superblock_hash: wots256::Signature,
    pub superblock_period_start_ts: wots32::Signature,
    pub groth16: g16::WotsSignatures,
}

#[derive(Debug, Clone, Copy)]
pub struct Assertions {
    pub bridge_out_txid: [u8; 32],
    pub superblock_hash: [u8; 32],
    pub superblock_period_start_ts: [u8; 4],
    pub groth16: g16::ProofAssertions,
}

pub fn bridge_poc_verification_key() -> g16::VerifyingKey {
    // TODO: replace this with actual verification key
    mock::get_verifying_key()
}

pub fn generate_verifier_partial_scripts() -> [Script; g16::N_TAPLEAVES] {
    g16::Verifier::compile(bridge_poc_verification_key())
}

pub fn generate_verifier_tapscripts_from_partial_scripts(
    verifier_scripts: &[Script; g16::N_TAPLEAVES],
    public_keys: g16::WotsPublicKeys,
) -> [Script; g16::N_TAPLEAVES] {
    g16::Verifier::generate_tapscripts(public_keys, verifier_scripts)
}

pub fn generate_assertions_for_proof(
    vk: g16::VerifyingKey,
    proof: g16::Proof,
    public_inputs: g16::PublicInputs,
) -> g16::ProofAssertions {
    g16::Verifier::generate_assertions(vk, proof, public_inputs)
}

pub fn validate_assertion_signatures(
    signatures: g16::WotsSignatures,
    public_keys: g16::WotsPublicKeys,
) -> Option<(usize, Script)> {
    g16::Verifier::validate_assertion_signatures(
        bridge_poc_verification_key(),
        signatures,
        public_keys,
    )
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

mod mock {
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
        let public_inputs = [
            // Fr::from_be_bytes_mod_order(&VKEY_HASH),
            Fr::from_be_bytes_mod_order(&sp1g16::hash_bn254_be_bytes(&PUBLIC_INPUT_BYTES)),
        ];

        (proof, public_inputs)
    }
}

mod _mock {
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
    use std::fs;

    use ark_bn254::{Fq, Fr};
    use ark_ff::{BigInteger, PrimeField, UniformRand};
    use ark_std::test_rng;
    use bitcoin::{
        opcodes::all::{
            OP_BOOLAND, OP_ENDIF, OP_EQUAL, OP_FROMALTSTACK, OP_GREATERTHAN, OP_SWAP, OP_TOALTSTACK,
        },
        ScriptBuf,
    };
    use bitvm::{
        groth16::g16,
        hash::sha256::sha256,
        pseudo::NMUL,
        signatures::wots::{wots160, wots256},
        treepp::*,
    };
    use rand::{RngCore, SeedableRng};
    use strata_bridge_tx_graph::mock_txid;

    use super::*;

    const WOTS_MSK: &str = "helloworld";

    #[test]
    fn test_groth16_compile() {
        let BRIDGE_POC_VK = bridge_poc_verification_key();
        let scripts = g16::Verifier::compile(BRIDGE_POC_VK);
        save_verifier_scripts(&scripts);
        println!("script.lens: {:?}", scripts.map(|script| script.len()));
    }

    fn save_verifier_scripts(scripts: &[Script; g16::N_TAPLEAVES]) {
        print!("Saving verifier scripts...");

        for (index, script) in scripts.iter().enumerate() {
            let path = format!("data/verifier-scripts/{index}");
            fs::write(path, script.clone().compile().to_bytes()).unwrap();
            print!("{}, ", index);
        }
        println!();
    }

    fn read_verifier_scripts() -> [Script; g16::N_TAPLEAVES] {
        print!("Reading verifier scripts...");

        let scripts = std::array::from_fn(|index| {
            let path = format!("data/verifier-scripts/{index}");
            let script_buf = ScriptBuf::from_bytes(fs::read(path).unwrap());
            print!("{}, ", index);
            script!().push_script(script_buf)
        });
        println!();
        scripts
    }

    #[test]
    fn test_full_verification() {
        let BRIDGE_POC_VK = bridge_poc_verification_key();

        println!("Generating assertions");
        // let assertions = {
        //     let (proof, public_inputs) = mock::get_proof_and_public_inputs();
        //     let groth16_assertions =
        //         g16::Verifier::generate_assertions(BRIDGE_POC_VK, proof, public_inputs);
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
        let assertions = {
            let mut assertions = get_mock_assertions();
            assertions.groth16.1[0] = [1u8; 32]; // make incorrect assertions
            assertions
        };

        let deposit_txid = mock_txid();

        println!("Generating wots public keys");
        let wots_public_keys = generate_wots_public_keys(WOTS_MSK, deposit_txid);

        println!("Generating wots signatures");
        let wots_signatures = generate_wots_signatures(WOTS_MSK, deposit_txid, assertions);

        println!("Validating assertion signatures");
        let res = g16::Verifier::validate_assertion_signatures(
            BRIDGE_POC_VK,
            wots_signatures.groth16,
            wots_public_keys.groth16,
        );

        match res {
            Some((tapleaf_index, witness_script)) => {
                println!("Assertion is invalid");

                let tapleaf_script = g16::Verifier::generate_tapscripts(
                    wots_public_keys.groth16,
                    &read_verifier_scripts(),
                )[tapleaf_index]
                    .clone();

                println!(
                    "{tapleaf_index}: {}, {}",
                    witness_script.len(),
                    tapleaf_script.len()
                );

                let script = script! {
                    { witness_script }
                    { tapleaf_script }
                };
                let res = execute_script(script);
                assert!(
                    res.success,
                    "Invalid assertion: Disprove script should not fail"
                );
            }
            None => println!("Assertion is valid"),
        }
    }

    fn get_mock_assertions() -> Assertions {
        Assertions {
            bridge_out_txid: [0u8; 32],
            superblock_hash: [0u8; 32],
            superblock_period_start_ts: [0u8; 4],
            groth16: (
                [[
                    97, 159, 38, 36, 141, 12, 72, 170, 77, 46, 140, 172, 244, 22, 160, 117, 81,
                    158, 13, 253, 161, 120, 105, 22, 145, 145, 31, 63, 151, 242, 229, 215,
                ]],
                [
                    [
                        177, 255, 221, 91, 223, 83, 170, 135, 200, 107, 158, 58, 0, 239, 79, 131,
                        195, 202, 154, 16, 148, 102, 64, 44, 199, 43, 244, 109, 48, 72, 132, 30,
                    ],
                    [
                        48, 49, 91, 186, 166, 66, 239, 181, 11, 187, 113, 185, 47, 19, 212, 33,
                        209, 211, 88, 199, 218, 153, 226, 61, 101, 80, 105, 121, 205, 167, 210, 89,
                    ],
                    [
                        145, 239, 63, 84, 116, 145, 8, 96, 241, 222, 75, 247, 53, 150, 192, 157,
                        100, 172, 0, 139, 177, 179, 229, 11, 250, 8, 55, 196, 217, 173, 206, 204,
                    ],
                    [
                        145, 173, 221, 172, 133, 20, 46, 139, 135, 95, 57, 184, 11, 123, 170, 30,
                        210, 56, 1, 134, 190, 183, 108, 143, 120, 94, 69, 140, 6, 252, 187, 37,
                    ],
                    [
                        192, 113, 108, 212, 111, 147, 244, 186, 174, 96, 172, 9, 91, 71, 94, 90,
                        76, 109, 139, 164, 21, 251, 9, 195, 254, 16, 52, 163, 112, 99, 51, 188,
                    ],
                    [
                        225, 43, 123, 233, 238, 178, 202, 104, 222, 234, 5, 246, 205, 212, 28, 65,
                        36, 5, 184, 157, 162, 171, 227, 204, 65, 96, 166, 62, 150, 9, 138, 33,
                    ],
                    [
                        17, 178, 7, 66, 181, 78, 189, 187, 240, 175, 99, 228, 94, 132, 112, 187,
                        233, 92, 170, 161, 184, 29, 101, 179, 10, 154, 17, 77, 22, 86, 242, 118,
                    ],
                    [
                        32, 31, 171, 128, 133, 67, 225, 74, 245, 8, 45, 65, 155, 138, 12, 240, 31,
                        251, 56, 117, 70, 131, 43, 113, 233, 98, 3, 219, 227, 206, 237, 6,
                    ],
                    [
                        225, 165, 59, 210, 91, 202, 220, 179, 195, 107, 64, 133, 234, 151, 86, 181,
                        168, 61, 186, 218, 35, 25, 10, 204, 141, 130, 10, 47, 73, 3, 249, 203,
                    ],
                    [
                        113, 37, 165, 0, 102, 50, 0, 104, 36, 143, 127, 21, 112, 95, 252, 217, 169,
                        68, 160, 87, 100, 85, 122, 31, 231, 19, 217, 41, 252, 226, 15, 225,
                    ],
                    [
                        226, 148, 255, 214, 236, 171, 94, 29, 55, 45, 67, 212, 68, 208, 26, 72,
                        170, 112, 236, 134, 64, 75, 237, 66, 243, 232, 117, 142, 68, 241, 247, 22,
                    ],
                    [
                        98, 3, 154, 177, 163, 0, 189, 196, 124, 232, 25, 53, 8, 132, 180, 163, 94,
                        195, 5, 134, 29, 169, 130, 193, 120, 39, 107, 2, 76, 78, 200, 181,
                    ],
                    [
                        130, 148, 254, 60, 212, 71, 202, 51, 85, 197, 204, 255, 175, 68, 121, 120,
                        161, 135, 47, 61, 182, 197, 230, 244, 130, 200, 212, 14, 193, 181, 26, 184,
                    ],
                    [
                        112, 180, 148, 48, 142, 187, 232, 211, 237, 26, 32, 92, 151, 1, 141, 160,
                        195, 25, 42, 76, 154, 51, 52, 117, 30, 129, 3, 28, 2, 74, 12, 184,
                    ],
                    [
                        192, 172, 229, 215, 50, 66, 74, 139, 242, 243, 120, 220, 248, 181, 216,
                        184, 56, 238, 162, 37, 75, 114, 251, 23, 152, 232, 42, 107, 77, 100, 229,
                        58,
                    ],
                    [
                        98, 74, 33, 186, 150, 58, 169, 41, 190, 207, 32, 33, 206, 169, 250, 155,
                        39, 109, 51, 12, 183, 71, 152, 10, 123, 230, 239, 189, 94, 214, 11, 167,
                    ],
                    [
                        144, 145, 70, 144, 184, 140, 75, 127, 48, 87, 24, 170, 131, 104, 160, 183,
                        216, 226, 139, 109, 105, 181, 217, 183, 239, 182, 217, 72, 140, 10, 233,
                        79,
                    ],
                    [
                        50, 47, 119, 82, 170, 104, 175, 255, 219, 79, 223, 253, 241, 28, 49, 24,
                        18, 226, 176, 172, 240, 203, 227, 134, 99, 224, 150, 187, 245, 111, 152,
                        121,
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
                        49, 6, 24, 149, 224, 204, 112, 230, 84, 93, 40, 250, 211, 110, 2, 210, 10,
                        57, 176, 188, 55, 159, 205, 138, 146, 16, 99, 48, 136, 199, 94, 29,
                    ],
                    [
                        224, 24, 114, 152, 181, 82, 4, 167, 221, 138, 243, 222, 211, 114, 45, 192,
                        247, 124, 108, 234, 122, 143, 178, 143, 82, 175, 96, 240, 90, 198, 184,
                        253,
                    ],
                    [
                        240, 139, 132, 141, 137, 1, 61, 108, 71, 46, 58, 5, 163, 240, 55, 108, 26,
                        146, 237, 92, 168, 2, 92, 32, 11, 47, 18, 223, 101, 115, 42, 82,
                    ],
                    [
                        16, 41, 241, 211, 105, 211, 58, 203, 208, 140, 118, 43, 158, 47, 107, 155,
                        170, 78, 148, 171, 7, 78, 226, 77, 153, 136, 255, 234, 93, 173, 194, 123,
                    ],
                    [
                        49, 153, 249, 102, 20, 95, 112, 10, 127, 196, 49, 139, 40, 116, 162, 68,
                        73, 213, 1, 166, 124, 96, 90, 156, 78, 22, 43, 67, 84, 142, 215, 195,
                    ],
                    [
                        208, 7, 31, 113, 99, 22, 113, 87, 110, 246, 53, 179, 52, 201, 146, 170,
                        127, 221, 190, 139, 250, 132, 51, 193, 175, 51, 178, 49, 34, 232, 1, 26,
                    ],
                    [
                        49, 97, 183, 103, 183, 20, 40, 207, 101, 204, 153, 245, 146, 211, 25, 18,
                        107, 43, 115, 153, 87, 182, 51, 209, 106, 95, 102, 26, 5, 143, 82, 178,
                    ],
                    [
                        3, 6, 81, 229, 182, 128, 0, 206, 118, 218, 52, 210, 159, 209, 180, 162, 29,
                        130, 239, 148, 14, 227, 176, 96, 47, 225, 132, 154, 48, 70, 137, 6,
                    ],
                    [
                        66, 21, 240, 148, 103, 227, 23, 252, 153, 208, 49, 181, 227, 164, 100, 251,
                        50, 175, 247, 94, 42, 135, 226, 36, 24, 204, 74, 43, 178, 93, 62, 92,
                    ],
                    [
                        33, 177, 166, 13, 176, 107, 89, 124, 237, 254, 134, 1, 230, 187, 49, 119,
                        132, 123, 220, 6, 242, 201, 150, 106, 91, 13, 165, 133, 181, 232, 19, 207,
                    ],
                ],
                [
                    [
                        98, 218, 182, 60, 99, 69, 18, 105, 144, 5, 3, 84, 196, 182, 194, 176, 245,
                        221, 248, 125,
                    ],
                    [
                        117, 186, 82, 229, 28, 47, 8, 12, 190, 216, 174, 127, 200, 79, 96, 159,
                        202, 9, 231, 249,
                    ],
                    [
                        59, 46, 35, 27, 83, 207, 27, 93, 119, 63, 175, 136, 120, 49, 140, 221, 161,
                        233, 79, 44,
                    ],
                    [
                        146, 156, 19, 78, 248, 200, 13, 163, 89, 253, 38, 151, 159, 203, 174, 207,
                        104, 13, 250, 212,
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
                        84, 175, 244, 144, 57, 42, 172, 0, 105, 105, 161, 220, 61, 28, 203, 47,
                        211, 52, 239, 201,
                    ],
                    [
                        210, 74, 186, 249, 35, 82, 152, 11, 183, 91, 74, 2, 188, 96, 104, 255, 172,
                        170, 32, 122,
                    ],
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    [
                        92, 43, 166, 165, 124, 76, 134, 216, 4, 231, 243, 254, 64, 93, 199, 125,
                        139, 181, 229, 249,
                    ],
                    [
                        151, 91, 168, 48, 145, 123, 21, 71, 12, 230, 86, 252, 202, 20, 77, 74, 229,
                        220, 206, 34,
                    ],
                    [
                        213, 184, 15, 212, 67, 124, 35, 127, 29, 174, 127, 191, 137, 157, 62, 30,
                        166, 57, 80, 39,
                    ],
                    [
                        241, 185, 125, 2, 79, 89, 161, 246, 223, 144, 185, 1, 248, 28, 86, 187,
                        201, 77, 197, 222,
                    ],
                    [
                        176, 88, 15, 71, 51, 253, 149, 226, 35, 224, 228, 61, 48, 102, 156, 23, 1,
                        181, 234, 53,
                    ],
                    [
                        154, 138, 111, 10, 51, 112, 74, 62, 95, 228, 166, 101, 223, 202, 58, 11,
                        20, 245, 69, 13,
                    ],
                    [
                        213, 120, 12, 249, 2, 182, 61, 104, 244, 173, 150, 100, 61, 233, 141, 162,
                        36, 203, 50, 135,
                    ],
                    [
                        191, 98, 182, 133, 38, 28, 133, 25, 3, 63, 156, 214, 211, 207, 229, 145,
                        252, 215, 139, 185,
                    ],
                    [
                        54, 246, 204, 232, 169, 117, 121, 106, 209, 216, 251, 118, 153, 2, 89, 202,
                        229, 28, 125, 101,
                    ],
                    [
                        133, 201, 106, 74, 1, 104, 115, 95, 203, 17, 123, 132, 254, 199, 75, 177,
                        6, 60, 8, 211,
                    ],
                    [
                        240, 199, 88, 210, 23, 14, 79, 138, 34, 123, 193, 25, 96, 61, 251, 95, 65,
                        239, 154, 242,
                    ],
                    [
                        2, 139, 157, 95, 152, 16, 139, 112, 216, 51, 171, 237, 130, 118, 253, 95,
                        148, 126, 129, 13,
                    ],
                    [
                        229, 4, 236, 48, 225, 212, 189, 212, 88, 172, 109, 73, 22, 24, 79, 131,
                        202, 156, 49, 160,
                    ],
                    [
                        234, 170, 86, 201, 26, 4, 141, 9, 111, 230, 190, 56, 146, 101, 68, 2, 94,
                        230, 121, 188,
                    ],
                    [
                        233, 216, 19, 123, 215, 210, 170, 66, 24, 134, 186, 105, 251, 13, 58, 38,
                        84, 4, 22, 89,
                    ],
                    [
                        87, 228, 34, 116, 141, 214, 72, 140, 3, 2, 149, 185, 128, 39, 7, 219, 239,
                        192, 204, 152,
                    ],
                    [
                        82, 240, 125, 215, 79, 203, 244, 152, 134, 124, 161, 106, 182, 218, 141,
                        70, 105, 9, 233, 139,
                    ],
                    [
                        234, 219, 91, 219, 46, 2, 149, 11, 66, 235, 142, 112, 248, 138, 31, 168,
                        247, 239, 94, 194,
                    ],
                    [
                        254, 199, 23, 149, 206, 14, 169, 46, 0, 161, 101, 14, 123, 37, 100, 158,
                        225, 96, 7, 86,
                    ],
                    [
                        107, 236, 97, 80, 10, 122, 131, 67, 135, 242, 180, 101, 99, 56, 206, 201,
                        160, 241, 64, 135,
                    ],
                    [
                        65, 178, 240, 237, 190, 126, 117, 245, 175, 214, 115, 253, 211, 67, 195,
                        221, 24, 125, 29, 145,
                    ],
                    [
                        171, 59, 9, 86, 3, 75, 9, 116, 228, 175, 138, 205, 54, 215, 137, 90, 136,
                        186, 123, 58,
                    ],
                    [
                        208, 73, 201, 229, 78, 162, 171, 214, 57, 71, 76, 100, 83, 10, 239, 131,
                        29, 163, 247, 51,
                    ],
                    [
                        23, 244, 90, 101, 35, 147, 170, 96, 247, 201, 45, 32, 245, 236, 251, 169,
                        8, 55, 64, 51,
                    ],
                    [
                        78, 160, 29, 74, 181, 205, 161, 53, 20, 113, 85, 249, 246, 97, 92, 36, 24,
                        214, 66, 173,
                    ],
                    [
                        237, 242, 172, 74, 63, 213, 53, 180, 39, 195, 146, 162, 181, 121, 239, 247,
                        168, 174, 235, 32,
                    ],
                    [
                        246, 67, 126, 78, 179, 121, 65, 157, 29, 45, 62, 105, 254, 171, 167, 224,
                        123, 96, 239, 156,
                    ],
                    [
                        97, 211, 61, 190, 112, 228, 125, 46, 131, 88, 251, 22, 75, 250, 45, 156,
                        212, 200, 231, 222,
                    ],
                    [
                        240, 50, 81, 18, 101, 23, 101, 56, 184, 1, 205, 48, 25, 199, 243, 106, 151,
                        246, 102, 102,
                    ],
                    [
                        138, 130, 227, 58, 33, 33, 98, 239, 72, 19, 155, 248, 15, 128, 244, 35,
                        249, 19, 167, 31,
                    ],
                    [
                        157, 95, 70, 137, 234, 132, 191, 237, 61, 118, 156, 62, 54, 47, 210, 6,
                        178, 219, 134, 220,
                    ],
                    [
                        161, 130, 36, 62, 228, 232, 96, 116, 29, 58, 32, 161, 9, 80, 198, 207, 177,
                        79, 68, 23,
                    ],
                    [
                        47, 196, 233, 76, 62, 122, 204, 216, 39, 26, 15, 163, 44, 209, 69, 23, 174,
                        76, 205, 192,
                    ],
                    [
                        238, 124, 77, 132, 48, 126, 168, 105, 40, 119, 156, 118, 205, 204, 66, 68,
                        164, 83, 36, 188,
                    ],
                    [
                        249, 177, 65, 102, 66, 150, 202, 121, 240, 157, 219, 58, 159, 80, 209, 169,
                        116, 212, 98, 246,
                    ],
                    [
                        35, 117, 66, 230, 118, 97, 132, 169, 40, 107, 65, 77, 198, 230, 190, 163,
                        185, 132, 53, 201,
                    ],
                    [
                        145, 108, 184, 113, 104, 12, 14, 208, 164, 30, 145, 104, 226, 58, 20, 216,
                        76, 244, 171, 80,
                    ],
                    [
                        220, 240, 212, 118, 253, 169, 132, 228, 218, 58, 246, 107, 99, 190, 158,
                        109, 100, 199, 66, 185,
                    ],
                    [
                        89, 233, 78, 207, 0, 135, 254, 94, 83, 207, 193, 44, 178, 233, 241, 167,
                        102, 109, 207, 133,
                    ],
                    [
                        62, 197, 195, 238, 65, 243, 69, 237, 238, 27, 144, 193, 36, 76, 30, 119, 3,
                        236, 89, 238,
                    ],
                    [
                        7, 17, 62, 51, 2, 104, 147, 224, 176, 174, 150, 239, 145, 112, 84, 1, 250,
                        133, 231, 85,
                    ],
                    [
                        40, 244, 212, 219, 79, 171, 204, 138, 238, 11, 64, 188, 177, 41, 12, 174,
                        247, 205, 138, 46,
                    ],
                    [
                        17, 160, 50, 171, 72, 42, 232, 235, 40, 177, 192, 178, 207, 217, 213, 187,
                        79, 11, 129, 2,
                    ],
                    [
                        10, 214, 34, 43, 9, 70, 152, 199, 113, 214, 59, 16, 177, 238, 56, 170, 75,
                        238, 183, 11,
                    ],
                    [
                        204, 243, 125, 11, 181, 4, 108, 22, 94, 203, 231, 30, 30, 194, 165, 121,
                        162, 190, 64, 135,
                    ],
                    [
                        101, 78, 226, 158, 7, 149, 80, 184, 4, 228, 153, 205, 26, 162, 25, 90, 68,
                        158, 218, 222,
                    ],
                    [
                        176, 116, 38, 103, 166, 81, 223, 90, 52, 94, 46, 189, 110, 110, 56, 15, 0,
                        149, 143, 233,
                    ],
                    [
                        254, 171, 90, 174, 0, 224, 113, 64, 121, 1, 122, 226, 82, 94, 86, 228, 234,
                        76, 189, 187,
                    ],
                    [
                        83, 140, 14, 11, 221, 154, 91, 53, 175, 160, 244, 198, 174, 19, 230, 84,
                        171, 128, 71, 207,
                    ],
                    [
                        222, 200, 121, 34, 51, 98, 204, 145, 178, 60, 32, 28, 91, 238, 133, 25, 58,
                        26, 150, 101,
                    ],
                    [
                        143, 38, 168, 247, 211, 186, 214, 161, 12, 9, 146, 29, 164, 231, 74, 192,
                        222, 100, 243, 224,
                    ],
                    [
                        15, 9, 83, 252, 138, 31, 15, 124, 157, 254, 171, 53, 216, 131, 193, 255,
                        221, 223, 206, 19,
                    ],
                    [
                        118, 208, 38, 245, 226, 36, 79, 15, 197, 233, 65, 142, 79, 137, 81, 181,
                        80, 52, 67, 81,
                    ],
                    [
                        235, 53, 174, 131, 53, 154, 73, 209, 116, 16, 105, 119, 48, 68, 146, 164,
                        195, 146, 153, 223,
                    ],
                    [
                        128, 33, 233, 36, 10, 13, 118, 68, 64, 190, 133, 243, 204, 119, 64, 155,
                        123, 144, 27, 49,
                    ],
                    [
                        227, 141, 219, 243, 190, 239, 232, 49, 118, 173, 47, 151, 130, 100, 81, 40,
                        40, 104, 68, 132,
                    ],
                    [
                        181, 164, 111, 139, 27, 5, 59, 128, 55, 255, 232, 228, 43, 139, 74, 98, 51,
                        149, 61, 59,
                    ],
                    [
                        239, 171, 176, 203, 48, 57, 201, 32, 116, 158, 90, 37, 225, 105, 3, 5, 112,
                        19, 119, 155,
                    ],
                    [
                        219, 128, 47, 146, 166, 65, 155, 111, 50, 113, 153, 196, 7, 134, 203, 211,
                        89, 148, 79, 10,
                    ],
                    [
                        230, 131, 84, 190, 95, 122, 46, 246, 228, 203, 104, 124, 230, 166, 205, 72,
                        12, 110, 222, 227,
                    ],
                    [
                        147, 143, 60, 130, 188, 59, 251, 205, 113, 217, 131, 55, 36, 115, 161, 180,
                        213, 126, 113, 125,
                    ],
                    [
                        48, 81, 69, 185, 236, 1, 194, 180, 239, 218, 85, 54, 197, 226, 38, 201, 36,
                        123, 133, 227,
                    ],
                    [
                        222, 112, 45, 183, 80, 46, 148, 43, 119, 126, 72, 187, 42, 106, 158, 149,
                        187, 25, 27, 86,
                    ],
                    [
                        147, 96, 128, 234, 158, 83, 152, 54, 83, 156, 18, 7, 244, 252, 35, 235,
                        201, 200, 30, 20,
                    ],
                    [
                        236, 105, 29, 112, 11, 143, 109, 189, 150, 193, 187, 195, 215, 246, 151,
                        252, 188, 80, 56, 172,
                    ],
                    [
                        108, 193, 251, 203, 254, 200, 5, 172, 141, 231, 35, 76, 190, 235, 29, 17,
                        146, 97, 206, 236,
                    ],
                    [
                        160, 215, 137, 215, 79, 192, 192, 100, 31, 81, 82, 5, 228, 163, 61, 37,
                        254, 207, 238, 40,
                    ],
                    [
                        65, 157, 34, 132, 74, 120, 143, 172, 194, 2, 98, 187, 163, 200, 137, 83,
                        73, 141, 167, 112,
                    ],
                    [
                        98, 220, 212, 216, 159, 40, 19, 45, 196, 45, 122, 67, 96, 193, 234, 28,
                        154, 92, 43, 221,
                    ],
                    [
                        154, 38, 14, 252, 194, 91, 127, 132, 245, 22, 173, 26, 21, 104, 225, 134,
                        224, 173, 225, 237,
                    ],
                    [
                        37, 152, 76, 50, 100, 182, 44, 239, 151, 8, 215, 34, 184, 246, 2, 83, 85,
                        144, 175, 131,
                    ],
                    [
                        161, 110, 132, 124, 125, 81, 124, 79, 148, 83, 203, 58, 128, 98, 228, 239,
                        215, 120, 244, 173,
                    ],
                    [
                        85, 227, 170, 161, 174, 23, 242, 5, 36, 159, 192, 175, 220, 69, 155, 34,
                        158, 102, 13, 144,
                    ],
                    [
                        95, 185, 15, 0, 188, 118, 93, 52, 56, 221, 171, 168, 135, 68, 134, 228, 90,
                        68, 125, 115,
                    ],
                    [
                        138, 248, 183, 245, 86, 20, 89, 224, 11, 134, 41, 195, 98, 169, 101, 33,
                        71, 155, 227, 60,
                    ],
                    [
                        203, 151, 53, 1, 194, 252, 229, 225, 148, 15, 41, 194, 134, 237, 204, 108,
                        69, 126, 55, 195,
                    ],
                    [
                        37, 56, 215, 135, 213, 99, 129, 114, 100, 222, 43, 112, 78, 88, 159, 106,
                        232, 28, 147, 171,
                    ],
                    [
                        8, 151, 92, 154, 5, 51, 236, 238, 112, 31, 18, 34, 118, 253, 237, 33, 1,
                        220, 185, 125,
                    ],
                    [
                        90, 117, 90, 53, 200, 69, 212, 51, 200, 164, 240, 23, 200, 235, 118, 113,
                        69, 61, 86, 183,
                    ],
                    [
                        123, 155, 13, 79, 19, 143, 71, 205, 10, 189, 197, 115, 121, 165, 19, 203,
                        52, 117, 175, 102,
                    ],
                    [
                        75, 87, 217, 168, 160, 180, 246, 91, 143, 37, 1, 72, 78, 80, 4, 32, 59,
                        153, 34, 103,
                    ],
                    [
                        160, 202, 186, 117, 98, 50, 121, 253, 168, 45, 21, 184, 78, 176, 9, 1, 117,
                        128, 253, 9,
                    ],
                    [
                        167, 207, 73, 159, 110, 54, 99, 23, 138, 237, 120, 102, 74, 100, 0, 59,
                        134, 53, 166, 162,
                    ],
                    [
                        93, 103, 52, 158, 62, 15, 70, 47, 106, 85, 22, 184, 185, 57, 10, 190, 222,
                        8, 6, 121,
                    ],
                    [
                        183, 18, 208, 238, 49, 248, 48, 121, 87, 133, 41, 135, 34, 54, 184, 253,
                        15, 240, 197, 201,
                    ],
                    [
                        201, 134, 30, 240, 17, 190, 199, 234, 210, 96, 83, 46, 101, 116, 215, 119,
                        62, 241, 52, 172,
                    ],
                    [
                        28, 119, 170, 60, 62, 154, 11, 99, 189, 92, 107, 169, 30, 137, 184, 98,
                        167, 171, 244, 209,
                    ],
                    [
                        60, 109, 98, 62, 202, 7, 3, 85, 242, 148, 243, 158, 211, 35, 215, 161, 53,
                        7, 161, 123,
                    ],
                    [
                        164, 92, 241, 234, 212, 215, 101, 219, 22, 175, 180, 141, 123, 164, 191,
                        242, 120, 26, 146, 35,
                    ],
                    [
                        134, 14, 188, 250, 1, 90, 204, 205, 73, 9, 141, 28, 231, 64, 83, 211, 20,
                        34, 130, 110,
                    ],
                    [
                        151, 10, 207, 135, 207, 179, 121, 198, 139, 139, 27, 146, 105, 61, 222,
                        121, 4, 106, 199, 44,
                    ],
                    [
                        149, 243, 115, 212, 60, 95, 88, 39, 252, 69, 177, 172, 140, 67, 198, 161,
                        96, 216, 57, 142,
                    ],
                    [
                        212, 233, 125, 43, 73, 67, 238, 25, 47, 136, 253, 116, 193, 111, 36, 183,
                        22, 36, 71, 91,
                    ],
                    [
                        33, 94, 209, 151, 138, 108, 212, 60, 123, 39, 137, 8, 125, 185, 93, 83,
                        138, 171, 169, 66,
                    ],
                    [
                        208, 75, 118, 103, 178, 65, 97, 237, 165, 226, 207, 212, 35, 195, 20, 70,
                        156, 221, 184, 50,
                    ],
                    [
                        63, 12, 159, 246, 242, 249, 100, 96, 53, 9, 228, 161, 250, 1, 253, 4, 88,
                        53, 127, 170,
                    ],
                    [
                        82, 39, 11, 14, 41, 109, 46, 16, 140, 92, 153, 189, 215, 118, 100, 179,
                        108, 198, 64, 90,
                    ],
                    [
                        20, 159, 138, 92, 17, 82, 108, 155, 234, 81, 112, 118, 177, 149, 27, 72,
                        18, 132, 74, 10,
                    ],
                    [
                        173, 125, 234, 68, 113, 82, 61, 110, 211, 103, 64, 79, 21, 79, 245, 79, 39,
                        23, 250, 20,
                    ],
                    [
                        118, 37, 138, 148, 75, 153, 180, 87, 112, 74, 175, 220, 195, 192, 37, 146,
                        59, 110, 41, 77,
                    ],
                    [
                        147, 106, 74, 56, 97, 168, 49, 116, 95, 175, 19, 49, 30, 54, 230, 219, 28,
                        24, 121, 181,
                    ],
                    [
                        85, 129, 84, 129, 215, 104, 137, 249, 180, 43, 170, 254, 176, 4, 131, 41,
                        234, 209, 167, 202,
                    ],
                    [
                        209, 15, 150, 142, 186, 234, 139, 163, 178, 124, 158, 212, 49, 189, 177,
                        136, 24, 99, 229, 49,
                    ],
                    [
                        80, 59, 75, 105, 105, 171, 231, 138, 24, 60, 152, 220, 11, 0, 190, 204,
                        171, 245, 201, 126,
                    ],
                    [
                        84, 71, 17, 64, 53, 50, 95, 24, 106, 68, 183, 107, 222, 123, 234, 70, 5,
                        143, 160, 101,
                    ],
                    [
                        77, 194, 40, 40, 178, 139, 57, 212, 18, 77, 219, 237, 130, 125, 120, 84,
                        172, 0, 207, 28,
                    ],
                    [
                        69, 190, 123, 24, 31, 174, 51, 232, 55, 144, 141, 141, 90, 49, 210, 127,
                        179, 26, 51, 246,
                    ],
                    [
                        177, 128, 174, 132, 14, 155, 106, 249, 59, 254, 43, 181, 125, 177, 8, 223,
                        177, 246, 66, 243,
                    ],
                    [
                        160, 85, 236, 158, 43, 160, 17, 33, 83, 188, 4, 178, 206, 200, 16, 242, 61,
                        254, 113, 33,
                    ],
                    [
                        137, 65, 18, 5, 96, 39, 73, 30, 136, 88, 113, 134, 61, 5, 32, 164, 83, 65,
                        39, 197,
                    ],
                    [
                        62, 85, 137, 112, 237, 151, 44, 169, 173, 207, 184, 103, 104, 165, 237,
                        199, 36, 195, 74, 180,
                    ],
                    [
                        15, 245, 119, 67, 10, 196, 7, 65, 39, 155, 234, 150, 246, 6, 44, 248, 126,
                        80, 187, 250,
                    ],
                    [
                        187, 247, 126, 177, 133, 131, 163, 123, 30, 24, 192, 249, 9, 211, 96, 11,
                        167, 16, 53, 247,
                    ],
                    [
                        251, 96, 6, 14, 99, 195, 48, 248, 9, 56, 137, 166, 247, 15, 155, 111, 252,
                        15, 143, 222,
                    ],
                    [
                        158, 9, 44, 98, 113, 224, 182, 228, 147, 239, 63, 7, 60, 179, 210, 20, 181,
                        233, 25, 59,
                    ],
                    [
                        66, 146, 48, 141, 107, 208, 38, 188, 209, 178, 118, 216, 161, 221, 73, 65,
                        158, 46, 127, 181,
                    ],
                    [
                        24, 135, 189, 138, 40, 24, 141, 242, 216, 58, 120, 36, 79, 255, 180, 147,
                        103, 164, 10, 202,
                    ],
                    [
                        126, 142, 225, 134, 87, 72, 82, 19, 76, 96, 59, 70, 243, 2, 168, 166, 78,
                        3, 128, 56,
                    ],
                    [
                        12, 35, 4, 83, 82, 241, 161, 187, 61, 189, 38, 146, 77, 6, 209, 115, 76,
                        78, 245, 52,
                    ],
                    [
                        81, 248, 204, 254, 146, 236, 135, 114, 23, 234, 250, 176, 43, 252, 197, 13,
                        174, 33, 168, 39,
                    ],
                    [
                        14, 77, 124, 101, 187, 240, 27, 52, 182, 91, 151, 2, 251, 213, 60, 16, 13,
                        255, 89, 20,
                    ],
                    [
                        94, 184, 176, 213, 33, 234, 14, 239, 33, 164, 42, 126, 147, 193, 59, 223,
                        208, 245, 163, 95,
                    ],
                    [
                        132, 84, 214, 179, 128, 79, 120, 193, 4, 100, 31, 133, 228, 110, 192, 76,
                        244, 186, 95, 31,
                    ],
                    [
                        103, 211, 67, 103, 252, 34, 231, 209, 197, 67, 163, 123, 119, 124, 250, 36,
                        104, 129, 112, 14,
                    ],
                    [
                        174, 162, 223, 192, 125, 85, 226, 13, 240, 171, 68, 214, 208, 141, 18, 116,
                        177, 89, 166, 228,
                    ],
                    [
                        107, 72, 21, 121, 255, 103, 125, 103, 103, 255, 29, 18, 216, 146, 78, 236,
                        92, 251, 237, 43,
                    ],
                    [
                        248, 192, 11, 95, 164, 66, 70, 253, 90, 124, 29, 204, 234, 30, 112, 29,
                        196, 2, 231, 103,
                    ],
                    [
                        67, 244, 187, 227, 55, 182, 205, 10, 248, 49, 58, 73, 73, 234, 73, 47, 16,
                        182, 184, 29,
                    ],
                    [
                        88, 142, 3, 128, 16, 64, 243, 75, 234, 61, 84, 34, 111, 149, 75, 49, 122,
                        65, 150, 35,
                    ],
                    [
                        175, 1, 252, 203, 190, 85, 191, 62, 65, 15, 161, 251, 113, 178, 91, 214,
                        241, 255, 222, 162,
                    ],
                    [
                        146, 109, 245, 221, 93, 197, 235, 42, 235, 148, 210, 13, 26, 128, 211, 29,
                        131, 200, 118, 165,
                    ],
                    [
                        21, 47, 253, 102, 49, 120, 148, 211, 96, 242, 221, 41, 36, 186, 141, 154,
                        62, 175, 11, 180,
                    ],
                    [
                        149, 118, 69, 170, 203, 152, 255, 14, 26, 131, 68, 208, 233, 186, 171, 55,
                        127, 94, 37, 53,
                    ],
                    [
                        98, 161, 130, 187, 25, 84, 154, 245, 61, 96, 250, 69, 90, 113, 103, 208, 3,
                        108, 241, 165,
                    ],
                    [
                        232, 187, 238, 213, 21, 233, 252, 128, 72, 0, 13, 88, 213, 82, 201, 137,
                        88, 50, 169, 112,
                    ],
                    [
                        113, 247, 180, 151, 77, 148, 160, 153, 58, 125, 193, 112, 141, 139, 168,
                        107, 41, 5, 141, 172,
                    ],
                    [
                        64, 72, 52, 22, 227, 91, 243, 89, 41, 155, 157, 220, 179, 56, 136, 109,
                        125, 209, 19, 30,
                    ],
                    [
                        215, 99, 85, 2, 196, 253, 50, 70, 63, 133, 69, 188, 187, 72, 201, 161, 242,
                        108, 37, 237,
                    ],
                    [
                        40, 35, 215, 121, 197, 57, 179, 217, 90, 26, 119, 160, 220, 155, 33, 98,
                        167, 245, 65, 70,
                    ],
                    [
                        119, 142, 48, 253, 31, 149, 161, 159, 201, 123, 132, 17, 191, 155, 121, 5,
                        9, 34, 216, 21,
                    ],
                    [
                        24, 119, 196, 112, 169, 131, 24, 200, 44, 49, 71, 195, 1, 3, 6, 173, 176,
                        255, 53, 86,
                    ],
                    [
                        239, 109, 240, 187, 236, 203, 93, 156, 52, 237, 74, 189, 89, 181, 91, 238,
                        237, 250, 12, 161,
                    ],
                    [
                        160, 152, 98, 222, 44, 175, 64, 202, 169, 235, 22, 36, 163, 20, 239, 136,
                        127, 8, 2, 235,
                    ],
                    [
                        78, 160, 141, 10, 109, 8, 90, 230, 168, 14, 25, 55, 115, 254, 215, 233, 45,
                        120, 74, 73,
                    ],
                    [
                        240, 85, 80, 16, 151, 49, 176, 138, 176, 203, 221, 56, 200, 196, 191, 235,
                        36, 119, 180, 58,
                    ],
                    [
                        203, 121, 239, 84, 183, 148, 149, 44, 23, 120, 5, 15, 166, 204, 177, 43,
                        14, 93, 192, 54,
                    ],
                    [
                        11, 98, 202, 246, 47, 7, 227, 48, 153, 96, 12, 114, 198, 134, 144, 180,
                        189, 83, 111, 123,
                    ],
                    [
                        2, 79, 75, 168, 172, 94, 94, 21, 224, 192, 172, 55, 29, 247, 11, 202, 172,
                        250, 84, 2,
                    ],
                    [
                        212, 220, 214, 163, 111, 191, 165, 163, 228, 203, 216, 20, 220, 53, 225,
                        145, 48, 49, 141, 162,
                    ],
                    [
                        138, 5, 80, 228, 140, 239, 47, 225, 242, 229, 121, 181, 64, 213, 47, 206,
                        132, 198, 56, 102,
                    ],
                    [
                        219, 104, 86, 171, 126, 68, 245, 114, 90, 128, 117, 96, 47, 119, 172, 34,
                        124, 217, 57, 219,
                    ],
                    [
                        247, 109, 229, 105, 182, 232, 64, 170, 238, 127, 211, 155, 7, 54, 209, 221,
                        237, 69, 169, 242,
                    ],
                    [
                        122, 46, 157, 162, 238, 27, 146, 166, 134, 56, 61, 240, 120, 66, 106, 171,
                        174, 251, 238, 223,
                    ],
                    [
                        29, 197, 180, 150, 28, 82, 48, 173, 22, 239, 88, 196, 65, 128, 104, 148,
                        188, 99, 219, 64,
                    ],
                    [
                        52, 140, 240, 165, 25, 214, 218, 100, 100, 100, 45, 179, 0, 131, 38, 239,
                        145, 34, 209, 51,
                    ],
                    [
                        33, 84, 229, 74, 14, 34, 67, 130, 207, 114, 133, 237, 45, 230, 104, 201,
                        189, 71, 62, 238,
                    ],
                    [
                        38, 245, 179, 121, 183, 244, 3, 92, 90, 239, 255, 207, 26, 50, 32, 226, 63,
                        85, 83, 214,
                    ],
                    [
                        134, 88, 123, 33, 101, 123, 166, 206, 181, 142, 44, 43, 200, 78, 157, 82,
                        55, 154, 108, 148,
                    ],
                    [
                        253, 13, 217, 244, 52, 142, 43, 41, 255, 31, 155, 227, 91, 133, 213, 127,
                        107, 137, 75, 197,
                    ],
                    [
                        90, 242, 237, 104, 145, 205, 103, 217, 102, 127, 255, 160, 43, 171, 127,
                        107, 124, 249, 112, 250,
                    ],
                    [
                        176, 228, 251, 192, 133, 227, 11, 122, 28, 165, 230, 166, 23, 217, 151, 18,
                        187, 202, 65, 161,
                    ],
                    [
                        41, 216, 101, 42, 24, 31, 199, 171, 225, 88, 135, 212, 243, 132, 59, 196,
                        35, 121, 104, 230,
                    ],
                    [
                        129, 75, 228, 149, 205, 43, 140, 4, 80, 253, 210, 61, 41, 127, 125, 243,
                        13, 58, 236, 37,
                    ],
                    [
                        169, 92, 105, 125, 10, 92, 17, 246, 122, 56, 206, 249, 249, 93, 50, 53, 76,
                        226, 158, 125,
                    ],
                    [
                        134, 70, 54, 253, 151, 0, 71, 15, 42, 79, 116, 99, 190, 143, 121, 62, 90,
                        193, 47, 168,
                    ],
                    [
                        65, 232, 58, 243, 210, 13, 95, 45, 127, 246, 135, 35, 25, 249, 205, 254,
                        71, 71, 65, 161,
                    ],
                    [
                        43, 140, 171, 234, 118, 41, 170, 254, 66, 30, 58, 59, 185, 4, 147, 230,
                        204, 146, 87, 223,
                    ],
                    [
                        171, 154, 163, 199, 243, 48, 146, 4, 120, 137, 195, 15, 59, 70, 53, 111,
                        80, 13, 214, 79,
                    ],
                    [
                        142, 36, 21, 71, 183, 41, 113, 15, 43, 158, 4, 169, 38, 210, 243, 243, 131,
                        47, 210, 236,
                    ],
                    [
                        184, 149, 160, 239, 53, 54, 190, 242, 182, 57, 248, 33, 83, 42, 136, 223,
                        215, 123, 98, 242,
                    ],
                    [
                        138, 3, 247, 148, 7, 116, 92, 161, 128, 211, 197, 145, 142, 125, 189, 220,
                        116, 75, 73, 194,
                    ],
                    [
                        244, 156, 145, 3, 0, 201, 228, 139, 142, 92, 49, 213, 76, 39, 198, 141,
                        226, 118, 42, 254,
                    ],
                    [
                        207, 198, 150, 112, 45, 162, 112, 227, 209, 197, 131, 92, 37, 145, 186,
                        114, 16, 137, 200, 120,
                    ],
                    [
                        246, 196, 117, 167, 15, 108, 195, 133, 107, 17, 38, 85, 112, 130, 34, 93,
                        81, 44, 169, 233,
                    ],
                    [
                        246, 206, 231, 79, 150, 253, 103, 215, 163, 246, 108, 133, 7, 26, 47, 94,
                        198, 64, 208, 25,
                    ],
                    [
                        118, 197, 96, 112, 215, 79, 51, 27, 216, 210, 89, 171, 86, 56, 96, 206,
                        104, 7, 9, 85,
                    ],
                    [
                        58, 164, 35, 154, 62, 61, 214, 81, 154, 120, 175, 199, 182, 210, 183, 9,
                        196, 57, 114, 115,
                    ],
                    [
                        69, 17, 225, 32, 43, 207, 95, 232, 33, 248, 163, 80, 88, 152, 47, 205, 189,
                        99, 147, 11,
                    ],
                    [
                        101, 248, 146, 70, 122, 159, 169, 83, 110, 148, 125, 42, 33, 144, 195, 111,
                        114, 250, 49, 51,
                    ],
                    [
                        77, 237, 59, 55, 88, 48, 155, 174, 190, 229, 185, 194, 172, 213, 6, 71,
                        168, 223, 198, 169,
                    ],
                    [
                        223, 92, 65, 138, 33, 36, 183, 156, 165, 179, 43, 8, 109, 111, 50, 217,
                        218, 178, 173, 155,
                    ],
                    [
                        232, 157, 18, 127, 186, 205, 202, 9, 95, 123, 59, 161, 90, 91, 139, 68,
                        171, 203, 197, 97,
                    ],
                    [
                        87, 150, 60, 84, 0, 136, 106, 55, 149, 91, 63, 166, 82, 228, 109, 167, 25,
                        23, 222, 23,
                    ],
                    [
                        244, 19, 255, 34, 236, 244, 192, 132, 136, 70, 146, 210, 41, 107, 130, 125,
                        153, 35, 7, 113,
                    ],
                    [
                        103, 187, 19, 203, 222, 228, 237, 121, 15, 100, 67, 39, 99, 30, 116, 180,
                        207, 122, 210, 185,
                    ],
                    [
                        227, 23, 111, 211, 85, 15, 167, 193, 172, 160, 138, 138, 136, 214, 45, 14,
                        140, 246, 110, 119,
                    ],
                    [
                        112, 82, 177, 70, 131, 87, 106, 184, 173, 88, 17, 221, 29, 84, 171, 217,
                        61, 162, 1, 176,
                    ],
                    [
                        244, 38, 223, 31, 159, 192, 144, 58, 137, 9, 33, 62, 112, 103, 225, 9, 17,
                        88, 137, 47,
                    ],
                    [
                        238, 91, 184, 224, 62, 173, 97, 184, 195, 33, 44, 72, 114, 155, 248, 203,
                        195, 28, 119, 7,
                    ],
                    [
                        62, 114, 152, 43, 254, 250, 103, 58, 217, 251, 207, 35, 78, 11, 113, 42,
                        70, 139, 143, 42,
                    ],
                    [
                        34, 99, 138, 229, 254, 32, 66, 91, 20, 111, 131, 63, 108, 24, 8, 227, 235,
                        8, 157, 163,
                    ],
                    [
                        219, 219, 148, 211, 9, 70, 104, 162, 153, 142, 28, 254, 68, 67, 141, 90,
                        203, 83, 115, 29,
                    ],
                    [
                        184, 252, 201, 80, 251, 148, 28, 41, 88, 248, 59, 40, 104, 22, 248, 229,
                        192, 121, 225, 102,
                    ],
                    [
                        161, 55, 170, 191, 187, 163, 250, 24, 178, 117, 0, 18, 117, 189, 159, 170,
                        249, 130, 40, 226,
                    ],
                    [
                        126, 80, 54, 59, 174, 46, 90, 117, 237, 192, 167, 224, 29, 181, 0, 121,
                        239, 161, 104, 104,
                    ],
                    [
                        71, 176, 167, 98, 230, 237, 117, 112, 117, 105, 188, 159, 143, 74, 184, 15,
                        64, 158, 81, 112,
                    ],
                    [
                        18, 202, 16, 213, 103, 100, 237, 233, 154, 176, 222, 160, 135, 241, 215,
                        246, 120, 223, 175, 148,
                    ],
                    [
                        144, 10, 30, 148, 201, 9, 111, 208, 45, 95, 103, 58, 38, 138, 87, 177, 107,
                        124, 83, 126,
                    ],
                    [
                        221, 220, 250, 182, 145, 192, 25, 84, 80, 142, 18, 142, 246, 243, 125, 104,
                        21, 133, 225, 129,
                    ],
                    [
                        241, 105, 161, 144, 161, 203, 20, 161, 131, 169, 179, 173, 126, 25, 151,
                        183, 203, 43, 225, 48,
                    ],
                    [
                        13, 247, 243, 44, 212, 28, 157, 125, 6, 179, 123, 14, 103, 205, 202, 39,
                        20, 147, 187, 188,
                    ],
                    [
                        49, 213, 216, 18, 65, 28, 88, 222, 165, 248, 105, 242, 84, 169, 18, 114,
                        150, 62, 178, 103,
                    ],
                    [
                        33, 215, 26, 0, 172, 253, 112, 161, 243, 233, 85, 219, 153, 119, 47, 191,
                        142, 43, 217, 132,
                    ],
                    [
                        249, 172, 113, 81, 176, 22, 213, 217, 76, 215, 173, 66, 154, 64, 73, 115,
                        222, 75, 182, 114,
                    ],
                    [
                        173, 63, 1, 178, 163, 110, 132, 250, 239, 166, 136, 146, 110, 133, 155,
                        122, 92, 64, 96, 81,
                    ],
                    [
                        247, 96, 37, 50, 9, 92, 23, 53, 85, 160, 245, 51, 105, 99, 168, 19, 139,
                        163, 158, 143,
                    ],
                    [
                        180, 47, 68, 139, 220, 166, 186, 193, 61, 198, 166, 184, 239, 105, 148, 77,
                        125, 241, 231, 194,
                    ],
                    [
                        94, 215, 252, 138, 240, 200, 239, 79, 249, 197, 10, 255, 229, 6, 130, 11,
                        53, 191, 219, 196,
                    ],
                    [
                        81, 141, 141, 191, 197, 153, 102, 229, 138, 77, 11, 23, 123, 175, 146, 128,
                        188, 123, 161, 206,
                    ],
                    [
                        7, 100, 238, 203, 205, 9, 191, 14, 206, 239, 4, 109, 244, 98, 12, 201, 120,
                        17, 39, 155,
                    ],
                    [
                        184, 7, 172, 162, 187, 191, 253, 156, 170, 222, 27, 253, 191, 215, 58, 139,
                        235, 16, 116, 223,
                    ],
                    [
                        220, 219, 64, 42, 61, 192, 175, 21, 227, 148, 173, 245, 5, 126, 191, 227,
                        183, 10, 149, 240,
                    ],
                    [
                        183, 185, 58, 26, 113, 218, 114, 253, 35, 163, 4, 167, 155, 121, 104, 38,
                        129, 159, 18, 112,
                    ],
                    [
                        165, 224, 206, 148, 106, 84, 232, 190, 149, 159, 142, 148, 134, 241, 129,
                        16, 111, 248, 111, 249,
                    ],
                    [
                        179, 129, 67, 48, 33, 224, 166, 137, 71, 114, 18, 85, 41, 161, 129, 202,
                        241, 102, 5, 160,
                    ],
                    [
                        161, 13, 207, 193, 168, 18, 8, 223, 131, 201, 148, 60, 50, 54, 18, 168, 5,
                        210, 204, 230,
                    ],
                    [
                        117, 158, 39, 84, 96, 23, 168, 107, 141, 41, 4, 92, 132, 169, 96, 102, 225,
                        215, 178, 87,
                    ],
                    [
                        226, 133, 78, 176, 172, 144, 2, 79, 163, 182, 72, 73, 62, 76, 217, 107,
                        194, 121, 63, 233,
                    ],
                    [
                        175, 32, 6, 97, 239, 126, 162, 201, 67, 125, 72, 130, 241, 80, 73, 121,
                        223, 168, 17, 26,
                    ],
                    [
                        87, 104, 127, 138, 8, 48, 103, 131, 208, 35, 94, 159, 133, 113, 88, 240,
                        187, 202, 27, 6,
                    ],
                    [
                        108, 7, 51, 222, 132, 151, 232, 197, 127, 137, 156, 166, 235, 40, 64, 31,
                        137, 107, 91, 244,
                    ],
                    [
                        50, 124, 117, 168, 33, 149, 231, 37, 177, 27, 93, 66, 217, 136, 15, 90,
                        207, 254, 127, 96,
                    ],
                    [
                        145, 182, 133, 105, 27, 15, 155, 206, 118, 85, 137, 103, 200, 31, 20, 153,
                        253, 104, 61, 202,
                    ],
                    [
                        222, 224, 250, 34, 130, 37, 252, 21, 51, 224, 53, 94, 124, 132, 246, 67,
                        75, 182, 58, 162,
                    ],
                    [
                        155, 154, 160, 202, 207, 169, 208, 223, 118, 134, 215, 199, 14, 150, 142,
                        46, 176, 25, 81, 157,
                    ],
                    [
                        80, 56, 128, 128, 15, 161, 247, 229, 229, 62, 230, 212, 107, 198, 53, 38,
                        206, 16, 194, 89,
                    ],
                    [
                        69, 184, 171, 98, 2, 212, 148, 193, 77, 141, 164, 28, 168, 113, 41, 203,
                        132, 155, 115, 255,
                    ],
                    [
                        44, 167, 28, 1, 247, 106, 84, 146, 136, 198, 76, 166, 85, 28, 141, 45, 23,
                        140, 120, 74,
                    ],
                    [
                        30, 146, 114, 205, 240, 203, 10, 145, 118, 187, 160, 237, 213, 94, 72, 216,
                        138, 122, 82, 248,
                    ],
                    [
                        178, 91, 64, 162, 56, 9, 103, 93, 53, 152, 191, 151, 239, 90, 141, 226,
                        153, 57, 110, 214,
                    ],
                    [
                        20, 36, 29, 34, 136, 189, 216, 83, 34, 105, 228, 61, 69, 130, 79, 18, 16,
                        194, 92, 90,
                    ],
                    [
                        12, 214, 251, 69, 8, 169, 202, 8, 225, 121, 0, 191, 113, 192, 51, 133, 252,
                        136, 11, 18,
                    ],
                    [
                        160, 206, 55, 109, 239, 134, 101, 190, 43, 179, 232, 39, 155, 130, 218, 6,
                        89, 149, 124, 253,
                    ],
                    [
                        158, 212, 45, 107, 118, 117, 223, 191, 64, 32, 186, 202, 250, 252, 36, 64,
                        237, 82, 163, 231,
                    ],
                    [
                        124, 4, 59, 3, 160, 61, 196, 38, 253, 167, 96, 214, 170, 232, 158, 8, 255,
                        103, 87, 177,
                    ],
                    [
                        236, 179, 17, 126, 204, 128, 167, 174, 230, 178, 115, 106, 137, 247, 76,
                        172, 239, 248, 236, 122,
                    ],
                    [
                        177, 34, 168, 102, 127, 105, 96, 129, 238, 121, 27, 137, 253, 70, 175, 177,
                        164, 40, 238, 126,
                    ],
                    [
                        124, 196, 63, 220, 236, 160, 101, 130, 206, 157, 132, 116, 45, 213, 64,
                        107, 5, 101, 145, 111,
                    ],
                    [
                        43, 245, 140, 59, 1, 116, 182, 234, 50, 4, 59, 25, 204, 211, 149, 51, 173,
                        94, 255, 30,
                    ],
                    [
                        196, 34, 22, 255, 156, 181, 121, 43, 121, 97, 59, 51, 144, 101, 239, 87,
                        186, 231, 83, 102,
                    ],
                    [
                        188, 93, 230, 133, 117, 203, 94, 182, 231, 10, 239, 174, 195, 21, 151, 198,
                        239, 112, 12, 62,
                    ],
                    [
                        57, 153, 46, 66, 69, 84, 109, 151, 224, 136, 133, 166, 150, 203, 200, 26,
                        206, 105, 179, 5,
                    ],
                    [
                        4, 207, 84, 99, 217, 125, 254, 128, 14, 108, 209, 180, 98, 155, 49, 198,
                        152, 218, 184, 38,
                    ],
                    [
                        60, 236, 46, 211, 84, 222, 28, 254, 172, 95, 247, 208, 137, 225, 83, 4, 30,
                        80, 53, 118,
                    ],
                    [
                        159, 74, 112, 175, 236, 178, 40, 192, 156, 174, 85, 31, 111, 158, 128, 200,
                        66, 6, 30, 206,
                    ],
                    [
                        11, 137, 158, 57, 115, 94, 198, 93, 202, 216, 209, 75, 218, 142, 129, 190,
                        107, 175, 86, 64,
                    ],
                    [
                        182, 121, 7, 208, 109, 80, 154, 1, 1, 53, 101, 121, 117, 88, 30, 88, 175,
                        62, 33, 0,
                    ],
                    [
                        93, 180, 41, 205, 86, 147, 84, 128, 221, 12, 107, 103, 221, 70, 167, 156,
                        180, 137, 136, 249,
                    ],
                    [
                        184, 130, 25, 209, 187, 130, 204, 221, 197, 101, 20, 179, 103, 119, 237,
                        123, 14, 119, 112, 183,
                    ],
                    [
                        128, 169, 118, 246, 239, 161, 27, 200, 236, 68, 112, 57, 42, 80, 74, 102,
                        90, 79, 37, 51,
                    ],
                    [
                        175, 114, 135, 166, 203, 32, 6, 33, 46, 176, 86, 99, 15, 56, 198, 205, 188,
                        249, 141, 43,
                    ],
                    [
                        78, 144, 223, 10, 47, 19, 239, 16, 210, 7, 198, 177, 233, 114, 115, 220,
                        34, 45, 164, 225,
                    ],
                    [
                        66, 14, 135, 98, 175, 160, 108, 249, 42, 39, 199, 154, 21, 186, 227, 65,
                        78, 76, 75, 241,
                    ],
                    [
                        204, 188, 129, 18, 131, 1, 57, 63, 233, 104, 252, 84, 56, 55, 64, 20, 0,
                        222, 0, 93,
                    ],
                    [
                        117, 249, 157, 60, 33, 169, 61, 202, 115, 148, 212, 111, 157, 241, 80, 235,
                        228, 224, 43, 68,
                    ],
                    [
                        151, 83, 21, 88, 116, 98, 251, 46, 183, 228, 110, 214, 122, 171, 85, 250,
                        159, 31, 242, 57,
                    ],
                    [
                        254, 141, 170, 24, 19, 214, 119, 61, 65, 53, 72, 174, 223, 172, 110, 117,
                        169, 103, 197, 16,
                    ],
                    [
                        253, 197, 27, 164, 223, 46, 227, 86, 203, 115, 9, 90, 216, 134, 203, 134,
                        126, 62, 114, 110,
                    ],
                    [
                        93, 62, 21, 9, 237, 45, 219, 83, 172, 229, 190, 86, 41, 237, 30, 46, 198,
                        207, 123, 56,
                    ],
                    [
                        181, 42, 177, 114, 173, 4, 239, 43, 95, 42, 125, 33, 11, 168, 192, 252,
                        148, 241, 23, 121,
                    ],
                    [
                        163, 164, 34, 97, 202, 10, 19, 21, 16, 15, 4, 32, 152, 79, 248, 100, 223,
                        184, 150, 15,
                    ],
                    [
                        76, 176, 85, 132, 36, 125, 50, 182, 203, 177, 193, 175, 113, 188, 15, 106,
                        113, 125, 86, 12,
                    ],
                    [
                        54, 11, 142, 117, 206, 203, 96, 105, 237, 1, 19, 114, 17, 140, 85, 134, 79,
                        162, 73, 59,
                    ],
                    [
                        193, 68, 72, 149, 230, 201, 39, 29, 250, 173, 103, 83, 36, 6, 204, 206,
                        149, 70, 34, 60,
                    ],
                    [
                        121, 103, 251, 51, 10, 59, 205, 182, 158, 48, 58, 138, 242, 146, 179, 166,
                        34, 231, 57, 44,
                    ],
                    [
                        225, 194, 185, 129, 191, 46, 26, 253, 98, 139, 1, 178, 10, 116, 15, 192,
                        232, 38, 89, 98,
                    ],
                    [
                        170, 199, 76, 243, 177, 164, 141, 136, 93, 54, 48, 42, 240, 234, 243, 171,
                        12, 111, 100, 107,
                    ],
                    [
                        219, 115, 175, 86, 186, 250, 248, 240, 233, 246, 191, 178, 153, 152, 26,
                        105, 220, 122, 100, 166,
                    ],
                    [
                        232, 20, 98, 34, 10, 17, 55, 231, 89, 194, 81, 236, 167, 120, 180, 45, 213,
                        62, 168, 185,
                    ],
                    [
                        128, 52, 1, 93, 31, 198, 58, 144, 186, 34, 171, 109, 4, 130, 37, 37, 233,
                        21, 110, 198,
                    ],
                    [
                        111, 165, 31, 119, 145, 193, 17, 140, 148, 78, 35, 103, 19, 92, 98, 75,
                        239, 48, 31, 148,
                    ],
                    [
                        64, 127, 83, 69, 40, 65, 33, 219, 92, 74, 133, 58, 5, 81, 39, 244, 91, 8,
                        12, 104,
                    ],
                    [
                        109, 156, 238, 189, 50, 32, 48, 234, 8, 191, 47, 182, 220, 7, 180, 33, 32,
                        170, 233, 80,
                    ],
                    [
                        22, 84, 203, 199, 202, 221, 240, 93, 179, 104, 233, 45, 27, 56, 5, 57, 212,
                        200, 192, 115,
                    ],
                    [
                        53, 170, 157, 3, 173, 208, 102, 129, 129, 174, 192, 217, 17, 188, 11, 212,
                        164, 125, 225, 80,
                    ],
                    [
                        21, 226, 197, 69, 255, 241, 82, 93, 79, 99, 104, 251, 251, 143, 118, 14,
                        25, 203, 114, 124,
                    ],
                    [
                        137, 39, 86, 194, 8, 153, 2, 117, 31, 76, 253, 1, 48, 37, 225, 199, 10, 2,
                        4, 102,
                    ],
                    [
                        178, 215, 180, 219, 55, 10, 27, 50, 62, 38, 131, 97, 95, 141, 105, 57, 110,
                        184, 174, 147,
                    ],
                    [
                        152, 134, 110, 120, 163, 167, 112, 122, 41, 84, 196, 194, 117, 86, 221,
                        222, 147, 101, 191, 90,
                    ],
                    [
                        127, 29, 115, 99, 207, 58, 101, 20, 206, 208, 96, 215, 38, 165, 39, 100,
                        156, 166, 205, 196,
                    ],
                    [
                        216, 102, 116, 117, 119, 189, 236, 136, 225, 21, 137, 73, 23, 129, 161,
                        103, 113, 6, 36, 4,
                    ],
                    [
                        127, 160, 160, 158, 237, 54, 188, 166, 49, 74, 10, 187, 34, 110, 150, 248,
                        180, 33, 146, 85,
                    ],
                    [
                        236, 221, 5, 53, 185, 62, 190, 186, 103, 72, 68, 202, 178, 52, 40, 84, 165,
                        59, 51, 121,
                    ],
                    [
                        106, 197, 55, 69, 53, 27, 75, 7, 5, 160, 8, 161, 12, 161, 188, 100, 237,
                        220, 105, 101,
                    ],
                    [
                        26, 11, 124, 176, 131, 217, 69, 193, 201, 179, 130, 215, 26, 135, 232, 0,
                        183, 152, 186, 132,
                    ],
                    [
                        196, 239, 250, 216, 234, 227, 119, 84, 199, 187, 84, 204, 70, 203, 125,
                        224, 122, 150, 240, 5,
                    ],
                    [
                        33, 183, 155, 11, 53, 236, 178, 163, 75, 134, 208, 186, 136, 28, 1, 144,
                        62, 47, 227, 235,
                    ],
                    [
                        11, 236, 88, 199, 121, 109, 78, 198, 0, 250, 5, 147, 216, 205, 228, 83,
                        189, 141, 144, 59,
                    ],
                    [
                        7, 187, 181, 26, 55, 77, 101, 108, 139, 57, 132, 246, 162, 132, 151, 38,
                        173, 189, 79, 134,
                    ],
                    [
                        172, 52, 196, 213, 175, 56, 35, 28, 175, 118, 122, 77, 153, 169, 112, 248,
                        80, 157, 133, 83,
                    ],
                    [
                        138, 75, 169, 71, 206, 232, 146, 7, 19, 127, 65, 52, 1, 232, 59, 202, 214,
                        117, 236, 127,
                    ],
                    [
                        180, 152, 73, 55, 145, 79, 4, 139, 144, 138, 102, 146, 37, 142, 59, 59, 79,
                        165, 227, 133,
                    ],
                    [
                        100, 104, 60, 60, 109, 78, 62, 97, 196, 46, 183, 222, 193, 254, 177, 220,
                        229, 39, 9, 22,
                    ],
                    [
                        241, 90, 83, 96, 65, 126, 194, 43, 141, 139, 75, 237, 159, 49, 10, 120,
                        240, 188, 155, 58,
                    ],
                    [
                        31, 135, 135, 98, 217, 250, 148, 203, 10, 60, 44, 167, 12, 206, 148, 32,
                        41, 253, 139, 141,
                    ],
                    [
                        154, 19, 103, 38, 145, 162, 181, 167, 226, 220, 13, 188, 245, 59, 94, 68,
                        28, 90, 4, 98,
                    ],
                    [
                        60, 250, 28, 231, 133, 122, 80, 229, 122, 86, 175, 199, 192, 80, 36, 118,
                        74, 162, 28, 240,
                    ],
                    [
                        150, 35, 168, 156, 191, 84, 179, 136, 8, 13, 63, 143, 77, 121, 25, 223,
                        204, 107, 217, 122,
                    ],
                    [
                        6, 215, 22, 154, 71, 172, 132, 239, 54, 197, 159, 83, 34, 179, 40, 253,
                        191, 94, 62, 167,
                    ],
                    [
                        72, 159, 192, 68, 154, 21, 186, 209, 12, 104, 34, 113, 221, 57, 127, 63,
                        80, 42, 166, 152,
                    ],
                    [
                        105, 201, 247, 167, 179, 23, 252, 169, 211, 33, 181, 193, 175, 229, 175,
                        121, 200, 172, 121, 175,
                    ],
                    [
                        186, 151, 39, 115, 120, 63, 224, 11, 228, 52, 200, 145, 220, 25, 100, 188,
                        192, 171, 246, 218,
                    ],
                    [
                        207, 18, 80, 244, 227, 100, 112, 209, 24, 150, 90, 172, 76, 172, 248, 139,
                        176, 40, 36, 65,
                    ],
                    [
                        39, 142, 25, 202, 110, 217, 227, 104, 164, 40, 67, 2, 62, 69, 119, 58, 2,
                        43, 216, 54,
                    ],
                    [
                        115, 167, 131, 216, 205, 174, 167, 97, 153, 187, 96, 190, 160, 21, 135,
                        247, 219, 47, 145, 116,
                    ],
                    [
                        243, 151, 92, 159, 96, 135, 75, 19, 43, 131, 225, 50, 178, 50, 198, 8, 181,
                        242, 86, 39,
                    ],
                    [
                        114, 144, 99, 96, 138, 196, 113, 98, 88, 14, 195, 214, 199, 195, 170, 22,
                        126, 208, 65, 26,
                    ],
                    [
                        138, 128, 192, 18, 66, 89, 171, 63, 230, 201, 235, 52, 64, 254, 192, 70,
                        150, 72, 47, 226,
                    ],
                    [
                        193, 89, 55, 100, 59, 102, 122, 135, 86, 177, 227, 7, 148, 237, 108, 114,
                        156, 74, 196, 248,
                    ],
                    [
                        205, 221, 28, 99, 153, 240, 50, 159, 106, 109, 70, 128, 54, 105, 152, 208,
                        22, 207, 190, 237,
                    ],
                    [
                        65, 239, 56, 189, 200, 78, 45, 144, 34, 170, 80, 171, 214, 52, 11, 99, 35,
                        250, 104, 183,
                    ],
                    [
                        39, 81, 231, 43, 190, 194, 8, 16, 189, 0, 138, 62, 251, 39, 193, 152, 104,
                        200, 38, 45,
                    ],
                    [
                        34, 252, 56, 189, 188, 204, 45, 125, 182, 34, 148, 150, 76, 225, 60, 220,
                        182, 173, 30, 9,
                    ],
                    [
                        65, 135, 183, 235, 26, 105, 72, 174, 118, 187, 83, 241, 9, 11, 14, 154,
                        201, 239, 15, 234,
                    ],
                    [
                        205, 229, 43, 137, 255, 31, 139, 103, 176, 12, 4, 85, 196, 117, 211, 193,
                        239, 96, 19, 53,
                    ],
                    [
                        10, 247, 236, 239, 208, 2, 15, 137, 105, 102, 25, 40, 49, 114, 133, 174,
                        30, 106, 153, 42,
                    ],
                    [
                        11, 107, 154, 202, 255, 225, 234, 178, 67, 114, 20, 189, 58, 27, 237, 120,
                        167, 5, 86, 67,
                    ],
                    [
                        7, 178, 195, 96, 34, 118, 186, 93, 68, 127, 221, 219, 23, 69, 142, 79, 39,
                        151, 22, 180,
                    ],
                    [
                        108, 30, 178, 46, 184, 216, 158, 146, 56, 125, 225, 21, 84, 9, 58, 88, 196,
                        1, 253, 23,
                    ],
                    [
                        70, 22, 197, 228, 121, 171, 182, 250, 215, 32, 191, 244, 75, 116, 13, 222,
                        73, 145, 105, 222,
                    ],
                    [
                        177, 82, 82, 39, 167, 28, 33, 49, 112, 218, 145, 180, 89, 73, 241, 151, 63,
                        193, 89, 106,
                    ],
                    [
                        147, 254, 155, 229, 186, 191, 167, 190, 253, 117, 44, 143, 33, 178, 58,
                        219, 6, 39, 148, 238,
                    ],
                    [
                        234, 24, 248, 95, 75, 121, 155, 58, 15, 152, 156, 248, 29, 133, 125, 31, 8,
                        156, 159, 87,
                    ],
                    [
                        239, 82, 87, 75, 67, 67, 28, 75, 235, 203, 174, 181, 76, 204, 22, 238, 37,
                        109, 33, 23,
                    ],
                    [
                        224, 70, 54, 60, 20, 43, 241, 64, 36, 141, 138, 38, 252, 134, 171, 97, 115,
                        154, 66, 236,
                    ],
                    [
                        215, 198, 26, 210, 197, 97, 199, 96, 79, 158, 240, 40, 241, 143, 177, 125,
                        78, 134, 186, 225,
                    ],
                    [
                        39, 125, 20, 239, 22, 228, 51, 241, 241, 20, 222, 85, 190, 141, 248, 80, 4,
                        202, 72, 179,
                    ],
                    [
                        37, 217, 82, 231, 156, 15, 62, 132, 119, 68, 146, 43, 254, 34, 180, 48, 24,
                        34, 53, 183,
                    ],
                    [
                        133, 34, 20, 56, 240, 62, 234, 249, 102, 38, 67, 239, 60, 141, 141, 88,
                        192, 120, 62, 14,
                    ],
                    [
                        199, 161, 91, 223, 124, 215, 197, 131, 16, 59, 18, 83, 96, 248, 128, 167,
                        191, 108, 168, 43,
                    ],
                    [
                        21, 222, 47, 96, 62, 125, 11, 98, 74, 130, 135, 130, 3, 249, 232, 215, 112,
                        187, 49, 175,
                    ],
                    [
                        227, 237, 98, 195, 203, 19, 234, 216, 155, 99, 33, 146, 239, 44, 67, 63,
                        248, 250, 222, 91,
                    ],
                    [
                        25, 164, 236, 43, 106, 252, 52, 4, 91, 241, 16, 218, 192, 195, 128, 229,
                        73, 233, 107, 253,
                    ],
                    [
                        228, 195, 175, 233, 93, 33, 117, 24, 171, 150, 106, 108, 201, 148, 96, 135,
                        44, 146, 175, 157,
                    ],
                    [
                        90, 237, 187, 122, 0, 2, 70, 38, 221, 64, 20, 76, 119, 168, 90, 100, 28,
                        169, 133, 167,
                    ],
                    [
                        155, 15, 73, 119, 148, 31, 253, 6, 219, 229, 173, 125, 121, 140, 73, 253,
                        120, 105, 2, 255,
                    ],
                    [
                        50, 65, 122, 237, 205, 50, 67, 138, 233, 226, 212, 207, 44, 253, 243, 165,
                        2, 28, 6, 7,
                    ],
                    [
                        103, 135, 37, 103, 107, 189, 193, 103, 190, 155, 189, 241, 88, 160, 117,
                        156, 119, 115, 78, 3,
                    ],
                    [
                        53, 44, 205, 153, 222, 231, 20, 143, 102, 194, 39, 142, 169, 239, 104, 51,
                        184, 46, 24, 187,
                    ],
                    [
                        229, 19, 228, 56, 198, 23, 6, 123, 174, 85, 231, 105, 27, 235, 125, 154,
                        147, 85, 20, 243,
                    ],
                    [
                        191, 230, 240, 72, 209, 225, 155, 16, 221, 23, 14, 236, 216, 119, 74, 118,
                        28, 13, 12, 125,
                    ],
                    [
                        238, 226, 203, 54, 20, 211, 224, 5, 203, 158, 25, 47, 172, 27, 143, 30, 1,
                        223, 248, 3,
                    ],
                    [
                        24, 48, 230, 59, 231, 116, 34, 101, 191, 200, 251, 149, 118, 25, 32, 59,
                        82, 170, 196, 230,
                    ],
                    [
                        44, 203, 15, 227, 45, 241, 166, 18, 85, 100, 164, 149, 191, 117, 185, 241,
                        62, 62, 188, 233,
                    ],
                    [
                        176, 213, 145, 10, 95, 24, 136, 119, 75, 83, 216, 140, 70, 28, 254, 215,
                        251, 34, 62, 77,
                    ],
                    [
                        36, 96, 155, 172, 86, 187, 176, 47, 160, 59, 238, 139, 154, 61, 135, 54,
                        245, 139, 224, 106,
                    ],
                    [
                        38, 244, 198, 255, 38, 129, 61, 38, 39, 166, 13, 14, 104, 168, 3, 214, 18,
                        82, 93, 233,
                    ],
                    [
                        3, 51, 207, 139, 41, 147, 92, 80, 10, 61, 110, 51, 110, 118, 129, 235, 159,
                        121, 209, 14,
                    ],
                    [
                        14, 191, 19, 60, 3, 221, 112, 26, 62, 196, 66, 45, 186, 192, 241, 188, 128,
                        170, 171, 148,
                    ],
                    [
                        30, 121, 3, 49, 148, 88, 142, 151, 168, 170, 54, 152, 127, 51, 95, 226,
                        129, 165, 53, 117,
                    ],
                    [
                        147, 20, 203, 121, 4, 116, 231, 74, 221, 6, 73, 155, 8, 217, 229, 99, 102,
                        6, 110, 202,
                    ],
                    [
                        171, 76, 59, 61, 251, 190, 86, 100, 150, 235, 185, 62, 155, 12, 172, 77,
                        142, 199, 104, 187,
                    ],
                    [
                        245, 157, 186, 188, 6, 110, 180, 22, 202, 128, 86, 140, 66, 69, 187, 140,
                        138, 8, 223, 187,
                    ],
                    [
                        178, 105, 83, 140, 161, 110, 146, 90, 66, 180, 79, 224, 149, 36, 210, 125,
                        88, 91, 113, 71,
                    ],
                    [
                        105, 247, 218, 9, 116, 238, 12, 64, 174, 52, 27, 172, 238, 208, 96, 114,
                        217, 82, 42, 204,
                    ],
                    [
                        198, 68, 181, 94, 237, 155, 228, 224, 193, 49, 66, 130, 112, 23, 159, 88,
                        63, 141, 219, 168,
                    ],
                    [
                        166, 204, 21, 50, 242, 246, 109, 211, 23, 89, 130, 9, 123, 53, 217, 155,
                        194, 186, 52, 196,
                    ],
                    [
                        38, 251, 163, 205, 255, 20, 13, 174, 218, 102, 121, 150, 173, 165, 70, 183,
                        100, 38, 105, 191,
                    ],
                    [
                        127, 224, 224, 182, 53, 185, 5, 232, 232, 52, 138, 47, 3, 88, 49, 180, 251,
                        78, 155, 212,
                    ],
                    [
                        29, 83, 182, 170, 227, 148, 81, 9, 109, 252, 12, 145, 65, 225, 179, 38,
                        139, 5, 115, 230,
                    ],
                    [
                        241, 192, 57, 2, 183, 180, 93, 4, 166, 199, 193, 186, 87, 90, 130, 97, 10,
                        224, 98, 53,
                    ],
                    [
                        205, 17, 93, 84, 70, 156, 14, 65, 80, 32, 129, 108, 0, 217, 239, 23, 224,
                        68, 179, 196,
                    ],
                    [
                        165, 218, 138, 166, 48, 108, 238, 45, 230, 153, 14, 225, 140, 58, 191, 177,
                        206, 87, 147, 109,
                    ],
                    [
                        122, 138, 68, 181, 109, 63, 235, 158, 160, 78, 98, 41, 68, 146, 213, 255,
                        36, 213, 196, 0,
                    ],
                    [
                        118, 118, 217, 232, 51, 168, 49, 65, 66, 224, 160, 209, 71, 19, 36, 217,
                        132, 169, 80, 93,
                    ],
                    [
                        221, 139, 179, 119, 187, 151, 79, 188, 71, 31, 98, 136, 242, 192, 60, 113,
                        247, 35, 45, 68,
                    ],
                    [
                        56, 1, 99, 69, 85, 171, 12, 205, 75, 1, 243, 96, 13, 178, 231, 33, 126,
                        170, 39, 109,
                    ],
                    [
                        198, 61, 219, 43, 204, 190, 5, 2, 99, 23, 237, 68, 251, 203, 100, 232, 50,
                        125, 216, 150,
                    ],
                    [
                        58, 49, 14, 33, 174, 21, 54, 71, 139, 171, 64, 24, 176, 151, 195, 218, 25,
                        149, 220, 187,
                    ],
                    [
                        77, 168, 4, 184, 133, 245, 47, 0, 136, 96, 172, 114, 239, 246, 10, 186,
                        191, 120, 194, 81,
                    ],
                    [
                        152, 125, 77, 156, 212, 78, 225, 226, 145, 226, 17, 14, 42, 142, 242, 59,
                        242, 97, 35, 204,
                    ],
                    [
                        252, 140, 200, 27, 58, 152, 172, 159, 91, 26, 85, 124, 65, 29, 108, 27,
                        241, 35, 202, 252,
                    ],
                    [
                        140, 35, 209, 42, 116, 211, 88, 1, 255, 1, 16, 5, 34, 177, 207, 233, 219,
                        207, 131, 235,
                    ],
                    [
                        186, 222, 53, 165, 88, 230, 151, 229, 79, 190, 86, 212, 193, 77, 100, 53,
                        181, 225, 173, 141,
                    ],
                    [
                        155, 145, 48, 168, 111, 31, 131, 73, 51, 215, 147, 188, 69, 93, 255, 53,
                        157, 134, 21, 18,
                    ],
                    [
                        50, 110, 105, 84, 60, 107, 136, 151, 3, 232, 167, 126, 215, 105, 131, 81,
                        46, 184, 17, 188,
                    ],
                    [
                        17, 223, 139, 95, 253, 179, 66, 182, 187, 123, 154, 53, 175, 206, 231, 170,
                        147, 181, 116, 33,
                    ],
                    [
                        114, 241, 11, 41, 244, 153, 247, 239, 60, 86, 222, 117, 66, 250, 121, 75,
                        91, 187, 51, 131,
                    ],
                    [
                        155, 241, 152, 84, 95, 16, 189, 37, 197, 0, 232, 113, 78, 54, 56, 27, 103,
                        113, 107, 170,
                    ],
                    [
                        193, 58, 106, 70, 13, 74, 182, 6, 90, 119, 226, 121, 245, 127, 204, 5, 8,
                        142, 83, 214,
                    ],
                    [
                        3, 176, 42, 241, 11, 66, 44, 60, 97, 15, 77, 53, 198, 75, 79, 116, 250, 68,
                        118, 161,
                    ],
                    [
                        99, 183, 206, 188, 234, 186, 190, 44, 218, 110, 221, 178, 241, 95, 143, 96,
                        156, 230, 68, 90,
                    ],
                    [
                        228, 140, 117, 149, 244, 40, 34, 61, 37, 228, 234, 125, 24, 198, 103, 135,
                        157, 199, 181, 185,
                    ],
                    [
                        48, 173, 7, 5, 36, 236, 172, 241, 186, 47, 161, 35, 154, 56, 120, 88, 11,
                        36, 89, 76,
                    ],
                    [
                        40, 81, 215, 223, 29, 88, 19, 153, 236, 251, 250, 51, 47, 244, 49, 48, 74,
                        175, 31, 237,
                    ],
                    [
                        165, 97, 226, 128, 120, 66, 178, 172, 246, 64, 51, 247, 179, 199, 241, 110,
                        205, 129, 186, 184,
                    ],
                    [
                        154, 99, 54, 202, 237, 85, 168, 104, 94, 114, 208, 210, 63, 182, 139, 245,
                        4, 72, 217, 14,
                    ],
                    [
                        182, 200, 108, 97, 156, 76, 156, 204, 46, 236, 186, 80, 95, 174, 22, 123,
                        3, 11, 43, 43,
                    ],
                    [
                        227, 35, 42, 138, 226, 227, 33, 238, 177, 71, 90, 119, 80, 233, 249, 98,
                        245, 170, 0, 19,
                    ],
                    [
                        49, 230, 123, 173, 64, 185, 194, 105, 51, 44, 44, 211, 127, 185, 165, 250,
                        233, 109, 15, 210,
                    ],
                    [
                        130, 13, 205, 8, 16, 157, 238, 115, 255, 58, 61, 32, 22, 43, 174, 149, 206,
                        17, 207, 239,
                    ],
                    [
                        210, 125, 109, 17, 39, 74, 53, 120, 241, 163, 164, 157, 138, 228, 228, 171,
                        102, 120, 145, 119,
                    ],
                    [
                        160, 240, 201, 107, 24, 99, 92, 111, 16, 195, 194, 229, 175, 92, 210, 172,
                        240, 168, 111, 215,
                    ],
                    [
                        118, 14, 49, 225, 75, 243, 164, 217, 50, 86, 57, 141, 162, 138, 126, 214,
                        5, 47, 55, 55,
                    ],
                    [
                        76, 193, 198, 202, 244, 106, 123, 241, 179, 152, 4, 107, 101, 235, 81, 44,
                        168, 70, 135, 151,
                    ],
                    [
                        161, 27, 237, 3, 194, 192, 221, 153, 214, 29, 149, 119, 126, 85, 59, 195,
                        214, 25, 108, 98,
                    ],
                    [
                        204, 207, 179, 0, 197, 63, 172, 241, 240, 10, 113, 35, 80, 248, 160, 20,
                        57, 196, 15, 155,
                    ],
                    [
                        146, 125, 103, 182, 126, 70, 193, 59, 77, 96, 124, 150, 122, 230, 27, 2,
                        183, 162, 30, 95,
                    ],
                    [
                        221, 175, 53, 207, 107, 246, 223, 9, 29, 200, 90, 170, 163, 183, 249, 61,
                        229, 43, 10, 94,
                    ],
                    [
                        143, 51, 239, 38, 55, 171, 34, 56, 94, 176, 87, 52, 141, 186, 161, 177, 46,
                        86, 59, 29,
                    ],
                    [
                        249, 230, 165, 1, 143, 178, 217, 45, 160, 12, 182, 103, 8, 180, 246, 47,
                        11, 31, 221, 246,
                    ],
                    [
                        200, 124, 16, 160, 181, 167, 241, 190, 111, 194, 184, 109, 166, 225, 4, 28,
                        221, 146, 250, 11,
                    ],
                    [
                        112, 46, 242, 137, 0, 202, 115, 39, 148, 108, 226, 218, 70, 205, 121, 173,
                        52, 123, 68, 122,
                    ],
                    [
                        163, 175, 22, 180, 129, 188, 180, 211, 98, 200, 135, 25, 99, 73, 175, 92,
                        123, 231, 219, 128,
                    ],
                    [
                        192, 215, 190, 107, 160, 201, 244, 169, 218, 107, 114, 12, 13, 220, 151,
                        126, 26, 145, 237, 130,
                    ],
                    [
                        97, 199, 99, 140, 215, 95, 236, 99, 43, 86, 59, 169, 167, 190, 223, 243,
                        173, 78, 0, 192,
                    ],
                    [
                        24, 173, 48, 207, 253, 208, 162, 125, 26, 93, 144, 244, 34, 52, 6, 186,
                        102, 166, 92, 218,
                    ],
                    [
                        67, 28, 235, 35, 225, 77, 177, 80, 9, 250, 91, 78, 181, 81, 201, 21, 246,
                        19, 54, 223,
                    ],
                    [
                        149, 134, 1, 156, 207, 55, 192, 188, 181, 90, 148, 118, 217, 15, 128, 255,
                        54, 230, 39, 161,
                    ],
                    [
                        193, 23, 11, 32, 92, 30, 221, 69, 70, 21, 209, 142, 129, 100, 27, 6, 13,
                        229, 211, 13,
                    ],
                    [
                        80, 239, 197, 55, 32, 1, 84, 177, 225, 14, 30, 70, 113, 162, 254, 195, 201,
                        240, 168, 229,
                    ],
                    [
                        218, 222, 67, 183, 121, 243, 22, 51, 12, 209, 165, 233, 8, 122, 160, 69,
                        201, 11, 215, 21,
                    ],
                    [
                        89, 215, 2, 21, 120, 210, 23, 94, 16, 73, 30, 242, 75, 70, 175, 195, 252,
                        97, 145, 171,
                    ],
                    [
                        242, 157, 50, 223, 4, 130, 173, 48, 162, 250, 255, 185, 4, 255, 80, 5, 74,
                        207, 253, 81,
                    ],
                    [
                        178, 173, 112, 38, 250, 238, 6, 135, 7, 77, 143, 108, 31, 204, 106, 98, 75,
                        109, 15, 17,
                    ],
                    [
                        13, 54, 4, 189, 185, 166, 246, 51, 235, 35, 71, 171, 104, 181, 251, 25, 86,
                        70, 160, 114,
                    ],
                    [
                        31, 238, 149, 255, 6, 187, 100, 16, 123, 159, 135, 109, 214, 237, 148, 241,
                        67, 25, 118, 187,
                    ],
                    [
                        114, 69, 33, 29, 186, 3, 90, 14, 157, 162, 176, 136, 118, 147, 148, 68,
                        145, 102, 134, 192,
                    ],
                    [
                        210, 249, 199, 174, 0, 76, 254, 77, 208, 135, 51, 221, 228, 215, 97, 136,
                        106, 193, 192, 242,
                    ],
                    [
                        57, 133, 210, 50, 254, 74, 60, 1, 115, 18, 146, 33, 251, 17, 168, 180, 69,
                        222, 46, 17,
                    ],
                    [
                        132, 15, 54, 205, 71, 30, 109, 99, 128, 47, 104, 53, 37, 70, 60, 225, 13,
                        38, 33, 168,
                    ],
                    [
                        221, 66, 176, 63, 169, 249, 142, 19, 184, 157, 14, 157, 255, 72, 132, 73,
                        127, 205, 18, 103,
                    ],
                    [
                        137, 126, 164, 39, 227, 154, 254, 22, 174, 95, 44, 27, 213, 143, 140, 7,
                        151, 82, 30, 70,
                    ],
                    [
                        173, 35, 89, 101, 61, 4, 36, 221, 225, 215, 179, 210, 212, 52, 107, 241,
                        245, 41, 239, 202,
                    ],
                    [
                        183, 249, 175, 158, 78, 118, 156, 64, 132, 86, 65, 115, 31, 122, 19, 60,
                        158, 184, 163, 83,
                    ],
                    [
                        121, 255, 65, 45, 155, 100, 192, 178, 144, 52, 228, 217, 86, 186, 167, 15,
                        111, 70, 225, 23,
                    ],
                    [
                        216, 16, 224, 68, 54, 16, 152, 70, 63, 194, 207, 195, 97, 232, 226, 161,
                        123, 248, 247, 59,
                    ],
                    [
                        32, 114, 114, 99, 145, 251, 206, 48, 9, 185, 24, 233, 237, 195, 130, 200,
                        99, 107, 94, 155,
                    ],
                    [
                        105, 252, 139, 158, 45, 78, 163, 16, 69, 228, 168, 147, 189, 94, 150, 85,
                        218, 190, 190, 228,
                    ],
                    [
                        32, 204, 164, 50, 191, 119, 124, 178, 217, 155, 109, 169, 70, 208, 218, 95,
                        37, 194, 241, 206,
                    ],
                    [
                        170, 14, 37, 162, 150, 42, 88, 251, 232, 52, 132, 88, 250, 27, 142, 42,
                        245, 115, 137, 89,
                    ],
                    [
                        175, 228, 85, 178, 141, 68, 100, 234, 4, 174, 228, 18, 170, 68, 98, 237,
                        89, 207, 134, 201,
                    ],
                    [
                        64, 201, 245, 248, 63, 19, 213, 14, 142, 118, 148, 67, 46, 90, 239, 54,
                        125, 148, 141, 139,
                    ],
                    [
                        53, 101, 136, 116, 75, 137, 165, 217, 104, 15, 245, 196, 76, 3, 18, 142,
                        210, 213, 39, 38,
                    ],
                    [
                        114, 83, 51, 161, 66, 6, 205, 59, 96, 123, 115, 136, 9, 197, 224, 193, 94,
                        52, 239, 22,
                    ],
                    [
                        209, 7, 118, 181, 18, 118, 7, 184, 140, 180, 119, 195, 97, 22, 82, 64, 191,
                        252, 103, 188,
                    ],
                    [
                        33, 84, 209, 30, 176, 128, 14, 25, 93, 30, 111, 44, 4, 180, 243, 96, 2,
                        238, 228, 33,
                    ],
                    [
                        105, 162, 164, 31, 225, 50, 9, 64, 220, 137, 80, 15, 130, 153, 67, 100, 76,
                        26, 174, 232,
                    ],
                    [
                        51, 151, 65, 56, 84, 167, 127, 202, 93, 164, 201, 165, 16, 224, 118, 15,
                        116, 9, 115, 174,
                    ],
                    [
                        77, 228, 161, 165, 167, 69, 132, 75, 180, 200, 124, 138, 108, 11, 22, 213,
                        189, 47, 198, 237,
                    ],
                    [
                        39, 218, 2, 73, 1, 96, 121, 180, 65, 226, 86, 190, 250, 223, 243, 8, 40,
                        30, 110, 236,
                    ],
                    [
                        144, 38, 91, 110, 162, 56, 130, 5, 123, 235, 255, 97, 109, 200, 226, 188,
                        16, 46, 167, 176,
                    ],
                    [
                        227, 178, 155, 18, 38, 6, 27, 120, 245, 103, 53, 253, 221, 233, 79, 202,
                        57, 113, 207, 71,
                    ],
                    [
                        203, 129, 178, 145, 113, 152, 162, 19, 165, 36, 190, 60, 137, 231, 103,
                        149, 186, 135, 120, 185,
                    ],
                    [
                        246, 107, 156, 162, 239, 43, 123, 29, 41, 182, 108, 139, 159, 190, 250,
                        135, 108, 176, 248, 53,
                    ],
                    [
                        23, 227, 115, 126, 180, 54, 250, 142, 213, 74, 19, 222, 248, 9, 138, 129,
                        131, 234, 74, 232,
                    ],
                    [
                        113, 10, 7, 131, 85, 206, 85, 18, 22, 112, 160, 83, 239, 24, 71, 169, 203,
                        119, 18, 132,
                    ],
                    [
                        189, 151, 51, 202, 212, 61, 31, 128, 110, 21, 5, 136, 181, 72, 172, 233,
                        22, 49, 33, 97,
                    ],
                    [
                        23, 151, 0, 10, 254, 249, 6, 51, 179, 175, 189, 139, 146, 89, 208, 203,
                        173, 29, 217, 170,
                    ],
                    [
                        95, 52, 52, 64, 88, 109, 39, 128, 9, 189, 165, 151, 183, 219, 243, 211,
                        181, 245, 20, 127,
                    ],
                    [
                        24, 227, 194, 223, 174, 149, 177, 134, 2, 172, 55, 35, 9, 100, 5, 187, 147,
                        171, 59, 164,
                    ],
                    [
                        232, 84, 163, 118, 65, 209, 94, 90, 185, 192, 196, 155, 105, 171, 43, 36,
                        174, 7, 67, 137,
                    ],
                    [
                        224, 2, 120, 164, 20, 214, 245, 36, 35, 150, 161, 29, 226, 54, 7, 247, 240,
                        255, 62, 29,
                    ],
                    [
                        32, 225, 48, 195, 88, 139, 2, 173, 114, 54, 47, 94, 144, 10, 54, 86, 8, 40,
                        207, 249,
                    ],
                    [
                        146, 152, 69, 12, 145, 60, 205, 224, 207, 65, 186, 147, 65, 199, 20, 185,
                        82, 128, 178, 121,
                    ],
                    [
                        180, 35, 151, 23, 178, 215, 99, 218, 43, 57, 12, 61, 78, 181, 251, 194, 77,
                        44, 51, 56,
                    ],
                    [
                        117, 161, 185, 182, 211, 101, 108, 215, 6, 33, 98, 232, 147, 210, 174, 173,
                        15, 139, 107, 145,
                    ],
                    [
                        187, 46, 6, 110, 170, 172, 52, 79, 208, 231, 176, 137, 189, 106, 193, 236,
                        105, 118, 87, 230,
                    ],
                    [
                        252, 142, 21, 106, 115, 216, 211, 247, 36, 70, 118, 88, 8, 211, 49, 6, 139,
                        43, 100, 12,
                    ],
                    [
                        107, 18, 251, 127, 182, 91, 189, 215, 109, 217, 129, 62, 87, 142, 13, 103,
                        170, 162, 29, 5,
                    ],
                    [
                        115, 206, 39, 208, 155, 120, 60, 43, 85, 65, 42, 244, 36, 129, 124, 155,
                        177, 119, 184, 190,
                    ],
                    [
                        60, 119, 193, 121, 197, 147, 246, 71, 186, 42, 118, 10, 103, 212, 86, 121,
                        195, 34, 126, 178,
                    ],
                    [
                        159, 1, 100, 185, 130, 57, 18, 116, 166, 77, 213, 208, 132, 97, 62, 128,
                        89, 48, 166, 216,
                    ],
                    [
                        8, 155, 202, 165, 102, 26, 47, 122, 216, 221, 29, 166, 235, 123, 68, 1, 18,
                        16, 146, 18,
                    ],
                    [
                        60, 137, 162, 242, 254, 178, 245, 204, 23, 108, 212, 208, 19, 128, 110,
                        180, 39, 197, 71, 96,
                    ],
                    [
                        200, 13, 77, 132, 203, 122, 140, 7, 189, 60, 162, 54, 196, 36, 241, 0, 96,
                        103, 128, 100,
                    ],
                    [
                        165, 29, 41, 14, 50, 110, 205, 94, 185, 63, 191, 253, 253, 127, 35, 253,
                        226, 251, 190, 27,
                    ],
                    [
                        207, 187, 242, 99, 138, 5, 19, 72, 221, 247, 87, 62, 245, 122, 1, 138, 251,
                        192, 16, 137,
                    ],
                    [
                        111, 31, 205, 167, 52, 237, 177, 25, 100, 107, 24, 138, 148, 35, 79, 228,
                        31, 120, 195, 105,
                    ],
                    [
                        227, 50, 199, 235, 29, 123, 250, 74, 72, 242, 236, 209, 227, 160, 17, 171,
                        211, 56, 47, 67,
                    ],
                    [
                        251, 37, 189, 220, 3, 25, 180, 177, 52, 70, 209, 148, 152, 122, 158, 219,
                        225, 94, 94, 153,
                    ],
                    [
                        118, 206, 152, 151, 31, 95, 77, 208, 210, 191, 28, 74, 86, 158, 204, 116,
                        149, 68, 253, 156,
                    ],
                    [
                        123, 175, 244, 90, 102, 30, 13, 50, 37, 1, 101, 103, 140, 29, 181, 211,
                        255, 150, 126, 220,
                    ],
                    [
                        201, 136, 253, 189, 210, 184, 135, 76, 220, 123, 4, 237, 158, 248, 11, 112,
                        221, 139, 165, 130,
                    ],
                    [
                        246, 45, 38, 16, 109, 145, 36, 89, 253, 229, 122, 163, 44, 6, 128, 80, 162,
                        42, 200, 183,
                    ],
                    [
                        124, 142, 82, 194, 205, 31, 92, 85, 85, 147, 59, 144, 22, 6, 234, 223, 180,
                        248, 2, 176,
                    ],
                    [
                        70, 5, 7, 224, 142, 21, 181, 196, 7, 106, 130, 19, 83, 210, 189, 31, 90,
                        63, 167, 29,
                    ],
                    [
                        16, 71, 191, 156, 107, 139, 210, 151, 158, 198, 47, 32, 242, 232, 35, 20,
                        50, 126, 26, 47,
                    ],
                    [
                        224, 18, 16, 190, 119, 2, 118, 170, 225, 1, 142, 103, 255, 32, 192, 194,
                        29, 28, 246, 101,
                    ],
                    [
                        98, 248, 22, 215, 10, 151, 139, 206, 130, 74, 245, 108, 99, 48, 123, 244,
                        191, 180, 252, 250,
                    ],
                    [
                        120, 130, 253, 232, 89, 161, 136, 214, 133, 66, 195, 5, 25, 241, 145, 49,
                        10, 99, 111, 59,
                    ],
                    [
                        159, 49, 11, 46, 106, 30, 172, 123, 248, 7, 32, 33, 184, 108, 150, 248, 72,
                        227, 230, 245,
                    ],
                    [
                        15, 225, 76, 152, 140, 102, 36, 86, 175, 227, 194, 150, 129, 38, 40, 175,
                        230, 13, 174, 73,
                    ],
                    [
                        68, 248, 41, 161, 126, 160, 226, 107, 20, 167, 192, 67, 119, 172, 52, 140,
                        96, 145, 47, 62,
                    ],
                    [
                        253, 78, 194, 252, 170, 206, 238, 35, 117, 146, 177, 158, 233, 188, 99,
                        133, 125, 106, 9, 141,
                    ],
                    [
                        115, 103, 86, 216, 41, 100, 161, 195, 171, 65, 175, 178, 62, 174, 54, 5,
                        210, 115, 140, 157,
                    ],
                    [
                        114, 200, 163, 234, 148, 102, 164, 187, 209, 228, 59, 254, 231, 224, 37,
                        47, 216, 50, 211, 43,
                    ],
                    [
                        213, 138, 154, 96, 8, 134, 205, 102, 37, 229, 107, 81, 154, 187, 91, 97,
                        21, 134, 163, 83,
                    ],
                    [
                        55, 2, 43, 133, 15, 30, 154, 219, 150, 212, 131, 242, 54, 46, 60, 156, 199,
                        9, 206, 183,
                    ],
                    [
                        117, 79, 218, 143, 66, 15, 27, 70, 241, 61, 84, 130, 9, 49, 179, 99, 157,
                        183, 183, 230,
                    ],
                    [
                        181, 210, 28, 159, 64, 211, 50, 164, 73, 62, 43, 85, 143, 187, 66, 198,
                        102, 228, 5, 222,
                    ],
                    [
                        112, 39, 117, 85, 232, 78, 195, 7, 193, 156, 80, 71, 253, 129, 8, 20, 59,
                        183, 81, 48,
                    ],
                    [
                        150, 168, 233, 18, 69, 90, 106, 195, 137, 21, 220, 240, 227, 228, 104, 89,
                        66, 165, 215, 140,
                    ],
                    [
                        174, 108, 42, 171, 78, 26, 40, 120, 44, 88, 166, 149, 20, 210, 11, 12, 155,
                        166, 166, 125,
                    ],
                    [
                        75, 130, 13, 184, 97, 84, 183, 69, 250, 128, 13, 215, 15, 66, 196, 127,
                        192, 11, 25, 54,
                    ],
                    [
                        202, 6, 32, 106, 4, 105, 65, 152, 78, 189, 91, 241, 113, 13, 92, 252, 92,
                        154, 200, 184,
                    ],
                    [
                        158, 248, 253, 142, 86, 37, 222, 164, 121, 63, 238, 11, 48, 58, 234, 74,
                        112, 84, 204, 72,
                    ],
                    [
                        152, 100, 150, 140, 133, 84, 206, 109, 80, 131, 43, 162, 60, 27, 119, 14,
                        184, 132, 232, 19,
                    ],
                    [
                        57, 198, 35, 242, 241, 224, 250, 129, 37, 115, 185, 249, 183, 150, 17, 183,
                        107, 217, 150, 232,
                    ],
                    [
                        158, 207, 237, 6, 218, 108, 204, 124, 11, 204, 220, 18, 38, 71, 44, 137,
                        199, 143, 0, 191,
                    ],
                    [
                        210, 209, 61, 141, 233, 186, 228, 240, 35, 110, 229, 187, 178, 168, 178,
                        188, 150, 82, 164, 211,
                    ],
                    [
                        94, 219, 174, 166, 6, 117, 127, 153, 179, 194, 172, 233, 77, 3, 163, 49,
                        122, 200, 91, 208,
                    ],
                    [
                        193, 36, 140, 144, 197, 142, 59, 155, 131, 190, 244, 130, 148, 43, 251,
                        126, 196, 1, 224, 50,
                    ],
                    [
                        45, 177, 33, 83, 252, 203, 115, 37, 194, 182, 151, 58, 11, 167, 250, 107,
                        182, 167, 85, 51,
                    ],
                    [
                        198, 26, 155, 17, 86, 10, 71, 238, 42, 91, 177, 183, 74, 71, 229, 28, 244,
                        80, 210, 31,
                    ],
                    [
                        241, 198, 51, 11, 126, 187, 29, 189, 80, 228, 88, 80, 127, 143, 216, 117,
                        136, 252, 197, 181,
                    ],
                    [
                        11, 230, 92, 218, 115, 11, 45, 0, 171, 8, 177, 23, 81, 37, 169, 144, 75,
                        153, 186, 204,
                    ],
                    [
                        113, 244, 2, 86, 219, 60, 228, 121, 76, 222, 106, 146, 43, 13, 180, 28,
                        207, 98, 192, 96,
                    ],
                    [
                        181, 124, 89, 252, 120, 134, 104, 102, 1, 53, 25, 191, 76, 19, 62, 44, 62,
                        169, 80, 219,
                    ],
                    [
                        245, 138, 14, 111, 52, 3, 173, 1, 172, 140, 229, 50, 34, 80, 215, 209, 39,
                        88, 16, 190,
                    ],
                    [
                        208, 211, 235, 192, 97, 223, 166, 122, 187, 24, 20, 124, 197, 86, 157, 138,
                        238, 174, 201, 163,
                    ],
                    [
                        64, 235, 8, 124, 248, 232, 83, 205, 233, 229, 234, 73, 242, 160, 27, 54,
                        229, 11, 114, 211,
                    ],
                    [
                        0, 226, 6, 123, 92, 32, 124, 180, 247, 169, 145, 135, 221, 138, 57, 1, 52,
                        180, 91, 136,
                    ],
                    [
                        235, 20, 88, 189, 74, 77, 45, 187, 243, 88, 115, 246, 89, 137, 91, 110,
                        101, 111, 125, 52,
                    ],
                    [
                        75, 239, 154, 132, 89, 194, 64, 154, 200, 38, 249, 232, 88, 126, 137, 43,
                        183, 8, 233, 213,
                    ],
                    [
                        112, 180, 15, 34, 178, 21, 56, 86, 166, 86, 84, 123, 2, 178, 83, 90, 65,
                        120, 48, 140,
                    ],
                    [
                        231, 199, 195, 7, 50, 144, 124, 0, 136, 99, 239, 197, 36, 89, 32, 99, 234,
                        179, 181, 7,
                    ],
                    [
                        8, 45, 227, 162, 149, 234, 35, 41, 171, 95, 88, 107, 123, 130, 215, 163,
                        217, 63, 194, 0,
                    ],
                    [
                        235, 219, 23, 68, 183, 213, 114, 164, 249, 73, 20, 176, 149, 10, 41, 23,
                        200, 23, 79, 60,
                    ],
                    [
                        50, 206, 25, 130, 43, 113, 112, 27, 167, 66, 150, 138, 219, 199, 205, 64,
                        246, 162, 116, 86,
                    ],
                    [
                        235, 137, 109, 88, 134, 115, 214, 45, 246, 183, 14, 46, 24, 241, 208, 11,
                        172, 243, 19, 110,
                    ],
                    [
                        184, 223, 38, 155, 211, 186, 80, 94, 35, 209, 198, 46, 145, 29, 48, 45,
                        177, 158, 137, 97,
                    ],
                    [
                        70, 170, 72, 165, 89, 163, 26, 87, 197, 101, 196, 202, 251, 16, 135, 78, 4,
                        30, 65, 156,
                    ],
                    [
                        223, 76, 252, 216, 129, 158, 228, 194, 44, 202, 72, 52, 84, 138, 13, 165,
                        33, 176, 199, 207,
                    ],
                    [
                        120, 98, 113, 4, 37, 65, 206, 191, 71, 202, 241, 198, 164, 185, 89, 34,
                        159, 67, 76, 133,
                    ],
                    [
                        186, 139, 27, 176, 25, 234, 88, 93, 195, 213, 48, 111, 95, 66, 161, 103,
                        168, 41, 169, 23,
                    ],
                    [
                        245, 19, 2, 112, 180, 60, 47, 97, 105, 66, 247, 140, 153, 79, 0, 96, 201,
                        232, 35, 49,
                    ],
                    [
                        139, 195, 123, 84, 235, 55, 52, 50, 157, 185, 97, 167, 180, 237, 252, 251,
                        16, 15, 3, 178,
                    ],
                    [
                        115, 33, 237, 178, 164, 90, 3, 182, 179, 17, 208, 75, 71, 53, 186, 144, 61,
                        16, 102, 55,
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
                        71, 211, 174, 61, 130, 31, 75, 97, 240, 103, 197, 1, 25, 169, 204, 200,
                        164, 133, 174, 27,
                    ],
                    [
                        173, 165, 2, 210, 196, 64, 242, 171, 96, 255, 43, 217, 209, 63, 128, 27,
                        235, 147, 194, 97,
                    ],
                    [
                        36, 135, 171, 129, 174, 51, 149, 131, 241, 35, 140, 171, 156, 153, 63, 112,
                        50, 23, 198, 178,
                    ],
                    [
                        70, 195, 20, 104, 183, 203, 236, 87, 177, 255, 60, 150, 232, 177, 113, 195,
                        234, 199, 57, 240,
                    ],
                    [
                        225, 156, 152, 77, 243, 145, 115, 166, 246, 108, 250, 251, 58, 72, 55, 163,
                        0, 205, 126, 136,
                    ],
                    [
                        39, 31, 179, 166, 76, 122, 88, 235, 126, 252, 86, 211, 200, 48, 4, 158,
                        251, 156, 12, 186,
                    ],
                    [
                        140, 56, 78, 246, 61, 168, 245, 179, 196, 20, 7, 40, 54, 221, 87, 90, 61,
                        137, 233, 115,
                    ],
                    [
                        253, 91, 76, 217, 29, 67, 91, 215, 48, 224, 24, 6, 111, 233, 203, 153, 43,
                        117, 10, 122,
                    ],
                    [
                        57, 142, 126, 222, 68, 161, 242, 234, 29, 137, 197, 164, 106, 248, 117,
                        230, 69, 182, 66, 107,
                    ],
                    [
                        112, 202, 168, 132, 16, 208, 20, 17, 142, 231, 14, 155, 172, 224, 68, 2,
                        15, 7, 21, 252,
                    ],
                    [
                        91, 86, 160, 16, 150, 211, 180, 29, 219, 113, 253, 210, 54, 73, 151, 255,
                        209, 219, 214, 246,
                    ],
                    [
                        20, 161, 207, 194, 162, 89, 60, 107, 33, 233, 165, 211, 211, 7, 205, 173,
                        94, 35, 138, 101,
                    ],
                    [
                        164, 207, 56, 12, 124, 211, 3, 13, 51, 81, 145, 42, 53, 8, 52, 217, 208,
                        233, 43, 188,
                    ],
                    [
                        116, 20, 75, 219, 129, 162, 77, 84, 139, 21, 70, 223, 211, 82, 237, 7, 53,
                        172, 244, 160,
                    ],
                    [
                        201, 253, 177, 30, 140, 1, 19, 55, 173, 12, 95, 131, 117, 135, 30, 173, 23,
                        97, 131, 28,
                    ],
                    [
                        152, 9, 181, 41, 162, 137, 146, 239, 249, 88, 179, 247, 85, 67, 40, 254,
                        34, 223, 55, 183,
                    ],
                    [
                        39, 25, 63, 254, 158, 69, 5, 4, 95, 190, 228, 217, 6, 16, 11, 136, 254,
                        237, 29, 128,
                    ],
                    [
                        102, 138, 27, 93, 211, 180, 71, 42, 97, 193, 136, 240, 94, 172, 226, 53,
                        211, 85, 153, 15,
                    ],
                    [
                        28, 32, 36, 241, 165, 145, 43, 135, 164, 255, 19, 56, 103, 49, 201, 33,
                        130, 71, 254, 0,
                    ],
                    [
                        146, 108, 120, 158, 44, 126, 39, 19, 10, 251, 56, 195, 236, 250, 194, 236,
                        104, 217, 16, 177,
                    ],
                    [
                        177, 164, 161, 4, 253, 69, 14, 216, 238, 231, 132, 215, 32, 164, 52, 57,
                        154, 69, 132, 248,
                    ],
                    [
                        205, 187, 191, 71, 51, 13, 156, 101, 138, 79, 225, 33, 182, 193, 20, 101,
                        204, 70, 235, 185,
                    ],
                    [
                        162, 178, 164, 22, 95, 64, 42, 194, 123, 15, 241, 64, 194, 165, 120, 57,
                        109, 203, 14, 29,
                    ],
                    [
                        164, 104, 5, 119, 165, 150, 148, 156, 58, 147, 52, 71, 190, 171, 240, 129,
                        80, 139, 227, 22,
                    ],
                    [
                        51, 202, 222, 197, 193, 8, 101, 198, 159, 184, 96, 34, 100, 225, 125, 240,
                        93, 208, 178, 239,
                    ],
                    [
                        98, 131, 187, 10, 82, 44, 75, 133, 158, 132, 90, 198, 56, 241, 166, 126,
                        90, 22, 25, 179,
                    ],
                    [
                        235, 110, 49, 109, 147, 22, 222, 138, 74, 77, 249, 230, 58, 255, 250, 226,
                        140, 95, 48, 127,
                    ],
                    [
                        42, 120, 84, 7, 85, 203, 132, 244, 236, 189, 147, 56, 89, 13, 116, 211, 89,
                        9, 165, 5,
                    ],
                    [
                        100, 47, 54, 48, 165, 170, 183, 119, 228, 85, 157, 120, 100, 210, 161, 164,
                        177, 1, 140, 72,
                    ],
                    [
                        124, 233, 16, 229, 32, 116, 39, 205, 188, 217, 78, 19, 40, 171, 253, 50,
                        15, 53, 135, 239,
                    ],
                    [
                        94, 62, 10, 181, 82, 157, 254, 157, 150, 190, 145, 149, 140, 59, 98, 40,
                        11, 71, 83, 36,
                    ],
                    [
                        211, 91, 62, 183, 204, 248, 214, 229, 233, 35, 175, 150, 64, 149, 37, 97,
                        173, 95, 167, 167,
                    ],
                ],
            ),
        }
    }

    fn from_wots256_signature<F: PrimeField>(signature: wots256::Signature) -> F {
        let nibbles = &signature.map(|(sig, digit)| digit)[0..wots256::M_DIGITS as usize];
        let bytes = nibbles
            .chunks(2)
            .rev()
            .map(|bn| (bn[0] << 4) + bn[1])
            .collect::<Vec<u8>>();
        F::from_le_bytes_mod_order(&bytes)
    }

    fn from_wots160_signature<F: PrimeField>(signature: wots160::Signature) -> F {
        let nibbles = &signature.map(|(sig, digit)| digit)[0..wots160::M_DIGITS as usize];
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

        let data = &[
            32, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
            18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46,
            48, 50, 52, 54, 56, 58, 60, 62, 120, 86, 52, 18,
        ];

        fn hash2fqBn254() -> Script {
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
            { hash2fqBn254() }

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
}
