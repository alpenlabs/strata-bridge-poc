use bitcoin::Txid;
use bitvm::{
    groth16::g16::{
        self, Proof, ProofAssertions as Groth16ProofAssertions, VerificationKey, WotsPublicKeys,
        WotsSignatures, N_TAPLEAVES,
    },
    signatures::wots::{wots160, wots256},
    treepp::*,
};

use super::commitments::{
    secret_key_for_bridge_out_txid, secret_key_for_proof_element, secret_key_for_superblock_hash,
    secret_key_for_superblock_period_start_ts,
};

pub fn bridge_poc_verification_key() -> g16::VerificationKey {
    // TODO: replace this with actual verification key
    let (_, ark_vk) = mock::compile_circuit();
    g16::VerificationKey { ark_vk }
}

pub fn generate_verifier_partial_scripts() -> [Script; N_TAPLEAVES] {
    g16::Verifier::compile(bridge_poc_verification_key())
}

pub fn generate_verifier_tapscripts_from_partial_scripts(
    verifier_scripts: &[Script; N_TAPLEAVES],
    public_keys: WotsPublicKeys,
) -> [Script; N_TAPLEAVES] {
    g16::Verifier::generate_tapscripts(public_keys, verifier_scripts)
}

pub fn generate_assertions_for_proof(vk: VerificationKey, proof: Proof) -> Groth16ProofAssertions {
    g16::Verifier::generate_assertions(vk, proof)
}

pub fn validate_assertion_signatures(
    proof: g16::Proof,
    signatures: WotsSignatures,
    public_keys: WotsPublicKeys,
) -> Option<(usize, Script)> {
    g16::Verifier::validate_assertion_signatures(
        proof,
        bridge_poc_verification_key(),
        signatures,
        public_keys,
    )
}

pub fn get_deposit_master_secret_key(msk: &str, deposit_txid: Txid) -> String {
    format!("{}:{}", msk, deposit_txid)
}

pub fn generate_wots_public_keys(msk: &str, deposit_txid: Txid) -> g16::WotsPublicKeys {
    let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);
    (
        [
            wots256::generate_public_key(&secret_key_for_superblock_period_start_ts(&deposit_msk)),
            wots256::generate_public_key(&secret_key_for_bridge_out_txid(&deposit_msk)),
            wots256::generate_public_key(&secret_key_for_superblock_hash(&deposit_msk)),
        ],
        std::array::from_fn(|i| {
            wots256::generate_public_key(&secret_key_for_proof_element(&deposit_msk, i as u32))
        }),
        std::array::from_fn(|i| {
            wots160::generate_public_key(&secret_key_for_proof_element(
                &deposit_msk,
                (i + 40) as u32,
            ))
        }),
    )
}

pub fn generate_wots_signatures(
    msk: &str,
    deposit_txid: Txid,
    assertions: g16::ProofAssertions,
) -> g16::WotsSignatures {
    let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);
    (
        [
            wots256::get_signature(
                &secret_key_for_superblock_period_start_ts(&deposit_msk),
                &assertions.0[0],
            ),
            wots256::get_signature(
                &secret_key_for_bridge_out_txid(&deposit_msk),
                &assertions.0[1],
            ),
            wots256::get_signature(
                &secret_key_for_superblock_hash(&deposit_msk),
                &assertions.0[2],
            ),
        ],
        std::array::from_fn(|i| {
            wots256::get_signature(
                &secret_key_for_proof_element(&deposit_msk, i as u32),
                &assertions.1[i],
            )
        }),
        std::array::from_fn(|i| {
            wots160::get_signature(
                &secret_key_for_proof_element(&deposit_msk, (i + 40) as u32),
                &assertions.2[i],
            )
        }),
    )
}

pub mod mock {
    use ark_bn254::{Bn254, Fr as F};
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_ff::AdditiveGroup;
    use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::test_rng;
    use rand::{RngCore, SeedableRng};

    #[derive(Debug, Clone)]
    pub struct DummyCircuit {
        pub a: Option<F>, // Private input a
        pub b: Option<F>, // Private input b
        pub c: F,         // Public output: a * b
        pub d: F,         // Public output: a + b
        pub e: F,         // Public output: a - b
    }

    impl ConstraintSynthesizer<F> for DummyCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
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
            let e = FpVar::new_input(cs.clone(), || Ok(self.e))?;

            // Enforce the constraints: c = a * b, d = a + b, e = a - b
            let computed_c = &a * &b;
            let computed_d = &a + &b;
            let computed_e = &a - &b;

            computed_c.enforce_equal(&c)?;
            computed_d.enforce_equal(&d)?;
            computed_e.enforce_equal(&e)?;

            Ok(())
        }
    }

    pub fn compile_circuit() -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
        type E = Bn254;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit {
            a: None,
            b: None,
            c: F::ZERO,
            d: F::ZERO,
            e: F::ZERO,
        };
        let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();
        (pk, vk)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::snark::SNARK;
    use ark_groth16::Groth16;
    use ark_std::test_rng;
    use bitcoin::{ScriptBuf, Txid};
    use bitvm::{
        groth16::g16,
        signatures::wots::{wots160, wots256},
        treepp::*,
    };
    use rand::{RngCore, SeedableRng};
    use strata_bridge_tx_graph::mock_txid;

    use super::{generate_verifier_partial_scripts, mock, validate_assertion_signatures};
    use crate::scripts::commitments::{
        secret_key_for_bridge_out_txid, secret_key_for_proof_element,
        secret_key_for_superblock_hash, secret_key_for_superblock_period_start_ts,
    };

    #[test]
    fn test_groth16_compile() {
        let scripts = generate_verifier_partial_scripts();
        // let scripts =
        //     std::array::from_fn::<Script, { g16::N_TAPLEAVES }, _>(|index| script! { {1+index}
        // });
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

    // fn save_assertions(assertions: &g16::ProofAssertions) {
    //     print!("Saving assertions...");

    //     for (index, script) in assertions.iter().enumerate() {
    //         let path = format!("data/verifier-scripts/{index}");
    //         fs::write(path, script.clone().compile().to_bytes()).unwrap();
    //         print!("{}, ", index);
    //     }
    //     println!();
    // }

    pub fn get_deposit_master_secret_key(deposit_txid: Txid) -> String {
        let master_secret_key = "helloworld";
        format!("{}:{}", master_secret_key, deposit_txid)
    }

    fn generate_wots_public_keys(deposit_txid: Txid) -> g16::WotsPublicKeys {
        let deposit_msk = get_deposit_master_secret_key(deposit_txid);
        (
            [
                wots256::generate_public_key(&secret_key_for_superblock_period_start_ts(
                    &deposit_msk,
                )),
                wots256::generate_public_key(&secret_key_for_bridge_out_txid(&deposit_msk)),
                wots256::generate_public_key(&secret_key_for_superblock_hash(&deposit_msk)),
            ],
            std::array::from_fn(|i| {
                wots256::generate_public_key(&secret_key_for_proof_element(&deposit_msk, i as u32))
            }),
            std::array::from_fn(|i| {
                wots160::generate_public_key(&secret_key_for_proof_element(&deposit_msk, i as u32))
            }),
        )
    }

    fn generate_wots_signatures(
        deposit_txid: Txid,
        assertions: g16::ProofAssertions,
    ) -> g16::WotsSignatures {
        let deposit_msk = get_deposit_master_secret_key(deposit_txid);
        (
            [
                wots256::get_signature(
                    &secret_key_for_superblock_period_start_ts(&deposit_msk),
                    &assertions.0[0],
                ),
                wots256::get_signature(
                    &secret_key_for_bridge_out_txid(&deposit_msk),
                    &assertions.0[1],
                ),
                wots256::get_signature(
                    &secret_key_for_superblock_hash(&deposit_msk),
                    &assertions.0[2],
                ),
            ],
            std::array::from_fn(|i| {
                wots256::get_signature(
                    &secret_key_for_proof_element(&deposit_msk, i as u32),
                    &assertions.1[i],
                )
            }),
            std::array::from_fn(|i| {
                wots160::get_signature(
                    &secret_key_for_proof_element(&deposit_msk, (i + 40) as u32),
                    &assertions.2[i],
                )
            }),
        )
    }

    #[test]
    fn test_full_verification() {
        let (pk, _) = mock::compile_circuit();

        let (a, b) = (5, 3);
        let (c, d, e) = (a * b, a + b, a - b);

        let circuit = mock::DummyCircuit {
            a: Some(Fr::from(a)),
            b: Some(Fr::from(b)),
            c: Fr::from(c),
            d: Fr::from(d),
            e: Fr::from(e),
        };

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();

        println!("Generating assertions");
        // let assertions = generate_assertions_for_proof(
        //     bridge_poc_verification_key(),
        //     g16::Proof {
        //         proof: proof.clone(),
        //         public_inputs: vec![circuit.c, circuit.d, circuit.e],
        //     },
        // );
        let assertions = get_mock_assertions();

        let deposit_txid = mock_txid();

        println!("Generating wots public keys");
        let wots_public_keys = generate_wots_public_keys(deposit_txid);

        println!("Generating wots signatures");
        let wots_signatures = generate_wots_signatures(deposit_txid, assertions);

        let verifier_scripts = &read_verifier_scripts();
        // let verifier_scripts = generate_verifier_partial_scripts();
        // save_verifier_scripts(&verifier_scripts);

        println!("Validating assertion signatures");
        let _res = validate_assertion_signatures(
            g16::Proof {
                proof: proof.clone(),
                public_inputs: vec![circuit.c, circuit.d, circuit.e],
            },
            wots_signatures,
            wots_public_keys,
        );

        // match res {
        //     Some([_tapleaf_index, witness_script]) => {
        //         println!("Assertion is invalid");
        //
        //         let script = script! {
        //             { witness_script }
        //             { tapleaf_script }
        //         };
        //         let res = execute_script(script);
        //         assert!(
        //             res.success,
        //             "Invalid assertion: Disprove script should not fail"
        //         );
        //     }
        //     None => println!("Assertion is valid"),
        // }
    }

    fn get_mock_assertions() -> g16::ProofAssertions {
        (
            [
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 32,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 128,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 240,
                ],
            ],
            [
                [
                    192, 108, 122, 159, 204, 253, 113, 40, 218, 130, 94, 123, 212, 108, 84, 99,
                    247, 27, 102, 236, 160, 78, 120, 184, 27, 52, 183, 141, 72, 132, 222, 199,
                ],
                [
                    242, 251, 184, 186, 5, 242, 33, 237, 176, 246, 65, 46, 61, 10, 109, 247, 157,
                    212, 164, 223, 103, 159, 83, 64, 119, 83, 103, 209, 54, 154, 177, 66,
                ],
                [
                    210, 16, 185, 231, 46, 51, 25, 174, 132, 116, 154, 83, 173, 171, 66, 149, 176,
                    4, 107, 76, 28, 149, 169, 3, 50, 244, 67, 223, 13, 31, 4, 96,
                ],
                [
                    80, 195, 204, 142, 164, 153, 165, 11, 60, 134, 60, 230, 56, 142, 0, 30, 85,
                    166, 154, 4, 179, 15, 246, 135, 11, 155, 233, 38, 52, 217, 157, 71,
                ],
                [
                    193, 43, 104, 91, 8, 214, 181, 122, 162, 248, 127, 254, 166, 61, 92, 94, 113,
                    30, 77, 189, 188, 65, 248, 200, 160, 248, 33, 72, 39, 94, 35, 0,
                ],
                [
                    144, 208, 207, 193, 234, 89, 140, 248, 29, 174, 143, 39, 53, 3, 224, 151, 22,
                    192, 9, 101, 29, 89, 99, 156, 135, 86, 214, 229, 235, 132, 178, 157,
                ],
                [
                    224, 167, 61, 151, 213, 177, 72, 246, 23, 238, 240, 129, 60, 86, 253, 75, 3,
                    205, 21, 228, 107, 92, 111, 104, 244, 231, 61, 121, 172, 222, 6, 68,
                ],
                [
                    98, 178, 54, 76, 108, 22, 155, 169, 239, 203, 49, 30, 247, 53, 211, 41, 87,
                    111, 25, 237, 185, 198, 222, 86, 140, 157, 230, 90, 165, 10, 68, 29,
                ],
                [
                    82, 67, 234, 180, 190, 154, 248, 52, 76, 92, 151, 86, 47, 162, 142, 156, 210,
                    37, 202, 53, 193, 156, 45, 167, 140, 196, 146, 162, 225, 122, 111, 211,
                ],
                [
                    240, 175, 137, 18, 17, 251, 74, 33, 103, 112, 162, 138, 141, 233, 229, 244, 62,
                    67, 46, 222, 117, 144, 92, 118, 177, 91, 215, 145, 107, 206, 74, 21,
                ],
                [
                    113, 24, 76, 190, 160, 7, 246, 228, 84, 44, 207, 21, 3, 241, 65, 177, 39, 55,
                    220, 79, 97, 78, 139, 52, 201, 110, 89, 32, 69, 123, 1, 164,
                ],
                [
                    49, 211, 83, 61, 213, 154, 247, 21, 5, 227, 47, 91, 135, 56, 132, 224, 155, 85,
                    35, 112, 253, 87, 104, 108, 158, 246, 245, 237, 64, 65, 213, 180,
                ],
                [
                    146, 99, 28, 92, 116, 209, 244, 230, 107, 157, 198, 240, 118, 166, 3, 32, 26,
                    124, 255, 71, 21, 253, 173, 218, 135, 58, 21, 155, 45, 187, 3, 78,
                ],
                [
                    178, 199, 45, 237, 24, 207, 251, 103, 11, 205, 5, 111, 192, 110, 210, 112, 160,
                    197, 194, 7, 22, 38, 133, 135, 78, 144, 194, 77, 186, 145, 224, 68,
                ],
                [
                    65, 201, 227, 188, 161, 20, 113, 57, 175, 182, 224, 109, 92, 169, 186, 253,
                    178, 179, 139, 123, 171, 149, 151, 248, 223, 111, 72, 203, 210, 177, 13, 47,
                ],
                [
                    18, 68, 169, 59, 200, 153, 196, 218, 46, 203, 223, 212, 71, 8, 57, 196, 199, 7,
                    61, 142, 33, 135, 52, 162, 141, 45, 111, 239, 59, 61, 82, 73,
                ],
                [
                    18, 87, 6, 141, 212, 133, 237, 34, 46, 145, 155, 21, 171, 253, 178, 21, 101,
                    93, 251, 106, 29, 89, 235, 72, 212, 189, 194, 231, 236, 252, 43, 121,
                ],
                [
                    17, 88, 178, 32, 164, 217, 29, 233, 135, 222, 164, 42, 13, 15, 133, 17, 147,
                    236, 214, 194, 230, 121, 232, 250, 121, 143, 99, 242, 99, 176, 1, 215,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    32, 221, 92, 245, 151, 247, 237, 41, 122, 74, 25, 65, 242, 126, 97, 65, 169,
                    227, 73, 151, 158, 228, 142, 170, 105, 23, 119, 128, 43, 214, 38, 233,
                ],
                [
                    194, 194, 220, 46, 57, 169, 50, 89, 28, 190, 179, 219, 201, 225, 185, 36, 243,
                    195, 139, 28, 221, 147, 139, 176, 91, 110, 107, 253, 77, 35, 209, 172,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    97, 222, 168, 174, 25, 254, 191, 222, 179, 69, 37, 127, 116, 54, 54, 50, 220,
                    33, 12, 23, 69, 67, 87, 161, 12, 131, 153, 65, 199, 56, 42, 7,
                ],
                [
                    162, 66, 10, 225, 151, 74, 239, 67, 249, 6, 156, 205, 123, 27, 14, 9, 164, 240,
                    173, 107, 43, 58, 250, 162, 193, 68, 53, 99, 209, 216, 39, 59,
                ],
                [
                    17, 144, 252, 151, 148, 195, 190, 36, 33, 6, 150, 1, 4, 168, 40, 178, 195, 222,
                    216, 31, 65, 180, 86, 148, 103, 107, 126, 118, 32, 81, 10, 219,
                ],
                [
                    49, 6, 144, 157, 255, 121, 131, 32, 127, 147, 34, 9, 35, 231, 253, 249, 8, 225,
                    18, 174, 122, 140, 248, 156, 111, 198, 132, 70, 172, 147, 140, 195,
                ],
                [
                    98, 33, 76, 89, 146, 146, 229, 162, 217, 194, 88, 123, 147, 79, 86, 154, 34,
                    69, 5, 1, 18, 70, 63, 229, 14, 183, 176, 78, 167, 69, 80, 207,
                ],
                [
                    18, 118, 190, 244, 206, 128, 160, 114, 212, 98, 55, 170, 192, 152, 229, 237,
                    205, 253, 106, 242, 7, 133, 115, 1, 215, 3, 102, 178, 66, 232, 179, 203,
                ],
                [
                    242, 99, 239, 2, 204, 8, 122, 144, 138, 208, 91, 192, 43, 128, 183, 55, 15, 69,
                    103, 107, 27, 204, 218, 114, 1, 37, 164, 98, 202, 119, 181, 99,
                ],
                [
                    34, 136, 168, 12, 65, 139, 197, 30, 115, 88, 60, 121, 161, 71, 240, 122, 237,
                    89, 222, 124, 50, 238, 75, 157, 56, 4, 82, 255, 159, 110, 200, 21,
                ],
                [
                    129, 1, 203, 93, 139, 1, 67, 157, 40, 121, 169, 251, 9, 219, 156, 0, 80, 58,
                    219, 185, 156, 107, 227, 229, 136, 197, 146, 36, 178, 146, 164, 38,
                ],
                [
                    34, 4, 123, 104, 216, 207, 183, 115, 33, 56, 23, 190, 93, 77, 11, 138, 79, 204,
                    45, 148, 73, 7, 114, 151, 47, 143, 40, 237, 7, 16, 177, 148,
                ],
            ],
            [
                [
                    168, 254, 116, 105, 202, 157, 46, 196, 73, 242, 174, 105, 138, 60, 195, 90, 91,
                    88, 143, 49,
                ],
                [
                    253, 89, 226, 10, 33, 157, 225, 106, 187, 138, 61, 111, 72, 185, 43, 56, 108,
                    42, 225, 230,
                ],
                [
                    13, 85, 122, 250, 251, 94, 203, 92, 128, 219, 1, 110, 190, 140, 46, 160, 130,
                    90, 190, 79,
                ],
                [
                    98, 143, 250, 173, 185, 35, 134, 241, 66, 238, 239, 240, 144, 216, 42, 113, 90,
                    58, 232, 133,
                ],
                [
                    172, 37, 4, 159, 20, 201, 231, 62, 149, 68, 127, 58, 40, 172, 78, 33, 171, 218,
                    66, 231,
                ],
                [
                    216, 158, 95, 10, 131, 220, 194, 137, 82, 240, 224, 225, 241, 95, 178, 176,
                    243, 181, 218, 188,
                ],
                [
                    81, 173, 157, 193, 190, 169, 69, 64, 134, 135, 98, 116, 82, 74, 213, 240, 128,
                    135, 30, 162,
                ],
                [
                    41, 96, 163, 78, 226, 27, 34, 213, 50, 126, 78, 164, 231, 164, 224, 230, 218,
                    130, 110, 248,
                ],
                [
                    56, 157, 143, 165, 104, 74, 111, 45, 242, 251, 234, 150, 239, 219, 182, 202,
                    75, 54, 30, 245,
                ],
                [
                    72, 173, 95, 131, 57, 129, 231, 158, 49, 13, 245, 247, 62, 30, 44, 75, 167, 43,
                    126, 73,
                ],
                [
                    163, 99, 120, 177, 174, 189, 211, 17, 90, 41, 29, 204, 148, 157, 252, 238, 83,
                    105, 201, 133,
                ],
                [
                    15, 26, 99, 198, 116, 124, 210, 92, 191, 65, 68, 14, 237, 196, 34, 86, 106, 61,
                    222, 10,
                ],
                [
                    40, 53, 94, 8, 58, 195, 5, 240, 192, 229, 180, 155, 173, 13, 10, 129, 31, 217,
                    16, 192,
                ],
                [
                    255, 227, 98, 248, 234, 48, 208, 178, 202, 105, 64, 195, 194, 189, 126, 85, 14,
                    90, 231, 246,
                ],
                [
                    63, 86, 123, 55, 24, 141, 169, 29, 198, 99, 74, 10, 178, 61, 235, 25, 206, 89,
                    239, 104,
                ],
                [
                    94, 186, 48, 198, 66, 8, 145, 184, 86, 184, 28, 203, 220, 117, 237, 98, 143,
                    149, 203, 228,
                ],
                [
                    78, 176, 73, 185, 255, 212, 151, 166, 133, 237, 191, 117, 249, 65, 203, 155,
                    53, 95, 252, 60,
                ],
                [
                    220, 4, 71, 69, 206, 46, 156, 122, 59, 161, 238, 250, 58, 11, 161, 121, 12, 92,
                    99, 135,
                ],
                [
                    199, 110, 239, 225, 137, 75, 30, 53, 117, 237, 157, 175, 185, 5, 235, 18, 155,
                    237, 214, 196,
                ],
                [
                    60, 67, 126, 172, 255, 49, 86, 31, 139, 224, 144, 40, 62, 101, 240, 223, 199,
                    138, 111, 48,
                ],
                [
                    104, 39, 218, 183, 224, 169, 5, 203, 236, 13, 0, 199, 77, 141, 179, 184, 64,
                    234, 7, 96,
                ],
                [
                    92, 76, 218, 91, 107, 197, 186, 204, 104, 64, 114, 232, 108, 147, 25, 89, 67,
                    108, 153, 177,
                ],
                [
                    219, 197, 102, 222, 33, 194, 76, 123, 36, 126, 197, 175, 5, 194, 58, 120, 95,
                    251, 2, 141,
                ],
                [
                    170, 149, 41, 163, 252, 198, 48, 147, 140, 152, 170, 109, 28, 130, 129, 86, 5,
                    148, 6, 137,
                ],
                [
                    9, 171, 182, 13, 247, 139, 216, 249, 19, 143, 103, 84, 155, 90, 38, 121, 249,
                    31, 202, 195,
                ],
                [
                    225, 222, 192, 178, 46, 182, 79, 151, 176, 246, 149, 9, 172, 159, 3, 86, 20,
                    161, 14, 122,
                ],
                [
                    245, 118, 223, 2, 239, 198, 220, 140, 133, 144, 81, 142, 126, 152, 144, 25,
                    196, 103, 58, 93,
                ],
                [
                    199, 140, 166, 248, 220, 157, 118, 189, 151, 5, 199, 240, 63, 194, 211, 220,
                    63, 142, 46, 112,
                ],
                [
                    78, 198, 64, 40, 10, 241, 224, 167, 134, 48, 34, 77, 102, 37, 156, 240, 8, 60,
                    12, 201,
                ],
                [
                    3, 42, 98, 165, 177, 172, 123, 33, 87, 42, 244, 128, 195, 128, 153, 99, 228,
                    140, 74, 244,
                ],
                [
                    117, 108, 202, 230, 128, 34, 196, 73, 161, 78, 95, 100, 104, 63, 236, 94, 164,
                    137, 14, 19,
                ],
                [
                    88, 2, 72, 19, 101, 71, 175, 177, 79, 202, 204, 225, 36, 242, 130, 87, 249, 64,
                    237, 229,
                ],
                [
                    111, 70, 43, 215, 143, 108, 27, 52, 121, 245, 10, 234, 14, 113, 168, 209, 251,
                    6, 34, 217,
                ],
                [
                    251, 150, 239, 219, 237, 219, 48, 213, 63, 183, 254, 50, 235, 245, 94, 110,
                    148, 61, 4, 84,
                ],
                [
                    107, 32, 255, 198, 159, 242, 116, 29, 227, 215, 195, 68, 215, 112, 102, 18,
                    135, 5, 188, 34,
                ],
                [
                    17, 16, 160, 226, 245, 191, 86, 73, 17, 99, 76, 68, 66, 106, 126, 230, 23, 115,
                    55, 79,
                ],
                [
                    64, 85, 225, 24, 171, 164, 92, 224, 252, 198, 159, 70, 196, 61, 172, 244, 58,
                    63, 210, 220,
                ],
                [
                    251, 18, 114, 165, 239, 165, 218, 119, 100, 114, 6, 82, 1, 67, 129, 185, 90,
                    88, 184, 92,
                ],
                [
                    110, 152, 220, 184, 12, 201, 240, 240, 54, 110, 109, 214, 43, 142, 13, 69, 240,
                    216, 10, 75,
                ],
                [
                    234, 30, 191, 1, 212, 112, 31, 234, 74, 157, 158, 17, 84, 5, 174, 34, 232, 163,
                    111, 103,
                ],
                [
                    211, 124, 27, 119, 162, 247, 248, 85, 94, 179, 107, 23, 244, 206, 71, 171, 228,
                    78, 162, 253,
                ],
                [
                    209, 73, 234, 36, 2, 33, 149, 90, 117, 150, 204, 151, 1, 164, 90, 36, 169, 211,
                    155, 99,
                ],
                [
                    82, 240, 14, 214, 247, 62, 133, 58, 134, 58, 104, 178, 181, 72, 112, 64, 200,
                    42, 106, 226,
                ],
                [
                    84, 79, 167, 153, 224, 65, 189, 8, 82, 178, 85, 158, 20, 150, 49, 192, 175,
                    102, 242, 238,
                ],
                [
                    233, 150, 20, 48, 255, 122, 69, 48, 91, 239, 197, 103, 104, 94, 147, 106, 194,
                    196, 59, 173,
                ],
                [
                    101, 81, 214, 223, 131, 6, 123, 120, 77, 251, 58, 97, 41, 46, 217, 180, 8, 136,
                    59, 189,
                ],
                [
                    182, 155, 34, 211, 46, 148, 177, 138, 139, 222, 51, 241, 197, 3, 143, 67, 83,
                    12, 215, 18,
                ],
                [
                    89, 178, 72, 225, 194, 202, 63, 107, 50, 56, 205, 91, 27, 62, 253, 35, 41, 76,
                    160, 118,
                ],
                [
                    217, 19, 50, 234, 67, 93, 109, 148, 42, 51, 52, 79, 191, 53, 88, 237, 243, 157,
                    239, 64,
                ],
                [
                    95, 110, 150, 75, 99, 252, 176, 138, 92, 62, 189, 72, 119, 146, 109, 126, 215,
                    114, 110, 226,
                ],
                [
                    58, 232, 254, 21, 206, 195, 177, 145, 135, 57, 122, 166, 98, 26, 174, 130, 252,
                    239, 13, 151,
                ],
                [
                    128, 71, 225, 240, 245, 65, 201, 5, 42, 228, 124, 210, 85, 160, 82, 176, 30,
                    165, 52, 95,
                ],
                [
                    108, 217, 55, 101, 23, 230, 245, 74, 96, 170, 36, 234, 114, 190, 49, 161, 226,
                    206, 238, 0,
                ],
                [
                    191, 180, 241, 42, 234, 232, 71, 201, 61, 224, 4, 168, 115, 91, 97, 216, 210,
                    51, 151, 238,
                ],
                [
                    162, 73, 131, 85, 189, 221, 185, 33, 166, 241, 132, 12, 48, 79, 108, 184, 220,
                    84, 68, 104,
                ],
                [
                    209, 132, 198, 88, 140, 86, 233, 8, 191, 84, 141, 160, 134, 182, 247, 2, 39,
                    211, 138, 180,
                ],
                [
                    66, 105, 55, 6, 239, 151, 79, 106, 76, 95, 242, 213, 221, 130, 24, 32, 18, 232,
                    223, 28,
                ],
                [
                    1, 189, 82, 147, 244, 144, 25, 160, 14, 85, 167, 56, 231, 112, 79, 147, 15, 96,
                    36, 138,
                ],
                [
                    216, 150, 140, 229, 218, 211, 88, 212, 235, 177, 255, 198, 221, 170, 219, 20,
                    148, 250, 57, 87,
                ],
                [
                    189, 149, 192, 179, 49, 93, 29, 33, 62, 178, 135, 171, 71, 44, 60, 151, 27, 43,
                    160, 47,
                ],
                [
                    170, 78, 46, 5, 114, 115, 227, 4, 99, 96, 149, 14, 30, 131, 226, 61, 136, 118,
                    10, 67,
                ],
                [
                    213, 69, 7, 14, 102, 242, 150, 180, 92, 26, 138, 207, 32, 194, 9, 255, 165,
                    221, 227, 100,
                ],
                [
                    42, 196, 112, 226, 132, 189, 33, 35, 165, 158, 82, 195, 184, 58, 111, 138, 149,
                    4, 68, 38,
                ],
                [
                    24, 143, 163, 33, 75, 208, 234, 104, 183, 86, 137, 149, 254, 83, 69, 40, 74,
                    41, 161, 63,
                ],
                [
                    70, 69, 249, 2, 31, 183, 50, 187, 233, 80, 8, 163, 131, 234, 125, 231, 222,
                    209, 98, 111,
                ],
                [
                    139, 47, 27, 46, 163, 156, 137, 65, 140, 55, 2, 227, 74, 196, 148, 232, 202,
                    40, 11, 9,
                ],
                [
                    10, 19, 52, 101, 31, 82, 204, 113, 92, 47, 108, 210, 217, 183, 27, 218, 194,
                    19, 100, 218,
                ],
                [
                    43, 113, 87, 18, 76, 237, 175, 104, 108, 73, 102, 2, 146, 1, 240, 69, 234, 85,
                    248, 97,
                ],
                [
                    132, 170, 85, 154, 63, 4, 160, 152, 192, 92, 199, 168, 193, 181, 124, 234, 189,
                    179, 220, 250,
                ],
                [
                    23, 26, 184, 131, 161, 203, 84, 113, 23, 141, 116, 58, 160, 201, 244, 198, 121,
                    250, 14, 205,
                ],
                [
                    132, 59, 191, 42, 201, 171, 84, 96, 23, 152, 90, 191, 198, 59, 94, 173, 84, 24,
                    61, 228,
                ],
                [
                    9, 55, 62, 129, 7, 104, 73, 27, 245, 104, 50, 132, 42, 140, 222, 116, 50, 11,
                    191, 16,
                ],
                [
                    92, 229, 129, 96, 57, 104, 233, 18, 222, 106, 118, 0, 51, 197, 236, 198, 193,
                    41, 107, 111,
                ],
                [
                    23, 36, 231, 198, 249, 96, 6, 190, 200, 10, 199, 136, 213, 83, 30, 53, 224,
                    174, 113, 75,
                ],
                [
                    177, 249, 199, 54, 106, 177, 211, 195, 163, 140, 227, 220, 237, 20, 22, 234,
                    148, 57, 132, 44,
                ],
                [
                    249, 15, 197, 181, 131, 209, 21, 57, 91, 237, 52, 250, 126, 170, 147, 136, 2,
                    255, 245, 119,
                ],
                [
                    126, 17, 248, 178, 243, 31, 158, 105, 71, 233, 9, 84, 84, 158, 129, 198, 54,
                    145, 249, 164,
                ],
                [
                    15, 113, 104, 42, 117, 141, 207, 7, 194, 41, 183, 13, 133, 132, 49, 92, 186,
                    115, 53, 236,
                ],
                [
                    219, 156, 10, 44, 27, 188, 117, 42, 128, 123, 12, 23, 231, 251, 50, 159, 213,
                    58, 70, 180,
                ],
                [
                    44, 128, 92, 208, 213, 28, 2, 27, 219, 47, 123, 197, 207, 105, 22, 181, 125,
                    81, 45, 93,
                ],
                [
                    185, 184, 19, 208, 126, 152, 134, 208, 114, 134, 244, 174, 226, 163, 100, 219,
                    177, 54, 25, 219,
                ],
                [
                    69, 172, 2, 197, 210, 21, 56, 43, 13, 128, 57, 129, 60, 38, 20, 194, 187, 159,
                    74, 165,
                ],
                [
                    14, 94, 42, 191, 43, 65, 115, 248, 141, 69, 51, 115, 144, 61, 87, 150, 87, 173,
                    155, 147,
                ],
                [
                    105, 66, 105, 247, 210, 62, 191, 212, 184, 232, 244, 255, 153, 111, 216, 18,
                    166, 245, 2, 53,
                ],
                [
                    220, 116, 196, 192, 88, 238, 206, 18, 5, 33, 107, 68, 221, 120, 88, 121, 137,
                    109, 168, 61,
                ],
                [
                    130, 84, 69, 176, 213, 170, 163, 55, 109, 9, 33, 188, 88, 248, 160, 91, 135,
                    89, 46, 15,
                ],
                [
                    2, 146, 159, 95, 89, 43, 17, 109, 60, 23, 166, 65, 113, 48, 59, 76, 3, 16, 117,
                    171,
                ],
                [
                    134, 50, 83, 213, 38, 242, 23, 179, 191, 7, 62, 15, 119, 130, 250, 5, 194, 212,
                    101, 80,
                ],
                [
                    47, 173, 49, 64, 0, 177, 159, 82, 31, 254, 177, 94, 93, 163, 9, 243, 37, 223,
                    59, 38,
                ],
                [
                    75, 123, 88, 227, 203, 108, 102, 187, 141, 30, 23, 105, 103, 174, 167, 123,
                    193, 38, 117, 229,
                ],
                [
                    32, 209, 197, 237, 97, 126, 84, 189, 101, 131, 123, 83, 204, 231, 224, 101,
                    200, 76, 238, 205,
                ],
                [
                    141, 174, 229, 255, 223, 102, 145, 208, 72, 231, 215, 187, 149, 98, 246, 31,
                    36, 36, 191, 98,
                ],
                [
                    114, 149, 169, 172, 124, 116, 130, 74, 43, 121, 213, 90, 56, 129, 55, 156, 113,
                    105, 216, 122,
                ],
                [
                    18, 197, 195, 46, 3, 8, 151, 69, 117, 148, 91, 16, 148, 125, 230, 222, 202, 65,
                    40, 132,
                ],
                [
                    137, 64, 248, 62, 160, 112, 184, 26, 113, 153, 23, 38, 235, 198, 125, 195, 204,
                    62, 184, 237,
                ],
                [
                    48, 183, 101, 40, 151, 234, 201, 253, 29, 81, 220, 123, 132, 59, 133, 98, 71,
                    87, 178, 251,
                ],
                [
                    74, 26, 238, 42, 197, 87, 40, 57, 156, 87, 235, 153, 202, 147, 56, 114, 182,
                    125, 197, 41,
                ],
                [
                    74, 45, 230, 38, 2, 228, 200, 69, 6, 200, 100, 17, 46, 3, 94, 204, 215, 34,
                    136, 3,
                ],
                [
                    132, 227, 200, 96, 170, 20, 169, 152, 122, 66, 53, 131, 60, 240, 188, 68, 108,
                    139, 163, 186,
                ],
                [
                    201, 43, 4, 44, 219, 230, 64, 234, 2, 129, 185, 136, 240, 4, 7, 209, 21, 217,
                    205, 152,
                ],
                [
                    154, 107, 193, 171, 128, 234, 132, 34, 192, 179, 61, 229, 110, 69, 79, 173, 36,
                    75, 233, 10,
                ],
                [
                    97, 228, 38, 117, 191, 224, 150, 186, 162, 13, 80, 182, 124, 72, 244, 99, 185,
                    207, 172, 183,
                ],
                [
                    23, 2, 121, 189, 16, 180, 220, 113, 213, 154, 139, 132, 136, 240, 232, 173, 85,
                    128, 45, 127,
                ],
                [
                    0, 240, 215, 112, 235, 66, 135, 122, 84, 182, 219, 36, 189, 239, 16, 117, 84,
                    210, 39, 54,
                ],
                [
                    27, 249, 143, 235, 183, 196, 147, 137, 95, 141, 151, 254, 158, 250, 130, 7,
                    104, 113, 36, 248,
                ],
                [
                    106, 153, 69, 136, 161, 191, 167, 7, 11, 255, 60, 138, 104, 138, 167, 181, 53,
                    67, 51, 155,
                ],
                [
                    181, 25, 83, 241, 191, 15, 126, 40, 37, 6, 141, 236, 81, 80, 2, 51, 29, 217,
                    107, 190,
                ],
                [
                    97, 46, 106, 144, 131, 50, 236, 81, 130, 114, 80, 159, 27, 253, 191, 202, 35,
                    55, 149, 251,
                ],
                [
                    239, 147, 73, 227, 45, 178, 43, 19, 221, 109, 136, 134, 225, 47, 194, 87, 71,
                    211, 237, 36,
                ],
                [
                    144, 9, 201, 40, 36, 113, 93, 230, 95, 8, 232, 34, 91, 140, 85, 253, 66, 182,
                    43, 178,
                ],
                [
                    91, 59, 248, 210, 18, 239, 165, 17, 69, 137, 3, 211, 67, 40, 154, 224, 213, 37,
                    116, 7,
                ],
                [
                    44, 40, 175, 67, 104, 152, 225, 214, 57, 121, 131, 36, 64, 66, 132, 40, 171,
                    86, 57, 190,
                ],
                [
                    71, 157, 128, 87, 199, 17, 161, 175, 30, 9, 129, 182, 40, 74, 88, 112, 210,
                    127, 188, 214,
                ],
                [
                    49, 229, 133, 167, 86, 30, 133, 147, 247, 106, 183, 87, 135, 98, 6, 68, 228,
                    154, 43, 45,
                ],
                [
                    42, 246, 179, 237, 21, 182, 13, 174, 176, 1, 217, 71, 71, 250, 156, 45, 250,
                    88, 238, 253,
                ],
                [
                    215, 13, 15, 23, 220, 57, 219, 63, 22, 144, 152, 79, 82, 211, 166, 66, 239, 12,
                    136, 40,
                ],
                [
                    242, 65, 116, 18, 114, 160, 128, 51, 227, 13, 169, 157, 48, 233, 241, 92, 77,
                    179, 201, 158,
                ],
                [
                    59, 83, 154, 75, 179, 0, 126, 142, 80, 6, 169, 40, 238, 200, 242, 149, 240, 71,
                    25, 142,
                ],
                [
                    26, 9, 161, 36, 84, 44, 114, 191, 145, 81, 158, 99, 210, 182, 19, 209, 39, 186,
                    3, 194,
                ],
                [
                    176, 138, 61, 189, 42, 215, 228, 41, 203, 162, 230, 178, 26, 173, 79, 135, 10,
                    222, 82, 239,
                ],
                [
                    110, 52, 51, 195, 27, 232, 221, 110, 80, 154, 221, 176, 144, 199, 113, 52, 115,
                    64, 241, 176,
                ],
                [
                    60, 140, 114, 17, 168, 221, 100, 110, 98, 69, 92, 249, 49, 84, 7, 13, 48, 108,
                    201, 46,
                ],
                [
                    240, 184, 137, 19, 174, 153, 190, 234, 109, 12, 173, 0, 58, 34, 71, 252, 73,
                    39, 240, 228,
                ],
                [
                    31, 11, 241, 74, 170, 190, 82, 134, 64, 23, 175, 128, 247, 117, 36, 178, 195,
                    7, 235, 174,
                ],
                [
                    46, 199, 18, 81, 130, 106, 52, 233, 148, 1, 170, 21, 245, 207, 108, 234, 118,
                    221, 180, 90,
                ],
                [
                    156, 60, 244, 131, 136, 42, 128, 158, 166, 84, 150, 93, 208, 21, 134, 198, 51,
                    118, 172, 1,
                ],
                [
                    228, 76, 61, 57, 20, 39, 119, 118, 5, 130, 223, 156, 164, 174, 247, 1, 184,
                    166, 139, 195,
                ],
                [
                    190, 233, 196, 78, 230, 233, 101, 100, 17, 34, 56, 48, 63, 114, 144, 30, 212,
                    102, 150, 100,
                ],
                [
                    11, 193, 24, 107, 14, 212, 37, 96, 16, 146, 33, 214, 106, 130, 41, 183, 23, 7,
                    224, 60,
                ],
                [
                    4, 96, 133, 216, 94, 89, 31, 123, 26, 250, 72, 226, 230, 137, 233, 175, 64,
                    248, 153, 221,
                ],
                [
                    200, 178, 225, 124, 0, 141, 201, 244, 113, 9, 15, 91, 72, 192, 194, 69, 234,
                    82, 165, 166,
                ],
                [
                    125, 185, 76, 93, 236, 181, 46, 239, 227, 128, 225, 210, 251, 20, 102, 94, 157,
                    11, 228, 71,
                ],
                [
                    68, 112, 117, 64, 195, 89, 251, 192, 83, 159, 252, 63, 76, 159, 216, 194, 86,
                    222, 26, 135,
                ],
                [
                    134, 94, 227, 135, 162, 44, 121, 132, 110, 68, 243, 174, 90, 245, 233, 235,
                    167, 234, 142, 173,
                ],
                [
                    129, 112, 223, 97, 63, 64, 68, 102, 181, 232, 223, 189, 166, 23, 44, 8, 130,
                    147, 251, 86,
                ],
                [
                    108, 181, 179, 203, 157, 162, 212, 161, 125, 116, 75, 28, 200, 249, 208, 55,
                    89, 28, 83, 91,
                ],
                [
                    61, 142, 107, 13, 88, 28, 76, 34, 233, 160, 241, 3, 11, 100, 58, 151, 195, 24,
                    193, 220,
                ],
                [
                    3, 124, 123, 65, 166, 182, 23, 175, 239, 185, 150, 138, 136, 51, 247, 44, 47,
                    144, 131, 247,
                ],
                [
                    227, 32, 152, 200, 144, 210, 22, 207, 160, 251, 238, 220, 21, 68, 45, 105, 101,
                    131, 238, 104,
                ],
                [
                    206, 72, 19, 3, 135, 46, 21, 255, 106, 180, 16, 85, 24, 6, 242, 177, 55, 56,
                    63, 98,
                ],
                [
                    86, 147, 7, 56, 194, 88, 225, 5, 85, 174, 111, 83, 196, 234, 146, 86, 83, 93,
                    202, 126,
                ],
                [
                    4, 171, 156, 32, 43, 94, 33, 1, 6, 106, 49, 61, 150, 26, 132, 122, 101, 14,
                    185, 140,
                ],
                [
                    147, 121, 83, 128, 137, 172, 20, 0, 139, 239, 197, 126, 232, 232, 52, 140, 84,
                    25, 22, 251,
                ],
                [
                    243, 170, 220, 245, 85, 107, 84, 130, 129, 139, 3, 145, 204, 236, 90, 89, 149,
                    28, 102, 219,
                ],
                [
                    176, 122, 168, 172, 187, 184, 169, 121, 210, 141, 120, 254, 178, 109, 226, 55,
                    161, 127, 165, 115,
                ],
                [
                    237, 185, 131, 56, 112, 82, 2, 199, 60, 116, 186, 72, 106, 14, 223, 20, 253,
                    230, 155, 205,
                ],
                [
                    189, 134, 147, 129, 38, 155, 195, 149, 244, 3, 179, 95, 52, 137, 24, 191, 17,
                    221, 88, 173,
                ],
                [
                    54, 43, 24, 61, 28, 162, 129, 186, 142, 143, 68, 21, 111, 201, 2, 1, 28, 100,
                    9, 155,
                ],
                [
                    146, 14, 206, 165, 134, 212, 219, 48, 189, 180, 56, 123, 93, 112, 95, 220, 61,
                    102, 30, 69,
                ],
                [
                    248, 9, 114, 147, 118, 247, 49, 102, 203, 162, 231, 36, 210, 121, 143, 106, 52,
                    198, 226, 201,
                ],
                [
                    225, 172, 233, 212, 35, 57, 149, 111, 39, 159, 6, 182, 27, 171, 248, 125, 91,
                    245, 77, 210,
                ],
                [
                    240, 63, 96, 94, 209, 115, 20, 7, 73, 16, 39, 101, 113, 229, 127, 224, 24, 249,
                    224, 99,
                ],
                [
                    136, 97, 102, 61, 204, 130, 101, 193, 90, 123, 242, 238, 171, 105, 198, 218,
                    114, 112, 82, 209,
                ],
                [
                    217, 223, 48, 189, 69, 221, 145, 106, 36, 229, 242, 193, 153, 170, 62, 155, 30,
                    216, 248, 213,
                ],
                [
                    75, 244, 1, 136, 73, 131, 112, 36, 163, 218, 153, 4, 187, 159, 180, 58, 54,
                    234, 126, 26,
                ],
                [
                    69, 179, 79, 139, 234, 76, 223, 22, 113, 81, 35, 37, 23, 48, 161, 44, 188, 121,
                    79, 194,
                ],
                [
                    66, 106, 176, 109, 140, 101, 33, 227, 31, 158, 179, 19, 218, 51, 102, 44, 4,
                    209, 63, 149,
                ],
                [
                    230, 44, 217, 170, 241, 244, 185, 203, 123, 122, 68, 10, 78, 197, 110, 217,
                    171, 195, 234, 124,
                ],
                [
                    226, 95, 175, 103, 111, 207, 185, 109, 229, 48, 124, 230, 175, 246, 194, 57,
                    182, 254, 15, 234,
                ],
                [
                    10, 43, 122, 122, 140, 129, 159, 114, 252, 108, 11, 183, 21, 62, 19, 125, 72,
                    150, 180, 124,
                ],
                [
                    91, 61, 192, 8, 216, 53, 150, 43, 243, 252, 181, 170, 95, 193, 112, 26, 151,
                    98, 146, 130,
                ],
                [
                    168, 84, 169, 110, 227, 199, 186, 27, 1, 238, 187, 223, 220, 35, 135, 107, 99,
                    155, 234, 64,
                ],
                [
                    105, 123, 29, 123, 66, 94, 57, 95, 211, 180, 118, 3, 188, 227, 46, 200, 87, 41,
                    24, 32,
                ],
                [
                    80, 213, 193, 213, 101, 165, 132, 255, 112, 193, 63, 54, 252, 234, 26, 131,
                    145, 199, 110, 2,
                ],
                [
                    87, 91, 170, 104, 73, 255, 84, 172, 42, 204, 168, 244, 120, 207, 211, 177, 83,
                    198, 188, 45,
                ],
                [
                    120, 92, 192, 115, 82, 184, 183, 39, 240, 174, 230, 165, 117, 232, 107, 178,
                    245, 161, 99, 171,
                ],
                [
                    135, 222, 6, 210, 11, 28, 133, 110, 145, 189, 195, 38, 53, 141, 98, 104, 126,
                    164, 241, 111,
                ],
                [
                    248, 121, 191, 220, 114, 54, 46, 251, 237, 179, 25, 137, 118, 254, 247, 22, 48,
                    253, 41, 10,
                ],
                [
                    111, 168, 102, 7, 37, 24, 47, 228, 248, 59, 64, 88, 252, 28, 199, 62, 24, 133,
                    233, 123,
                ],
                [
                    138, 173, 57, 46, 121, 124, 143, 108, 209, 43, 124, 129, 139, 57, 23, 250, 112,
                    15, 231, 59,
                ],
                [
                    222, 82, 212, 71, 183, 56, 0, 131, 33, 44, 198, 169, 193, 140, 155, 0, 159, 63,
                    198, 180,
                ],
                [
                    125, 206, 233, 225, 255, 33, 207, 233, 11, 147, 255, 240, 66, 159, 58, 97, 164,
                    110, 85, 250,
                ],
                [
                    214, 51, 221, 204, 242, 77, 212, 252, 208, 118, 5, 65, 39, 97, 127, 48, 106,
                    143, 143, 61,
                ],
                [
                    239, 175, 41, 100, 26, 237, 0, 36, 56, 115, 114, 229, 115, 243, 142, 188, 60,
                    138, 40, 106,
                ],
                [
                    24, 88, 57, 93, 35, 129, 249, 218, 221, 74, 15, 72, 45, 227, 20, 65, 243, 156,
                    205, 91,
                ],
                [
                    62, 203, 90, 143, 28, 53, 193, 215, 56, 106, 58, 207, 195, 178, 189, 91, 54,
                    52, 83, 149,
                ],
                [
                    51, 164, 56, 156, 155, 45, 203, 145, 204, 32, 190, 32, 158, 55, 217, 245, 109,
                    99, 171, 118,
                ],
                [
                    4, 51, 197, 17, 242, 148, 122, 119, 211, 209, 226, 11, 209, 98, 17, 72, 6, 157,
                    80, 18,
                ],
                [
                    164, 204, 130, 155, 39, 53, 100, 184, 149, 144, 139, 81, 171, 100, 108, 60, 84,
                    56, 28, 133,
                ],
                [
                    207, 205, 217, 207, 80, 156, 154, 35, 135, 21, 124, 28, 194, 134, 246, 58, 253,
                    210, 143, 128,
                ],
                [
                    113, 167, 96, 122, 36, 44, 124, 13, 32, 4, 1, 110, 59, 140, 86, 175, 123, 157,
                    197, 121,
                ],
                [
                    230, 210, 69, 245, 75, 248, 53, 250, 162, 120, 191, 132, 26, 89, 163, 179, 15,
                    46, 38, 78,
                ],
                [
                    207, 239, 147, 227, 192, 109, 246, 123, 47, 109, 99, 186, 198, 62, 105, 34, 48,
                    251, 223, 219,
                ],
                [
                    153, 52, 136, 149, 145, 63, 31, 190, 43, 226, 31, 32, 121, 253, 247, 70, 106,
                    21, 214, 169,
                ],
                [
                    235, 45, 130, 233, 27, 116, 221, 140, 53, 44, 190, 242, 244, 17, 89, 23, 116,
                    202, 255, 68,
                ],
                [
                    135, 212, 164, 153, 41, 10, 47, 76, 197, 143, 143, 103, 187, 198, 104, 84, 188,
                    75, 197, 161,
                ],
                [
                    161, 56, 212, 89, 140, 211, 158, 112, 86, 134, 173, 59, 79, 66, 114, 46, 111,
                    3, 178, 58,
                ],
                [
                    193, 236, 141, 236, 192, 213, 9, 134, 102, 144, 251, 102, 196, 159, 18, 165,
                    160, 89, 235, 112,
                ],
                [
                    100, 14, 163, 247, 125, 91, 87, 151, 139, 116, 198, 29, 69, 18, 76, 205, 175,
                    14, 68, 227,
                ],
                [
                    194, 128, 18, 247, 17, 253, 7, 207, 156, 208, 73, 142, 203, 229, 112, 238, 242,
                    142, 66, 158,
                ],
                [
                    68, 104, 138, 215, 132, 20, 127, 164, 81, 101, 98, 44, 107, 160, 166, 19, 32,
                    54, 147, 117,
                ],
                [
                    205, 30, 215, 115, 55, 54, 220, 104, 141, 180, 173, 43, 66, 107, 209, 243, 135,
                    68, 254, 191,
                ],
                [
                    214, 103, 120, 201, 202, 17, 224, 60, 78, 64, 174, 13, 251, 185, 10, 211, 148,
                    148, 35, 15,
                ],
                [
                    116, 163, 197, 119, 184, 128, 170, 81, 82, 251, 222, 53, 122, 13, 226, 245,
                    202, 198, 27, 100,
                ],
                [
                    120, 88, 90, 251, 147, 106, 157, 71, 9, 28, 207, 129, 193, 92, 78, 48, 133,
                    120, 253, 149,
                ],
                [
                    123, 205, 242, 79, 214, 193, 206, 114, 118, 208, 171, 247, 234, 101, 53, 255,
                    197, 190, 30, 114,
                ],
                [
                    182, 5, 234, 152, 36, 239, 249, 29, 232, 30, 248, 245, 223, 188, 23, 45, 239,
                    95, 224, 152,
                ],
                [
                    43, 48, 171, 174, 18, 58, 1, 94, 57, 201, 122, 128, 204, 198, 239, 170, 27, 0,
                    149, 177,
                ],
                [
                    66, 215, 74, 223, 127, 2, 40, 165, 80, 137, 36, 140, 171, 14, 235, 239, 126,
                    202, 174, 202,
                ],
                [
                    103, 205, 130, 107, 117, 176, 10, 252, 0, 62, 54, 57, 3, 248, 4, 50, 188, 58,
                    209, 19,
                ],
                [
                    226, 80, 124, 76, 124, 169, 171, 56, 11, 15, 50, 41, 74, 54, 129, 253, 9, 79,
                    234, 69,
                ],
                [
                    21, 130, 207, 77, 37, 172, 35, 220, 52, 104, 30, 203, 227, 248, 156, 159, 45,
                    96, 38, 112,
                ],
                [
                    201, 94, 60, 164, 146, 169, 1, 7, 211, 211, 2, 26, 205, 110, 24, 224, 145, 14,
                    214, 143,
                ],
                [
                    202, 110, 140, 38, 164, 232, 121, 36, 60, 109, 15, 26, 158, 60, 240, 121, 38,
                    150, 192, 87,
                ],
                [
                    112, 15, 161, 239, 196, 149, 17, 249, 43, 193, 73, 220, 136, 100, 130, 105,
                    185, 41, 162, 110,
                ],
                [
                    223, 82, 6, 83, 31, 15, 169, 202, 214, 103, 179, 26, 236, 172, 5, 34, 54, 0,
                    95, 210,
                ],
                [
                    25, 64, 174, 60, 183, 10, 40, 185, 15, 48, 44, 98, 241, 147, 147, 167, 16, 46,
                    1, 245,
                ],
                [
                    190, 97, 10, 250, 50, 96, 71, 96, 164, 60, 140, 19, 43, 127, 114, 52, 95, 56,
                    131, 214,
                ],
                [
                    84, 35, 74, 198, 147, 22, 82, 4, 112, 187, 159, 79, 152, 103, 16, 41, 234, 199,
                    71, 60,
                ],
                [
                    217, 101, 39, 123, 81, 14, 147, 78, 67, 60, 130, 86, 172, 203, 12, 10, 231,
                    184, 129, 140,
                ],
                [
                    145, 252, 10, 104, 194, 11, 210, 201, 38, 71, 37, 143, 175, 193, 147, 57, 188,
                    111, 2, 228,
                ],
                [
                    88, 12, 135, 40, 20, 232, 56, 33, 115, 229, 46, 12, 214, 157, 54, 159, 48, 153,
                    163, 123,
                ],
                [
                    147, 49, 180, 88, 154, 206, 71, 28, 74, 200, 133, 228, 20, 188, 202, 214, 145,
                    161, 72, 195,
                ],
                [
                    254, 222, 151, 225, 181, 21, 41, 249, 66, 124, 95, 51, 106, 63, 142, 243, 172,
                    11, 46, 84,
                ],
                [
                    210, 237, 53, 142, 207, 108, 240, 234, 108, 167, 215, 132, 38, 14, 103, 63, 18,
                    160, 35, 146,
                ],
                [
                    249, 102, 32, 21, 192, 243, 92, 244, 234, 188, 140, 205, 179, 194, 45, 80, 40,
                    35, 77, 251,
                ],
                [
                    106, 216, 16, 63, 70, 120, 4, 165, 39, 251, 155, 24, 35, 191, 194, 249, 103,
                    144, 188, 17,
                ],
                [
                    9, 82, 122, 94, 251, 119, 170, 119, 3, 121, 19, 158, 38, 3, 181, 158, 92, 69,
                    92, 168,
                ],
                [
                    47, 152, 29, 118, 156, 36, 43, 223, 170, 6, 50, 198, 170, 12, 127, 102, 37,
                    111, 79, 124,
                ],
                [
                    33, 93, 120, 248, 84, 50, 24, 199, 242, 146, 205, 206, 64, 102, 128, 103, 84,
                    11, 250, 254,
                ],
                [
                    217, 60, 223, 247, 44, 23, 164, 183, 254, 123, 54, 105, 223, 28, 1, 186, 208,
                    205, 227, 27,
                ],
                [
                    224, 103, 2, 165, 14, 246, 78, 101, 72, 65, 65, 159, 24, 109, 146, 193, 52,
                    111, 83, 204,
                ],
                [
                    211, 9, 204, 166, 22, 155, 70, 116, 85, 217, 175, 255, 126, 155, 142, 110, 7,
                    248, 186, 158,
                ],
                [
                    229, 172, 38, 83, 82, 142, 220, 133, 53, 156, 44, 121, 215, 146, 89, 41, 147,
                    23, 131, 31,
                ],
                [
                    251, 71, 73, 58, 252, 58, 53, 175, 91, 249, 39, 117, 237, 193, 188, 18, 208,
                    206, 92, 135,
                ],
                [
                    106, 27, 213, 94, 245, 105, 62, 138, 148, 154, 238, 29, 60, 22, 244, 214, 64,
                    133, 54, 206,
                ],
                [
                    245, 249, 15, 14, 181, 117, 170, 13, 238, 105, 55, 200, 65, 187, 192, 148, 100,
                    202, 192, 213,
                ],
                [
                    214, 29, 95, 165, 20, 129, 55, 231, 138, 95, 30, 240, 142, 124, 60, 29, 6, 83,
                    115, 159,
                ],
                [
                    14, 21, 247, 181, 242, 228, 15, 214, 136, 25, 182, 103, 22, 177, 189, 70, 70,
                    112, 229, 243,
                ],
                [
                    250, 207, 155, 66, 137, 203, 192, 206, 151, 84, 11, 221, 91, 242, 44, 15, 237,
                    134, 107, 183,
                ],
                [
                    73, 168, 112, 149, 154, 32, 28, 94, 140, 236, 170, 211, 151, 45, 48, 135, 156,
                    208, 35, 54,
                ],
                [
                    95, 79, 14, 19, 128, 31, 68, 142, 213, 207, 19, 116, 28, 168, 68, 206, 108, 66,
                    117, 196,
                ],
                [
                    243, 141, 161, 86, 6, 241, 106, 146, 24, 160, 182, 102, 152, 222, 247, 80, 18,
                    212, 10, 124,
                ],
                [
                    88, 206, 29, 182, 80, 165, 204, 216, 166, 79, 136, 104, 207, 31, 102, 176, 233,
                    65, 90, 243,
                ],
                [
                    243, 129, 229, 119, 209, 238, 123, 146, 83, 222, 141, 239, 131, 8, 223, 226,
                    227, 51, 135, 158,
                ],
                [
                    89, 5, 51, 71, 143, 2, 111, 99, 210, 91, 213, 27, 15, 202, 131, 114, 89, 249,
                    234, 152,
                ],
                [
                    45, 47, 8, 153, 122, 123, 131, 219, 240, 169, 169, 255, 13, 93, 198, 92, 51,
                    104, 205, 48,
                ],
                [
                    70, 189, 137, 158, 9, 81, 75, 74, 69, 208, 196, 194, 251, 148, 108, 70, 206,
                    15, 50, 204,
                ],
                [
                    98, 253, 197, 31, 189, 155, 158, 26, 64, 2, 33, 152, 254, 145, 47, 21, 253,
                    104, 37, 26,
                ],
                [
                    49, 70, 123, 177, 239, 43, 61, 32, 15, 219, 176, 21, 250, 23, 232, 62, 156,
                    121, 91, 10,
                ],
                [
                    144, 250, 184, 151, 197, 246, 114, 153, 69, 245, 126, 15, 17, 21, 193, 34, 146,
                    227, 21, 157,
                ],
                [
                    115, 123, 120, 1, 138, 252, 104, 169, 218, 151, 224, 239, 121, 232, 50, 129,
                    221, 143, 185, 149,
                ],
                [
                    233, 197, 64, 24, 113, 61, 132, 127, 56, 139, 156, 240, 133, 7, 232, 62, 159,
                    179, 217, 89,
                ],
                [
                    88, 123, 77, 65, 97, 80, 24, 218, 143, 106, 174, 119, 91, 126, 134, 93, 102,
                    125, 95, 25,
                ],
                [
                    199, 175, 32, 239, 236, 120, 177, 192, 147, 176, 31, 86, 227, 134, 212, 249,
                    22, 19, 223, 182,
                ],
                [
                    145, 61, 130, 182, 139, 69, 251, 76, 29, 182, 51, 178, 170, 105, 127, 157, 18,
                    218, 16, 82,
                ],
                [
                    142, 40, 26, 8, 147, 193, 180, 138, 98, 59, 37, 161, 199, 90, 125, 7, 193, 172,
                    92, 114,
                ],
                [
                    246, 83, 231, 143, 178, 12, 36, 115, 18, 88, 80, 9, 57, 128, 183, 150, 182,
                    238, 65, 255,
                ],
                [
                    4, 147, 161, 211, 251, 239, 126, 243, 179, 104, 172, 159, 179, 109, 116, 214,
                    176, 72, 238, 64,
                ],
                [
                    20, 249, 184, 144, 142, 20, 124, 21, 28, 85, 147, 173, 155, 184, 12, 149, 233,
                    152, 126, 221,
                ],
                [
                    150, 119, 152, 182, 92, 141, 112, 221, 204, 230, 198, 224, 1, 76, 192, 74, 15,
                    9, 85, 87,
                ],
                [
                    113, 44, 117, 86, 121, 21, 25, 232, 18, 34, 67, 176, 37, 60, 33, 158, 209, 152,
                    120, 61,
                ],
                [
                    242, 67, 4, 174, 216, 62, 146, 0, 148, 64, 247, 185, 100, 253, 90, 136, 7, 57,
                    22, 49,
                ],
                [
                    228, 252, 229, 96, 135, 121, 8, 235, 126, 129, 47, 12, 121, 230, 191, 117, 193,
                    220, 161, 106,
                ],
                [
                    137, 218, 170, 167, 88, 12, 191, 91, 107, 33, 207, 230, 170, 7, 49, 48, 24,
                    171, 83, 207,
                ],
                [
                    95, 254, 120, 179, 120, 16, 212, 178, 53, 152, 118, 118, 220, 5, 109, 46, 41,
                    58, 251, 18,
                ],
                [
                    68, 93, 63, 62, 95, 8, 43, 239, 71, 251, 175, 38, 120, 122, 160, 142, 200, 159,
                    163, 168,
                ],
                [
                    54, 115, 203, 165, 223, 158, 144, 201, 51, 230, 147, 107, 230, 108, 11, 176,
                    221, 242, 36, 122,
                ],
                [
                    239, 126, 188, 178, 123, 238, 102, 76, 30, 64, 81, 53, 201, 119, 174, 4, 114,
                    86, 83, 46,
                ],
                [
                    204, 17, 133, 213, 159, 3, 64, 212, 97, 66, 250, 93, 235, 168, 145, 58, 71, 99,
                    15, 94,
                ],
                [
                    105, 193, 250, 165, 111, 255, 17, 142, 23, 21, 158, 175, 165, 118, 60, 115, 3,
                    71, 141, 205,
                ],
                [
                    24, 226, 33, 230, 172, 20, 59, 204, 68, 124, 165, 7, 123, 119, 32, 28, 118, 57,
                    206, 73,
                ],
                [
                    146, 176, 13, 96, 204, 117, 241, 177, 22, 156, 73, 133, 207, 201, 64, 175, 224,
                    224, 127, 84,
                ],
                [
                    48, 109, 124, 211, 53, 117, 122, 235, 205, 234, 76, 49, 167, 100, 149, 232,
                    160, 211, 91, 176,
                ],
                [
                    118, 216, 255, 67, 114, 126, 104, 123, 132, 102, 205, 237, 60, 56, 56, 170,
                    246, 190, 148, 69,
                ],
                [
                    29, 4, 73, 169, 169, 253, 18, 46, 103, 138, 14, 81, 63, 84, 214, 89, 230, 224,
                    214, 6,
                ],
                [
                    170, 182, 247, 153, 214, 61, 65, 222, 81, 163, 185, 253, 111, 120, 99, 194, 41,
                    152, 209, 40,
                ],
                [
                    64, 235, 96, 93, 174, 99, 249, 29, 138, 116, 84, 42, 47, 248, 145, 173, 98,
                    189, 144, 215,
                ],
                [
                    187, 14, 254, 142, 90, 218, 234, 91, 16, 216, 213, 19, 158, 244, 37, 231, 225,
                    6, 11, 45,
                ],
                [
                    28, 161, 72, 145, 178, 75, 234, 223, 39, 94, 246, 175, 62, 35, 36, 234, 184,
                    227, 190, 38,
                ],
                [
                    213, 154, 175, 170, 73, 77, 211, 188, 185, 217, 242, 42, 221, 186, 96, 41, 71,
                    192, 138, 195,
                ],
                [
                    123, 11, 211, 39, 146, 15, 146, 179, 141, 219, 231, 46, 105, 50, 2, 247, 10,
                    202, 20, 236,
                ],
                [
                    172, 39, 71, 237, 205, 48, 23, 221, 152, 206, 126, 91, 237, 234, 168, 120, 11,
                    61, 47, 4,
                ],
                [
                    85, 205, 218, 55, 163, 116, 214, 70, 140, 5, 91, 42, 0, 236, 113, 109, 75, 197,
                    151, 160,
                ],
                [
                    104, 238, 71, 110, 75, 113, 106, 243, 104, 248, 206, 37, 160, 17, 79, 32, 27,
                    169, 219, 231,
                ],
                [
                    193, 146, 59, 32, 29, 243, 39, 176, 219, 40, 33, 154, 94, 248, 46, 72, 52, 53,
                    145, 174,
                ],
                [
                    43, 162, 62, 9, 146, 197, 225, 197, 129, 6, 238, 192, 87, 182, 94, 135, 175,
                    210, 53, 221,
                ],
                [
                    246, 70, 78, 194, 139, 181, 132, 19, 69, 50, 246, 25, 35, 72, 63, 66, 217, 195,
                    246, 128,
                ],
                [
                    176, 141, 32, 10, 187, 253, 72, 77, 2, 27, 158, 221, 204, 92, 231, 192, 145,
                    154, 95, 11,
                ],
                [
                    61, 110, 174, 148, 36, 155, 126, 152, 152, 83, 165, 19, 237, 188, 59, 46, 103,
                    106, 92, 92,
                ],
                [
                    97, 129, 112, 98, 124, 216, 18, 213, 0, 48, 21, 121, 73, 236, 67, 44, 76, 243,
                    103, 152,
                ],
                [
                    156, 92, 92, 145, 111, 8, 168, 197, 232, 181, 162, 236, 84, 23, 65, 189, 84,
                    28, 221, 141,
                ],
                [
                    56, 95, 230, 29, 230, 57, 48, 241, 69, 161, 117, 199, 166, 127, 240, 107, 226,
                    108, 50, 205,
                ],
                [
                    195, 211, 137, 21, 197, 111, 76, 76, 119, 105, 114, 150, 250, 141, 116, 1, 63,
                    216, 63, 8,
                ],
                [
                    37, 180, 140, 155, 29, 188, 190, 1, 255, 58, 24, 88, 126, 70, 248, 96, 167,
                    108, 141, 215,
                ],
                [
                    253, 129, 192, 106, 129, 184, 192, 179, 174, 38, 60, 116, 114, 36, 136, 36,
                    184, 81, 177, 128,
                ],
                [
                    217, 94, 182, 98, 107, 72, 195, 243, 180, 89, 214, 160, 153, 72, 68, 252, 202,
                    228, 118, 33,
                ],
                [
                    155, 162, 225, 182, 4, 137, 120, 43, 214, 95, 205, 129, 138, 241, 32, 172, 235,
                    171, 117, 219,
                ],
                [
                    85, 64, 226, 13, 106, 91, 227, 239, 228, 68, 86, 167, 153, 108, 91, 53, 76, 51,
                    59, 115,
                ],
                [
                    225, 246, 5, 0, 231, 148, 198, 58, 65, 31, 44, 183, 123, 128, 10, 108, 88, 179,
                    123, 177,
                ],
                [
                    229, 240, 75, 38, 86, 231, 151, 127, 87, 125, 101, 72, 128, 176, 205, 69, 165,
                    13, 116, 39,
                ],
                [
                    80, 219, 200, 112, 67, 103, 80, 70, 145, 228, 216, 100, 241, 24, 182, 119, 8,
                    59, 112, 206,
                ],
                [
                    131, 43, 173, 23, 224, 137, 110, 246, 171, 150, 252, 69, 74, 46, 184, 119, 61,
                    181, 53, 151,
                ],
                [
                    127, 154, 77, 78, 128, 254, 99, 163, 199, 242, 95, 50, 128, 109, 164, 100, 76,
                    193, 216, 77,
                ],
                [
                    229, 18, 249, 161, 59, 131, 141, 91, 43, 96, 148, 242, 149, 223, 61, 117, 133,
                    145, 242, 205,
                ],
                [
                    167, 95, 245, 154, 167, 229, 63, 162, 115, 122, 49, 62, 162, 93, 157, 41, 211,
                    92, 195, 21,
                ],
                [
                    233, 130, 112, 13, 250, 66, 5, 134, 175, 177, 240, 183, 223, 34, 135, 174, 185,
                    5, 102, 195,
                ],
                [
                    43, 27, 226, 124, 207, 66, 38, 197, 9, 253, 199, 81, 234, 9, 58, 209, 110, 115,
                    140, 72,
                ],
                [
                    195, 154, 91, 93, 174, 188, 6, 145, 135, 184, 26, 19, 8, 146, 113, 186, 61,
                    224, 39, 88,
                ],
                [
                    253, 95, 233, 3, 238, 242, 185, 26, 48, 193, 129, 95, 107, 52, 69, 4, 35, 225,
                    199, 100,
                ],
                [
                    77, 204, 54, 238, 218, 69, 41, 201, 155, 99, 87, 66, 173, 7, 53, 51, 173, 121,
                    53, 2,
                ],
                [
                    163, 108, 113, 49, 105, 162, 213, 124, 80, 174, 221, 181, 215, 255, 135, 19,
                    62, 36, 141, 187,
                ],
                [
                    143, 13, 146, 198, 178, 110, 125, 78, 166, 39, 95, 162, 243, 242, 90, 129, 11,
                    29, 26, 128,
                ],
                [
                    21, 23, 176, 87, 151, 165, 112, 131, 133, 72, 27, 148, 10, 109, 216, 113, 150,
                    90, 71, 127,
                ],
                [
                    155, 3, 158, 136, 186, 32, 49, 114, 185, 73, 151, 73, 19, 165, 177, 0, 16, 211,
                    71, 145,
                ],
                [
                    223, 218, 16, 157, 93, 39, 72, 36, 217, 62, 98, 70, 61, 87, 207, 112, 222, 255,
                    130, 76,
                ],
                [
                    55, 186, 71, 181, 181, 168, 135, 205, 10, 159, 18, 79, 214, 198, 161, 145, 34,
                    122, 192, 51,
                ],
                [
                    224, 43, 197, 147, 122, 138, 178, 53, 156, 205, 9, 13, 170, 106, 215, 133, 50,
                    58, 33, 148,
                ],
                [
                    113, 19, 166, 104, 22, 72, 105, 247, 38, 210, 65, 118, 64, 19, 9, 159, 99, 23,
                    229, 86,
                ],
                [
                    254, 193, 4, 68, 235, 148, 176, 237, 223, 216, 57, 5, 70, 122, 0, 36, 102, 126,
                    70, 131,
                ],
                [
                    27, 254, 151, 161, 84, 208, 87, 10, 242, 199, 178, 159, 171, 147, 42, 144, 210,
                    142, 245, 240,
                ],
                [
                    140, 126, 120, 233, 25, 172, 63, 123, 177, 80, 55, 23, 86, 119, 174, 198, 85,
                    84, 36, 197,
                ],
                [
                    8, 40, 228, 90, 156, 15, 4, 218, 169, 38, 48, 226, 80, 241, 16, 159, 77, 25,
                    82, 53,
                ],
                [
                    94, 220, 233, 159, 199, 15, 165, 191, 95, 48, 61, 209, 96, 142, 103, 128, 141,
                    240, 110, 65,
                ],
                [
                    202, 0, 22, 159, 239, 36, 216, 164, 152, 80, 15, 229, 188, 252, 10, 228, 3, 97,
                    78, 119,
                ],
                [
                    198, 53, 185, 123, 68, 43, 169, 109, 6, 190, 74, 62, 239, 28, 86, 120, 20, 97,
                    53, 142,
                ],
                [
                    38, 48, 254, 100, 39, 14, 16, 69, 119, 38, 168, 193, 17, 243, 226, 120, 21,
                    157, 151, 219,
                ],
                [
                    41, 179, 132, 40, 108, 129, 108, 31, 49, 70, 38, 169, 58, 99, 53, 120, 201,
                    247, 150, 91,
                ],
                [
                    1, 113, 177, 167, 146, 107, 247, 168, 116, 18, 215, 78, 203, 31, 73, 35, 94,
                    16, 129, 252,
                ],
                [
                    49, 52, 168, 221, 250, 26, 138, 141, 192, 19, 6, 211, 49, 53, 238, 42, 145, 78,
                    111, 49,
                ],
                [
                    33, 200, 32, 165, 242, 236, 19, 14, 44, 12, 96, 11, 59, 252, 216, 206, 207, 8,
                    45, 61,
                ],
                [
                    219, 65, 39, 124, 160, 191, 153, 188, 233, 237, 52, 217, 40, 66, 60, 176, 120,
                    141, 42, 79,
                ],
                [
                    76, 14, 72, 8, 240, 201, 230, 47, 90, 132, 31, 160, 58, 166, 128, 108, 54, 231,
                    131, 106,
                ],
                [
                    39, 194, 231, 127, 145, 183, 59, 121, 114, 79, 172, 89, 23, 201, 0, 4, 22, 212,
                    236, 152,
                ],
                [
                    167, 253, 196, 232, 124, 144, 11, 185, 169, 194, 60, 89, 146, 13, 86, 180, 193,
                    120, 77, 186,
                ],
                [
                    46, 200, 33, 188, 142, 216, 147, 60, 189, 76, 92, 248, 142, 255, 46, 210, 113,
                    173, 248, 130,
                ],
                [
                    123, 214, 238, 50, 145, 37, 161, 251, 209, 54, 69, 15, 119, 127, 135, 168, 2,
                    103, 24, 89,
                ],
                [
                    19, 215, 21, 152, 47, 244, 168, 0, 252, 207, 166, 182, 248, 181, 37, 83, 117,
                    17, 110, 52,
                ],
                [
                    183, 41, 234, 205, 251, 127, 202, 77, 247, 86, 237, 213, 219, 17, 140, 97, 6,
                    127, 70, 176,
                ],
                [
                    112, 137, 218, 140, 171, 45, 78, 122, 73, 73, 193, 84, 251, 192, 155, 80, 117,
                    247, 219, 103,
                ],
                [
                    153, 48, 27, 175, 215, 172, 153, 97, 118, 222, 8, 201, 25, 112, 185, 204, 201,
                    73, 57, 112,
                ],
                [
                    34, 197, 138, 28, 107, 250, 146, 180, 89, 55, 7, 163, 140, 64, 205, 142, 146,
                    103, 223, 35,
                ],
                [
                    127, 121, 120, 4, 75, 251, 233, 132, 78, 6, 30, 75, 175, 202, 63, 136, 175, 24,
                    12, 118,
                ],
                [
                    105, 92, 194, 38, 125, 217, 118, 175, 13, 148, 210, 208, 219, 69, 129, 231, 71,
                    99, 18, 23,
                ],
                [
                    121, 134, 251, 210, 25, 254, 226, 195, 61, 186, 62, 32, 152, 182, 100, 150, 13,
                    60, 179, 16,
                ],
                [
                    186, 190, 121, 28, 151, 57, 130, 153, 248, 94, 132, 128, 106, 178, 142, 81,
                    181, 107, 66, 96,
                ],
                [
                    211, 69, 76, 101, 132, 148, 208, 220, 51, 225, 197, 26, 17, 194, 60, 117, 183,
                    27, 64, 193,
                ],
                [
                    251, 54, 198, 116, 8, 16, 224, 172, 203, 91, 51, 186, 241, 61, 83, 158, 28, 98,
                    131, 231,
                ],
                [
                    101, 9, 252, 51, 213, 104, 243, 237, 108, 223, 147, 13, 224, 10, 120, 25, 36,
                    101, 248, 73,
                ],
                [
                    142, 77, 18, 115, 168, 249, 176, 48, 104, 14, 110, 109, 128, 21, 37, 199, 81,
                    220, 163, 61,
                ],
                [
                    217, 215, 45, 94, 197, 219, 77, 243, 66, 78, 65, 1, 178, 207, 129, 10, 77, 141,
                    5, 102,
                ],
                [
                    156, 150, 3, 41, 75, 180, 140, 49, 23, 53, 122, 160, 143, 215, 87, 22, 135,
                    224, 166, 126,
                ],
                [
                    175, 236, 186, 157, 160, 151, 206, 63, 74, 183, 46, 65, 7, 74, 70, 225, 7, 131,
                    12, 55,
                ],
                [
                    122, 190, 68, 129, 210, 223, 52, 73, 161, 77, 61, 104, 226, 151, 197, 105, 159,
                    0, 101, 24,
                ],
                [
                    210, 221, 86, 90, 89, 104, 163, 217, 151, 33, 176, 115, 231, 173, 21, 226, 182,
                    141, 176, 16,
                ],
                [
                    192, 210, 39, 217, 144, 43, 115, 72, 39, 5, 38, 101, 56, 44, 51, 177, 11, 65,
                    176, 166,
                ],
                [
                    90, 86, 255, 173, 13, 165, 40, 230, 71, 37, 51, 75, 50, 220, 28, 201, 46, 206,
                    137, 156,
                ],
                [
                    11, 181, 8, 200, 115, 90, 186, 68, 35, 221, 181, 47, 18, 55, 192, 237, 149, 54,
                    114, 172,
                ],
                [
                    155, 205, 70, 9, 168, 195, 230, 56, 181, 243, 233, 172, 224, 81, 194, 8, 13,
                    55, 39, 252,
                ],
                [
                    59, 238, 213, 105, 222, 37, 52, 224, 116, 61, 125, 66, 32, 237, 244, 198, 99,
                    248, 26, 55,
                ],
                [
                    145, 232, 22, 26, 6, 30, 91, 13, 72, 24, 108, 106, 66, 240, 234, 193, 151, 8,
                    98, 178,
                ],
                [
                    125, 100, 75, 9, 240, 125, 96, 91, 152, 59, 17, 206, 244, 255, 170, 125, 18,
                    127, 122, 183,
                ],
                [
                    207, 131, 128, 236, 168, 219, 41, 54, 106, 37, 140, 59, 58, 137, 119, 40, 2,
                    22, 248, 207,
                ],
                [
                    159, 179, 119, 178, 7, 5, 247, 91, 240, 43, 114, 154, 36, 7, 211, 169, 237, 53,
                    196, 245,
                ],
                [
                    58, 88, 244, 198, 1, 210, 32, 73, 97, 43, 145, 67, 14, 114, 95, 127, 230, 219,
                    204, 96,
                ],
                [
                    194, 170, 149, 52, 232, 197, 92, 45, 174, 104, 11, 97, 174, 54, 0, 113, 110,
                    10, 86, 108,
                ],
                [
                    253, 233, 34, 118, 115, 240, 90, 248, 33, 210, 7, 104, 41, 65, 219, 73, 31,
                    111, 149, 71,
                ],
                [
                    125, 145, 242, 117, 106, 153, 67, 147, 27, 88, 252, 113, 204, 218, 222, 22, 85,
                    211, 103, 206,
                ],
                [
                    217, 248, 128, 200, 18, 248, 58, 167, 202, 150, 181, 126, 110, 60, 22, 128, 87,
                    181, 20, 207,
                ],
                [
                    147, 27, 141, 29, 207, 11, 190, 140, 140, 225, 152, 208, 197, 152, 192, 248,
                    198, 150, 102, 158,
                ],
                [
                    197, 105, 136, 88, 0, 203, 146, 206, 19, 74, 83, 168, 34, 127, 117, 182, 164,
                    211, 90, 110,
                ],
                [
                    158, 53, 84, 116, 78, 36, 51, 216, 35, 221, 154, 24, 214, 237, 173, 94, 25, 50,
                    73, 114,
                ],
                [
                    234, 217, 32, 167, 76, 61, 128, 10, 90, 84, 141, 212, 62, 116, 146, 204, 225,
                    124, 45, 158,
                ],
                [
                    40, 133, 152, 30, 5, 155, 34, 47, 211, 172, 52, 140, 107, 176, 65, 133, 50, 47,
                    67, 91,
                ],
                [
                    206, 149, 219, 92, 35, 31, 54, 13, 107, 243, 252, 52, 134, 40, 104, 251, 14,
                    16, 87, 25,
                ],
                [
                    232, 12, 254, 97, 151, 26, 116, 64, 10, 69, 237, 159, 40, 253, 231, 88, 38,
                    169, 251, 194,
                ],
                [
                    125, 165, 162, 130, 3, 111, 26, 166, 38, 180, 107, 136, 128, 54, 57, 233, 34,
                    20, 246, 27,
                ],
                [
                    151, 232, 63, 36, 80, 94, 171, 49, 114, 238, 15, 78, 127, 56, 101, 175, 49,
                    203, 132, 185,
                ],
                [
                    8, 222, 83, 83, 21, 168, 78, 158, 212, 37, 54, 135, 89, 124, 59, 70, 5, 156,
                    235, 153,
                ],
                [
                    232, 57, 196, 235, 147, 213, 160, 21, 79, 158, 65, 139, 220, 97, 72, 12, 171,
                    185, 90, 165,
                ],
                [
                    70, 186, 67, 207, 142, 155, 75, 172, 199, 31, 21, 113, 155, 100, 226, 16, 200,
                    9, 20, 254,
                ],
                [
                    193, 1, 92, 121, 229, 34, 232, 175, 113, 19, 167, 222, 74, 136, 97, 221, 8,
                    194, 167, 188,
                ],
                [
                    223, 132, 190, 165, 178, 68, 9, 17, 31, 166, 163, 255, 69, 187, 47, 138, 31,
                    148, 148, 154,
                ],
                [
                    166, 238, 29, 211, 75, 140, 167, 150, 22, 17, 179, 11, 148, 89, 226, 124, 169,
                    55, 137, 71,
                ],
                [
                    68, 114, 30, 231, 87, 178, 29, 38, 192, 165, 107, 249, 230, 55, 38, 49, 91,
                    138, 149, 142,
                ],
                [
                    65, 208, 179, 114, 135, 20, 118, 175, 214, 55, 16, 0, 123, 250, 181, 59, 231,
                    176, 103, 120,
                ],
                [
                    88, 83, 222, 151, 157, 78, 213, 0, 103, 254, 197, 73, 30, 231, 72, 72, 132,
                    171, 59, 21,
                ],
                [
                    25, 250, 241, 224, 227, 192, 67, 100, 4, 101, 115, 56, 214, 72, 164, 100, 183,
                    128, 85, 167,
                ],
                [
                    56, 26, 31, 10, 172, 91, 40, 196, 78, 90, 239, 63, 99, 246, 115, 236, 69, 91,
                    29, 72,
                ],
                [
                    110, 241, 134, 97, 170, 33, 181, 132, 163, 87, 245, 155, 243, 229, 97, 131, 32,
                    74, 228, 157,
                ],
                [
                    135, 131, 182, 59, 150, 232, 235, 37, 233, 83, 153, 234, 15, 8, 13, 197, 6, 33,
                    32, 105,
                ],
                [
                    68, 216, 82, 49, 98, 0, 216, 245, 189, 242, 43, 59, 129, 100, 216, 126, 255,
                    133, 187, 90,
                ],
                [
                    216, 231, 149, 249, 118, 57, 53, 80, 225, 141, 49, 248, 229, 225, 25, 122, 42,
                    213, 56, 241,
                ],
                [
                    191, 116, 44, 229, 36, 252, 171, 37, 252, 55, 167, 229, 163, 251, 14, 25, 238,
                    221, 173, 153,
                ],
                [
                    173, 90, 61, 254, 60, 43, 33, 93, 247, 53, 50, 145, 222, 24, 173, 73, 222, 177,
                    22, 78,
                ],
                [
                    189, 22, 10, 197, 19, 28, 70, 212, 80, 215, 84, 41, 90, 57, 113, 116, 193, 118,
                    229, 24,
                ],
                [
                    25, 40, 161, 251, 223, 159, 215, 132, 145, 200, 200, 96, 10, 67, 244, 48, 65,
                    242, 21, 167,
                ],
                [
                    243, 157, 237, 21, 39, 177, 184, 15, 181, 148, 186, 109, 247, 30, 255, 0, 182,
                    254, 49, 184,
                ],
                [
                    219, 173, 254, 74, 65, 12, 197, 146, 189, 89, 21, 47, 231, 142, 232, 2, 85,
                    102, 198, 67,
                ],
                [
                    190, 173, 108, 152, 190, 162, 114, 89, 161, 77, 223, 177, 78, 212, 218, 226,
                    237, 142, 172, 145,
                ],
                [
                    183, 75, 212, 24, 38, 105, 80, 51, 40, 168, 93, 81, 168, 151, 77, 31, 247, 65,
                    143, 13,
                ],
                [
                    165, 113, 200, 155, 228, 238, 47, 180, 63, 181, 2, 253, 86, 58, 183, 79, 59,
                    41, 166, 195,
                ],
                [
                    145, 103, 227, 79, 122, 233, 18, 161, 189, 219, 222, 81, 41, 143, 80, 59, 247,
                    204, 15, 24,
                ],
                [
                    121, 171, 137, 232, 170, 157, 221, 118, 129, 220, 37, 129, 126, 65, 144, 164,
                    25, 51, 220, 70,
                ],
                [
                    214, 223, 62, 26, 40, 49, 48, 246, 35, 143, 227, 17, 131, 21, 44, 156, 207, 94,
                    228, 179,
                ],
                [
                    27, 109, 169, 5, 8, 111, 120, 236, 148, 177, 106, 167, 136, 146, 167, 148, 202,
                    141, 56, 238,
                ],
                [
                    146, 175, 51, 225, 229, 76, 221, 254, 22, 211, 60, 229, 117, 142, 113, 190,
                    236, 196, 134, 253,
                ],
                [
                    112, 91, 152, 91, 197, 6, 67, 40, 251, 35, 245, 39, 54, 125, 109, 204, 117,
                    159, 115, 43,
                ],
                [
                    203, 245, 193, 102, 96, 159, 220, 43, 96, 41, 18, 175, 242, 200, 201, 20, 187,
                    56, 45, 5,
                ],
                [
                    8, 237, 171, 126, 160, 124, 135, 93, 63, 214, 15, 161, 106, 19, 68, 252, 78,
                    227, 220, 234,
                ],
                [
                    66, 15, 43, 114, 64, 1, 108, 113, 49, 183, 252, 29, 157, 232, 198, 110, 114,
                    35, 255, 227,
                ],
                [
                    251, 68, 110, 138, 164, 34, 82, 182, 225, 126, 143, 87, 0, 175, 123, 47, 92,
                    62, 88, 105,
                ],
                [
                    95, 55, 9, 65, 127, 107, 235, 253, 253, 107, 211, 75, 81, 236, 173, 63, 179,
                    41, 227, 53,
                ],
                [
                    65, 9, 81, 119, 208, 75, 31, 184, 149, 243, 37, 148, 155, 223, 57, 170, 222,
                    87, 78, 101,
                ],
                [
                    57, 149, 152, 26, 127, 223, 14, 97, 7, 202, 217, 73, 31, 140, 3, 90, 78, 127,
                    94, 41,
                ],
                [
                    145, 202, 2, 178, 10, 249, 200, 70, 61, 43, 181, 20, 233, 216, 52, 108, 161,
                    164, 249, 2,
                ],
                [
                    80, 97, 144, 144, 240, 89, 160, 132, 52, 149, 73, 199, 180, 209, 148, 167, 226,
                    213, 179, 149,
                ],
                [
                    93, 240, 150, 253, 17, 158, 158, 128, 42, 195, 207, 120, 93, 107, 43, 87, 131,
                    166, 238, 1,
                ],
                [
                    45, 7, 104, 234, 48, 116, 19, 147, 216, 37, 149, 166, 153, 252, 85, 76, 178,
                    75, 49, 202,
                ],
                [
                    221, 195, 138, 166, 26, 28, 245, 173, 223, 74, 110, 108, 146, 226, 141, 203,
                    28, 46, 109, 155,
                ],
                [
                    148, 199, 152, 182, 251, 36, 49, 168, 156, 145, 231, 249, 140, 185, 201, 186,
                    98, 119, 141, 175,
                ],
                [
                    6, 169, 232, 200, 225, 205, 113, 24, 194, 192, 26, 125, 218, 62, 71, 88, 35,
                    161, 230, 213,
                ],
                [
                    53, 114, 185, 1, 242, 233, 107, 64, 120, 214, 105, 51, 47, 52, 203, 198, 92,
                    198, 101, 232,
                ],
                [
                    4, 33, 15, 134, 184, 47, 53, 152, 109, 98, 38, 149, 38, 44, 218, 178, 92, 96,
                    83, 162,
                ],
                [
                    50, 165, 162, 103, 112, 43, 101, 202, 229, 208, 166, 101, 119, 204, 156, 190,
                    239, 228, 231, 249,
                ],
                [
                    95, 163, 178, 164, 128, 209, 218, 55, 235, 72, 215, 207, 100, 139, 223, 155,
                    65, 250, 54, 9,
                ],
                [
                    154, 42, 134, 184, 38, 17, 130, 153, 138, 120, 93, 238, 217, 243, 43, 55, 101,
                    10, 189, 192,
                ],
                [
                    237, 94, 50, 77, 15, 71, 97, 119, 119, 154, 0, 143, 14, 176, 55, 90, 188, 14,
                    225, 151,
                ],
                [
                    64, 175, 226, 135, 253, 1, 220, 154, 91, 12, 117, 222, 190, 231, 55, 168, 19,
                    127, 135, 103,
                ],
                [
                    132, 131, 189, 184, 41, 221, 137, 26, 95, 210, 244, 81, 211, 204, 117, 116,
                    228, 214, 168, 43,
                ],
                [
                    151, 70, 28, 223, 146, 186, 78, 66, 242, 72, 141, 119, 203, 130, 240, 108, 60,
                    24, 189, 1,
                ],
                [
                    52, 144, 114, 5, 135, 55, 4, 81, 220, 171, 183, 141, 239, 255, 111, 156, 182,
                    207, 235, 177,
                ],
                [
                    223, 56, 54, 204, 181, 94, 106, 226, 212, 140, 78, 23, 151, 20, 44, 72, 0, 1,
                    159, 117,
                ],
                [
                    156, 94, 200, 32, 58, 211, 224, 169, 43, 0, 208, 40, 208, 171, 78, 193, 39, 90,
                    67, 143,
                ],
                [
                    108, 86, 56, 81, 68, 42, 82, 30, 134, 236, 241, 174, 250, 18, 160, 181, 63, 1,
                    73, 98,
                ],
                [
                    16, 20, 131, 189, 69, 244, 249, 196, 146, 126, 62, 89, 181, 35, 239, 85, 195,
                    205, 141, 204,
                ],
                [
                    221, 198, 168, 193, 223, 91, 25, 143, 34, 172, 249, 230, 110, 126, 117, 178,
                    221, 56, 3, 203,
                ],
                [
                    215, 224, 43, 10, 47, 20, 114, 252, 117, 214, 67, 247, 124, 197, 174, 207, 2,
                    138, 50, 238,
                ],
                [
                    240, 9, 94, 99, 26, 251, 67, 20, 217, 118, 102, 19, 239, 182, 67, 77, 24, 70,
                    96, 42,
                ],
                [
                    166, 157, 101, 132, 198, 44, 223, 72, 0, 77, 59, 23, 197, 178, 242, 49, 21,
                    192, 255, 52,
                ],
                [
                    250, 177, 230, 174, 136, 210, 210, 41, 70, 53, 238, 177, 219, 30, 202, 0, 129,
                    148, 206, 146,
                ],
                [
                    181, 31, 94, 238, 112, 211, 253, 176, 15, 109, 155, 2, 254, 219, 43, 164, 48,
                    11, 243, 94,
                ],
                [
                    132, 172, 23, 25, 17, 191, 44, 213, 206, 69, 206, 156, 175, 114, 201, 111, 166,
                    182, 222, 40,
                ],
                [
                    8, 123, 70, 69, 82, 33, 226, 71, 217, 9, 95, 188, 116, 103, 248, 196, 98, 62,
                    40, 25,
                ],
                [
                    186, 139, 16, 251, 7, 210, 4, 175, 214, 37, 178, 221, 63, 165, 128, 106, 63,
                    91, 131, 253,
                ],
                [
                    175, 191, 58, 226, 188, 68, 185, 97, 46, 194, 226, 211, 229, 7, 124, 174, 69,
                    82, 3, 6,
                ],
                [
                    147, 46, 30, 67, 123, 12, 96, 114, 70, 174, 0, 77, 242, 239, 227, 184, 198,
                    202, 38, 31,
                ],
                [
                    115, 255, 120, 111, 163, 151, 138, 160, 114, 84, 147, 146, 38, 209, 163, 121,
                    143, 46, 89, 173,
                ],
                [
                    145, 232, 72, 147, 166, 74, 86, 60, 189, 48, 72, 219, 89, 15, 183, 126, 112,
                    34, 58, 112,
                ],
                [
                    72, 124, 95, 201, 30, 58, 109, 40, 46, 158, 18, 228, 211, 173, 168, 147, 63,
                    178, 198, 167,
                ],
                [
                    144, 251, 221, 124, 37, 4, 24, 110, 145, 251, 173, 111, 180, 165, 67, 50, 237,
                    202, 54, 202,
                ],
                [
                    231, 44, 7, 203, 18, 10, 82, 17, 25, 241, 110, 105, 228, 0, 167, 149, 120, 176,
                    158, 221,
                ],
                [
                    106, 121, 103, 99, 220, 193, 56, 23, 44, 20, 79, 47, 168, 196, 185, 216, 251,
                    44, 235, 166,
                ],
                [
                    35, 155, 193, 173, 183, 57, 217, 141, 185, 92, 20, 78, 131, 134, 103, 230, 112,
                    165, 105, 105,
                ],
                [
                    87, 29, 178, 97, 223, 149, 47, 168, 210, 131, 232, 134, 176, 113, 216, 214, 50,
                    89, 243, 220,
                ],
                [
                    51, 143, 124, 163, 239, 120, 218, 113, 18, 86, 79, 92, 38, 157, 101, 160, 85,
                    0, 236, 48,
                ],
                [
                    43, 237, 141, 73, 93, 23, 132, 62, 231, 206, 167, 252, 90, 121, 223, 138, 45,
                    236, 26, 106,
                ],
                [
                    17, 153, 55, 47, 110, 37, 149, 50, 153, 34, 167, 248, 69, 216, 123, 159, 1, 94,
                    108, 78,
                ],
                [
                    186, 44, 234, 199, 96, 29, 33, 104, 70, 174, 90, 147, 116, 4, 145, 155, 38,
                    124, 73, 245,
                ],
                [
                    18, 92, 39, 95, 16, 212, 196, 60, 94, 99, 27, 233, 145, 41, 90, 215, 240, 63,
                    201, 232,
                ],
                [
                    3, 142, 117, 90, 163, 173, 207, 89, 40, 14, 250, 92, 2, 18, 204, 81, 223, 135,
                    56, 221,
                ],
                [
                    213, 200, 150, 39, 228, 70, 225, 28, 68, 185, 115, 190, 63, 157, 143, 143, 78,
                    204, 162, 12,
                ],
                [
                    72, 10, 30, 123, 65, 127, 3, 126, 162, 179, 162, 227, 57, 203, 251, 209, 96,
                    109, 200, 21,
                ],
                [
                    124, 68, 142, 152, 24, 33, 234, 22, 196, 211, 166, 59, 114, 89, 213, 64, 111,
                    175, 2, 115,
                ],
                [
                    31, 45, 69, 239, 77, 254, 44, 45, 84, 17, 41, 6, 21, 231, 146, 217, 137, 160,
                    82, 183,
                ],
                [
                    73, 42, 30, 74, 151, 15, 196, 210, 160, 3, 135, 51, 57, 160, 96, 104, 138, 32,
                    46, 51,
                ],
                [
                    172, 225, 43, 45, 24, 209, 203, 149, 21, 49, 37, 53, 138, 0, 145, 87, 172, 142,
                    58, 36,
                ],
                [
                    220, 92, 216, 26, 100, 36, 31, 18, 58, 86, 18, 166, 136, 179, 128, 173, 89, 82,
                    129, 210,
                ],
                [
                    220, 99, 90, 126, 121, 52, 102, 112, 226, 91, 8, 240, 101, 214, 111, 245, 9,
                    132, 6, 180,
                ],
                [
                    87, 94, 145, 126, 82, 80, 69, 186, 31, 176, 202, 236, 126, 80, 221, 209, 117,
                    93, 37, 63,
                ],
                [
                    224, 128, 204, 43, 27, 9, 38, 197, 123, 158, 17, 251, 177, 224, 216, 57, 82,
                    212, 12, 240,
                ],
                [
                    123, 102, 70, 189, 119, 42, 112, 97, 254, 35, 212, 198, 148, 142, 76, 101, 29,
                    169, 15, 6,
                ],
                [
                    47, 161, 138, 217, 46, 55, 89, 124, 161, 158, 210, 234, 141, 75, 222, 123, 237,
                    27, 197, 27,
                ],
                [
                    5, 23, 155, 162, 61, 49, 190, 32, 253, 93, 99, 38, 214, 48, 234, 53, 91, 196,
                    229, 252,
                ],
                [
                    252, 63, 133, 104, 80, 206, 60, 111, 14, 123, 192, 178, 36, 248, 157, 34, 18,
                    105, 203, 25,
                ],
                [
                    181, 246, 125, 39, 76, 239, 123, 225, 50, 145, 164, 8, 83, 186, 207, 202, 221,
                    173, 35, 148,
                ],
                [
                    5, 40, 236, 174, 214, 241, 115, 79, 151, 38, 202, 232, 167, 149, 42, 98, 89,
                    129, 160, 37,
                ],
                [
                    122, 4, 62, 76, 65, 140, 128, 140, 181, 138, 11, 250, 207, 30, 241, 118, 71,
                    18, 146, 30,
                ],
                [
                    65, 155, 30, 204, 253, 201, 164, 108, 233, 70, 238, 227, 203, 180, 121, 155,
                    97, 254, 132, 239,
                ],
                [
                    56, 89, 92, 61, 105, 108, 162, 36, 136, 161, 221, 106, 60, 126, 150, 157, 238,
                    57, 213, 56,
                ],
                [
                    129, 128, 111, 203, 6, 33, 120, 99, 181, 126, 113, 25, 158, 79, 16, 198, 0, 6,
                    67, 112,
                ],
                [
                    65, 6, 149, 85, 42, 157, 217, 48, 143, 215, 243, 93, 234, 179, 201, 225, 201,
                    213, 127, 62,
                ],
                [
                    69, 27, 255, 53, 169, 200, 72, 109, 173, 127, 239, 51, 16, 80, 221, 221, 47,
                    190, 55, 171,
                ],
                [
                    105, 247, 184, 160, 178, 252, 206, 78, 170, 145, 165, 239, 232, 52, 115, 254,
                    217, 225, 240, 85,
                ],
                [
                    247, 69, 119, 14, 185, 46, 84, 26, 32, 146, 234, 24, 18, 95, 223, 185, 173,
                    209, 158, 237,
                ],
                [
                    17, 21, 152, 128, 56, 10, 154, 139, 149, 129, 182, 251, 156, 168, 72, 210, 130,
                    153, 207, 181,
                ],
                [
                    250, 23, 80, 54, 109, 195, 120, 252, 119, 21, 50, 149, 46, 237, 124, 77, 78,
                    203, 111, 238,
                ],
                [
                    199, 148, 228, 175, 173, 17, 197, 153, 134, 179, 220, 73, 47, 42, 52, 172, 53,
                    85, 118, 163,
                ],
                [
                    174, 94, 208, 77, 88, 104, 234, 243, 32, 40, 182, 172, 203, 62, 119, 226, 111,
                    252, 234, 99,
                ],
                [
                    148, 252, 185, 34, 201, 127, 76, 229, 212, 225, 105, 83, 105, 159, 250, 255,
                    19, 186, 248, 66,
                ],
                [
                    52, 103, 57, 172, 88, 97, 82, 41, 113, 81, 74, 224, 28, 27, 252, 199, 169, 9,
                    62, 33,
                ],
                [
                    36, 144, 4, 250, 34, 64, 234, 127, 253, 47, 128, 245, 177, 153, 155, 185, 82,
                    159, 3, 178,
                ],
                [
                    63, 90, 16, 135, 79, 41, 193, 48, 52, 80, 148, 1, 163, 229, 156, 132, 246, 85,
                    102, 3,
                ],
                [
                    151, 147, 3, 66, 38, 66, 162, 51, 116, 99, 73, 120, 52, 180, 17, 97, 183, 144,
                    156, 234,
                ],
                [
                    246, 99, 89, 23, 110, 158, 58, 99, 34, 162, 185, 111, 150, 53, 162, 239, 198,
                    10, 79, 32,
                ],
                [
                    18, 44, 79, 118, 177, 48, 247, 93, 185, 213, 235, 37, 107, 12, 52, 231, 50,
                    186, 5, 69,
                ],
                [
                    112, 102, 85, 201, 239, 115, 194, 133, 249, 130, 196, 6, 255, 231, 205, 55, 9,
                    49, 36, 75,
                ],
                [
                    250, 193, 92, 131, 102, 101, 112, 84, 144, 5, 98, 105, 4, 215, 48, 72, 85, 2,
                    63, 42,
                ],
                [
                    16, 50, 72, 113, 122, 186, 88, 126, 212, 199, 248, 52, 156, 16, 163, 120, 170,
                    72, 228, 94,
                ],
                [
                    166, 111, 88, 208, 86, 79, 73, 127, 55, 49, 35, 35, 212, 62, 249, 249, 17, 77,
                    1, 144,
                ],
                [
                    201, 231, 187, 246, 184, 130, 244, 110, 210, 207, 245, 143, 103, 228, 43, 107,
                    152, 68, 19, 103,
                ],
                [
                    122, 40, 230, 252, 113, 242, 227, 69, 87, 27, 211, 168, 135, 66, 5, 111, 143,
                    159, 202, 29,
                ],
                [
                    244, 150, 48, 148, 70, 148, 238, 115, 90, 110, 124, 59, 245, 216, 9, 212, 109,
                    242, 76, 194,
                ],
                [
                    205, 118, 184, 28, 47, 76, 124, 243, 219, 48, 136, 88, 98, 235, 219, 124, 101,
                    59, 180, 60,
                ],
                [
                    244, 183, 25, 18, 247, 24, 228, 87, 113, 11, 101, 51, 63, 4, 111, 55, 139, 172,
                    205, 116,
                ],
                [
                    99, 72, 29, 101, 168, 37, 72, 255, 229, 246, 101, 56, 69, 156, 245, 205, 68,
                    55, 124, 224,
                ],
                [
                    194, 78, 230, 114, 227, 8, 91, 246, 128, 229, 188, 141, 247, 90, 75, 17, 213,
                    205, 160, 224,
                ],
                [
                    225, 209, 157, 79, 38, 81, 236, 202, 64, 23, 22, 58, 108, 56, 128, 88, 149, 77,
                    68, 4,
                ],
                [
                    5, 168, 169, 134, 166, 169, 26, 200, 42, 226, 107, 96, 206, 117, 204, 19, 212,
                    108, 120, 175,
                ],
                [
                    85, 20, 193, 236, 196, 190, 147, 86, 1, 54, 232, 50, 207, 40, 144, 115, 159,
                    18, 206, 6,
                ],
                [
                    96, 238, 206, 243, 32, 70, 242, 150, 82, 48, 171, 4, 190, 214, 214, 240, 115,
                    203, 171, 145,
                ],
                [
                    167, 242, 5, 208, 164, 163, 25, 113, 248, 51, 77, 249, 103, 13, 104, 109, 117,
                    96, 175, 130,
                ],
                [
                    6, 172, 220, 250, 115, 119, 107, 69, 254, 73, 130, 246, 52, 247, 132, 215, 33,
                    203, 134, 36,
                ],
                [
                    113, 236, 204, 61, 254, 47, 153, 185, 213, 243, 27, 63, 109, 130, 203, 92, 86,
                    24, 32, 108,
                ],
                [
                    30, 43, 158, 53, 85, 102, 157, 155, 32, 116, 128, 99, 182, 77, 48, 188, 177,
                    212, 154, 159,
                ],
                [
                    29, 13, 181, 14, 102, 176, 174, 73, 3, 177, 9, 53, 83, 220, 63, 135, 227, 156,
                    222, 192,
                ],
                [
                    209, 232, 177, 108, 90, 119, 214, 108, 67, 27, 67, 183, 241, 189, 190, 192,
                    185, 176, 165, 188,
                ],
                [
                    138, 23, 174, 179, 233, 102, 139, 29, 94, 41, 35, 121, 20, 0, 44, 198, 53, 109,
                    86, 39,
                ],
                [
                    136, 100, 53, 117, 86, 216, 97, 139, 183, 147, 82, 0, 101, 221, 192, 49, 90,
                    184, 76, 177,
                ],
                [
                    197, 22, 120, 3, 91, 94, 117, 171, 239, 50, 47, 34, 98, 203, 144, 217, 241,
                    214, 213, 2,
                ],
                [
                    253, 67, 45, 76, 63, 253, 71, 214, 54, 241, 40, 130, 3, 235, 227, 180, 37, 204,
                    199, 243,
                ],
                [
                    207, 223, 203, 129, 185, 184, 181, 82, 209, 188, 168, 108, 95, 218, 224, 193,
                    251, 182, 162, 177,
                ],
                [
                    98, 165, 146, 90, 22, 78, 95, 163, 108, 110, 116, 147, 10, 189, 244, 94, 82,
                    205, 100, 23,
                ],
                [
                    219, 251, 185, 33, 36, 215, 60, 57, 196, 43, 157, 102, 219, 70, 160, 236, 96,
                    19, 195, 240,
                ],
                [
                    52, 163, 72, 102, 59, 90, 197, 224, 157, 20, 45, 207, 197, 202, 47, 73, 80,
                    205, 191, 203,
                ],
                [
                    77, 160, 31, 52, 246, 202, 31, 110, 127, 215, 75, 198, 172, 175, 167, 235, 234,
                    64, 155, 140,
                ],
                [
                    230, 76, 28, 188, 204, 222, 242, 100, 94, 183, 196, 165, 54, 17, 7, 207, 46,
                    85, 75, 33,
                ],
                [
                    45, 190, 248, 141, 70, 6, 24, 182, 94, 118, 108, 179, 88, 63, 115, 242, 40,
                    221, 209, 142,
                ],
                [
                    138, 68, 123, 207, 200, 214, 139, 25, 233, 21, 166, 19, 253, 68, 245, 208, 139,
                    4, 155, 153,
                ],
                [
                    192, 85, 44, 76, 115, 162, 202, 48, 201, 48, 97, 51, 8, 201, 75, 251, 14, 138,
                    58, 7,
                ],
                [
                    189, 175, 191, 234, 93, 174, 190, 247, 63, 1, 217, 148, 71, 149, 90, 148, 241,
                    153, 153, 143,
                ],
                [
                    98, 135, 198, 20, 196, 209, 34, 153, 4, 203, 104, 95, 245, 28, 141, 96, 90,
                    249, 13, 91,
                ],
                [
                    70, 114, 172, 3, 179, 87, 64, 156, 250, 207, 40, 157, 149, 147, 76, 55, 29, 78,
                    82, 10,
                ],
                [
                    175, 36, 164, 114, 112, 251, 248, 209, 217, 29, 98, 77, 218, 58, 46, 134, 245,
                    13, 25, 181,
                ],
                [
                    144, 241, 84, 178, 86, 248, 179, 214, 129, 69, 182, 104, 228, 99, 247, 255,
                    155, 232, 244, 66,
                ],
                [
                    209, 230, 86, 130, 240, 246, 28, 147, 239, 113, 51, 77, 138, 251, 148, 192, 52,
                    157, 176, 209,
                ],
                [
                    159, 35, 64, 34, 82, 246, 126, 245, 177, 51, 133, 58, 121, 49, 185, 206, 229,
                    14, 211, 132,
                ],
                [
                    17, 3, 190, 3, 9, 212, 217, 213, 255, 133, 134, 204, 251, 53, 138, 11, 158,
                    243, 64, 44,
                ],
                [
                    173, 153, 230, 139, 52, 215, 199, 232, 99, 203, 34, 97, 66, 52, 87, 75, 39,
                    216, 145, 79,
                ],
                [
                    100, 244, 16, 154, 4, 132, 249, 161, 170, 143, 121, 228, 41, 34, 142, 53, 156,
                    188, 163, 198,
                ],
                [
                    169, 115, 95, 88, 86, 245, 245, 249, 2, 109, 2, 186, 250, 6, 96, 73, 56, 253,
                    49, 232,
                ],
                [
                    65, 126, 139, 56, 30, 184, 121, 233, 236, 193, 127, 155, 202, 117, 195, 58, 27,
                    195, 112, 152,
                ],
                [
                    90, 149, 131, 177, 134, 179, 76, 155, 229, 18, 142, 232, 147, 207, 29, 172,
                    173, 26, 71, 193,
                ],
                [
                    33, 98, 11, 16, 64, 244, 162, 219, 228, 34, 29, 114, 175, 96, 49, 38, 72, 245,
                    192, 110,
                ],
                [
                    109, 76, 162, 115, 79, 106, 76, 186, 160, 60, 232, 210, 202, 229, 94, 222, 169,
                    18, 139, 126,
                ],
                [
                    16, 194, 157, 99, 197, 49, 58, 68, 111, 189, 17, 0, 55, 195, 47, 85, 183, 155,
                    158, 199,
                ],
                [
                    12, 194, 75, 147, 71, 208, 239, 224, 72, 129, 36, 156, 26, 192, 164, 91, 18,
                    207, 130, 216,
                ],
                [
                    70, 215, 32, 114, 201, 177, 55, 118, 68, 189, 233, 15, 109, 121, 204, 22, 225,
                    40, 158, 17,
                ],
                [
                    181, 2, 168, 68, 62, 35, 17, 201, 241, 181, 27, 178, 47, 110, 206, 12, 64, 153,
                    167, 57,
                ],
                [
                    141, 145, 87, 44, 109, 83, 162, 123, 44, 54, 188, 67, 34, 34, 105, 185, 201,
                    240, 154, 109,
                ],
                [
                    81, 173, 157, 193, 190, 169, 69, 64, 134, 135, 98, 116, 82, 74, 213, 240, 128,
                    135, 30, 162,
                ],
                [
                    41, 96, 163, 78, 226, 27, 34, 213, 50, 126, 78, 164, 231, 164, 224, 230, 218,
                    130, 110, 248,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    74, 128, 161, 218, 212, 199, 5, 143, 161, 223, 238, 64, 32, 176, 15, 5, 104,
                    186, 166, 85,
                ],
                [
                    56, 157, 143, 165, 104, 74, 111, 45, 242, 251, 234, 150, 239, 219, 182, 202,
                    75, 54, 30, 245,
                ],
            ],
        )
    }

    // use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    // use ark_ff::Field;
    // use ark_groth16::prepare_verifying_key;
    // use ark_relations::{
    //     lc,
    //     r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    // };
    // use ark_std::UniformRand;

    // struct MySillyCircuit<F: Field> {
    //     a: Option<F>,
    //     b: Option<F>,
    // }

    // impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
    //     fn generate_constraints(
    //         self,
    //         cs: ConstraintSystemRef<ConstraintF>,
    //     ) -> Result<(), SynthesisError> {
    //         let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
    //         let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
    //         let c = cs.new_input_variable(|| {
    //             let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
    //             let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

    //             a *= &b;
    //             Ok(a)
    //         })?;

    //         cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
    //         cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
    //         cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
    //         cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
    //         cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
    //         cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

    //         Ok(())
    //     }
    // }

    // fn setup_prove_verify<E: Pairing>() {
    //     let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    //     let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut
    // rng).unwrap();     let pvk = prepare_verifying_key::<E>(&vk);

    //     let a = E::ScalarField::rand(&mut rng);
    //     let b = E::ScalarField::rand(&mut rng);
    //     let mut c = a;
    //     c *= b;

    //     let proof = Groth16::<E>::prove(
    //         &pk,
    //         MySillyCircuit {
    //             a: Some(a),
    //             b: Some(b),
    //         },
    //         &mut rng,
    //     )
    //     .unwrap();

    //     println!(
    //         "{}",
    //         Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof).unwrap()
    //     );
    //     assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof).unwrap());
    //     assert!(!Groth16::<E>::verify_with_processed_vk(&pvk, &[a], &proof).unwrap());
    // }

    // #[test]
    // fn test_setup_prove_verify() {
    //     setup_prove_verify::<Bn254>();
    // }
}
