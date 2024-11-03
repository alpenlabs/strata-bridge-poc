pub mod db;

use bitvm::{
    groth16::g16::{
        self, Proof, ProofAssertions as Groth16ProofAssertions, VerificationKey, WotsPublicKeys,
        WotsSignatures, N_TAPLEAVES,
    },
    treepp::*,
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
    verifier_scripts: &[Script; N_TAPLEAVES],
) -> Option<(u32, Script, Script)> {
    g16::Verifier::validate_assertion_signatures(
        proof,
        bridge_poc_verification_key(),
        signatures,
        public_keys,
        verifier_scripts,
    )
}

pub mod mock {
    use ark_bn254::{Bn254, Fr as F};
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_ec::pairing::Pairing;
    use ark_ff::{AdditiveGroup, Field, PrimeField};
    use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_std::{test_rng, UniformRand};
    use rand::{RngCore, SeedableRng};

    #[derive(Clone)]
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
    use ark_ec::pairing::Pairing;
    use ark_groth16::Groth16;
    use ark_std::test_rng;
    use bitcoin::{ScriptBuf, Txid};
    use bitvm::{
        groth16::g16,
        signatures::wots::{wots160, wots256},
        treepp::*,
    };
    use rand::{rngs::OsRng, RngCore, SeedableRng};
    use strata_bridge_tx_graph::{
        commitments::{
            secret_key_for_bridge_out_txid, secret_key_for_proof_element,
            secret_key_for_superblock_hash, secret_key_for_superblock_period_start_ts,
        },
        mock_txid,
    };

    use super::{
        bridge_poc_verification_key, generate_assertions_for_proof,
        generate_verifier_partial_scripts, mock, validate_assertion_signatures,
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

    pub fn get_deposit_master_secret_key(deposit_txid: Txid) -> String {
        let master_secret_key = "helloworld";
        format!("{}:{}", master_secret_key, deposit_txid.to_string())
    }

    fn generate_wots_public_keys(deposit_txid: Txid) -> g16::WotsPublicKeys {
        let deposit_msk = get_deposit_master_secret_key(deposit_txid);
        (
            (
                wots256::generate_public_key(&secret_key_for_superblock_period_start_ts(
                    &deposit_msk,
                )),
                wots256::generate_public_key(&secret_key_for_bridge_out_txid(&deposit_msk)),
                wots256::generate_public_key(&secret_key_for_superblock_hash(&deposit_msk)),
            ),
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
            (
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
            ),
            std::array::from_fn(|i| {
                wots256::get_signature(
                    &secret_key_for_proof_element(&deposit_msk, i as u32),
                    &assertions.1[i],
                )
            }),
            std::array::from_fn(|mut i| {
                i += 40;
                wots160::get_signature(
                    &secret_key_for_proof_element(&deposit_msk, i as u32),
                    &assertions.2[i],
                )
            }),
        )
    }

    #[test]
    fn test_full_verification() {
        // let verifier_scripts = generate_verifier_partial_scripts();
        // save_verifier_scripts(&verifier_scripts);
        // return;

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

        let assertions = generate_assertions_for_proof(
            bridge_poc_verification_key(),
            g16::Proof {
                proof: proof.clone(),
                public_inputs: vec![circuit.c, circuit.d, circuit.e],
            },
        );

        println!("assertions: {:?}", assertions);

        let deposit_txid = mock_txid();

        let wots_public_keys = generate_wots_public_keys(deposit_txid);
        let wots_signatures = generate_wots_signatures(deposit_txid, assertions);

        let verifier_scripts = &read_verifier_scripts();

        let res = validate_assertion_signatures(
            g16::Proof {
                proof: proof.clone(),
                public_inputs: vec![Fr::from(15), Fr::from(8), Fr::from(2)],
            },
            wots_signatures,
            wots_public_keys,
            verifier_scripts,
        );

        println!("{:?}", res);
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
