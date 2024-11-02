pub mod db;

use bitvm::{
    groth16::g16::{
        self, Groth16ProofAssertions, Proof, WotsPublicKeys, WotsSignatures, N_TAPLEAVES,
    },
    treepp::*,
};

pub fn BRIDGE_POC_VERIFICATION_KEY() -> g16::VerificationKey {
    // TODO: replace this with actual verification key
    let (_, ark_vk) = mock::groth16_circuit();
    g16::VerificationKey { ark_vk }
}

pub fn generate_verifier_partial_scripts() -> [Script; N_TAPLEAVES] {
    g16::Verifier::compile(BRIDGE_POC_VERIFICATION_KEY())
}

pub fn generate_verifier_tapscripts_from_partial_scripts(
    verifier_scripts: [Script; N_TAPLEAVES],
    public_keys: WotsPublicKeys,
) -> [Script; N_TAPLEAVES] {
    g16::Verifier::generate_tapscripts(public_keys, verifier_scripts)
}

pub fn generate_assertions_for_proof(proof: Proof) -> Groth16ProofAssertions {
    g16::Verifier::generate_assertions(proof)
}

pub fn validate_assertion_signatures(
    signatures: WotsSignatures,
    public_keys: WotsPublicKeys,
    verifier_scripts: [Script; N_TAPLEAVES],
) -> Option<(u32, Script, Script)> {
    g16::Verifier::validate_assertion_signatures(public_keys, signatures, verifier_scripts)
}

pub mod mock {
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_groth16::{ProvingKey, VerifyingKey};

    pub fn groth16_circuit() -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
        use ark_bn254::Bn254;
        use ark_ec::pairing::Pairing;
        use ark_ff::PrimeField;
        use ark_groth16::Groth16;
        use ark_relations::{
            lc,
            r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
        };
        use ark_std::{test_rng, UniformRand};
        use rand::{RngCore, SeedableRng};

        #[derive(Copy)]
        struct DummyCircuit<F: PrimeField> {
            pub a: Option<F>,
            pub b: Option<F>,
            pub num_variables: usize,
            pub num_constraints: usize,
        }

        impl<F: PrimeField> Clone for DummyCircuit<F> {
            fn clone(&self) -> Self {
                DummyCircuit {
                    a: self.a,
                    b: self.b,
                    num_variables: self.num_variables,
                    num_constraints: self.num_constraints,
                }
            }
        }

        impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
            fn generate_constraints(
                self,
                cs: ConstraintSystemRef<F>,
            ) -> Result<(), SynthesisError> {
                let a =
                    cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
                let b =
                    cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
                let c = cs.new_input_variable(|| {
                    let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                    let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                    Ok(a * b)
                })?;
                let d = cs.new_input_variable(|| {
                    let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                    let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                    Ok(a + b)
                })?;
                let e = cs.new_input_variable(|| {
                    let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                    let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                    Ok(a - b)
                })?;

                for _ in 0..(self.num_variables - 3) {
                    let _ = cs
                        .new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
                }

                for _ in 0..self.num_constraints - 1 {
                    cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
                }

                cs.enforce_constraint(lc!(), lc!(), lc!())?;

                Ok(())
            }
        }

        type E = Bn254;
        let k = 6;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
            a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
            b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();
        (pk, vk)
    }
}

#[cfg(test)]
mod tests {
    use super::generate_verifier_partial_scripts;

    #[test]
    fn test_groth16_compile() {
        let scripts = generate_verifier_partial_scripts();

        println!("script.lens: {:?}", scripts.map(|script| script.len()));
    }
}
