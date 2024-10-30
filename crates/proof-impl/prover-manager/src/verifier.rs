use num_bigint::BigUint;
use num_traits::Num;
use strata_sp1_adapter::SP1Verifier;
use strata_zkvm::{Proof, ZKVMVerifier};

pub fn verify_proof(proof: Proof, vkey: String, comitted_values: &[u8]) -> anyhow::Result<()> {
    let vkey_hash = BigUint::from_str_radix(
        vkey.strip_prefix("0x")
            .expect("vkey should start with '0x'"),
        16,
    )
    .expect("Failed to parse vkey hash")
    .to_bytes_be();

    SP1Verifier::verify_groth16_raw(&proof, &vkey_hash, comitted_values)?;

    anyhow::Ok(())
}

#[cfg(test)]
mod test {
    use sp1_sdk::{HashableKey, SP1ProofWithPublicValues, SP1VerifyingKey};
    use strata_proofimpl_bitvm_bridge::BridgeProofPublicParams;

    use super::*;

    #[test]
    fn test_proof_verification() {
        let proof_data = include_bytes!("../proof_data/proof.bin");
        let (sp1_proof, sp1_vkey, raw_groth16_proof): (
            SP1ProofWithPublicValues,
            SP1VerifyingKey,
            Proof,
        ) = bincode::deserialize(proof_data).unwrap();

        let public_value: BridgeProofPublicParams = sp1_proof.clone().public_values.read();
        println!("got the public param {:?}", public_value);

        let vkey_str = sp1_vkey.bytes32();
        let commited_values = sp1_proof.public_values.as_slice();

        verify_proof(raw_groth16_proof, vkey_str, commited_values).unwrap();
    }
}
