use anyhow::Context;
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1VerifyingKey};
use strata_bridge_guest_builder::GUEST_BRIDGE_ELF;
use strata_sp1_adapter::SP1ProofInputBuilder;
use strata_zkvm::{Proof, ZKVMInputBuilder};

pub fn make_proof() -> anyhow::Result<(SP1ProofWithPublicValues, SP1VerifyingKey, Proof)> {
    let mut input_builder = SP1ProofInputBuilder::new();
    let input = input_builder.build()?;

    let prover_client = ProverClient::new();
    let (proving_key, vkey) = prover_client.setup(GUEST_BRIDGE_ELF);

    let prover = prover_client
        .prove(&proving_key, input)
        .compressed()
        .groth16();

    let proof = prover.run()?;

    let sp1_groth16_proof_bytes = hex::decode(
        &proof
            .clone()
            .proof
            .try_as_groth_16()
            .context("Failed to convert proof to Groth16")?
            .raw_proof,
    )
    .context("Failed to decode Groth16 proof")?;
    anyhow::Ok((proof, vkey, Proof::new(sp1_groth16_proof_bytes)))
}

#[cfg(test)]
mod test {
    use std::{
        fs::File,
        io::{self, Write},
    };

    use super::*;

    #[test]
    fn test_proof_generation_and_save() {
        let proof_res = make_proof().unwrap();
        let proof_res = bincode::serialize(&proof_res).unwrap();
        save_to_bin_file(proof_res, "proof.bin").unwrap();
    }

    fn save_to_bin_file(data: Vec<u8>, file_path: &str) -> io::Result<()> {
        let mut file = File::create(file_path)?; // Open or create the file
        file.write_all(&data)?; // Write the entire byte vector to the file
        Ok(())
    }
}
