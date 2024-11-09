use anyhow::Context;
use sp1_sdk::{HashableKey, ProverClient, SP1ProofWithPublicValues, SP1VerifyingKey};
use strata_bridge_guest_builder::GUEST_BRIDGE_ELF;
use strata_primitives::vk;
use strata_proofimpl_bitvm_bridge::BridgeProofInput;
use strata_sp1_adapter::SP1ProofInputBuilder;
use strata_state::chain_state::ChainState;
use strata_zkvm::{Proof, ZKVMInputBuilder};

pub fn make_proof(
    proof_input: BridgeProofInput,
    chain_state: ChainState,
) -> anyhow::Result<(SP1ProofWithPublicValues, String, SP1VerifyingKey, Proof)> {
    let mut input_builder = SP1ProofInputBuilder::new();
    input_builder.write(&proof_input).unwrap();
    input_builder.write_borsh(&chain_state).unwrap();
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
    anyhow::Ok((
        proof,
        vkey.bytes32(),
        vkey,
        Proof::new(sp1_groth16_proof_bytes),
    ))
}

#[cfg(test)]
mod test {
    use std::{
        fs::File,
        io::{self, Write},
    };

    use strata_proofimpl_bitvm_bridge::BridgeProofInput;
    use strata_state::chain_state::ChainState;

    use super::*;

    #[test]
    fn test_proof_generation_and_save() {
        sp1_sdk::utils::setup_logger();
        let proof_input_raw = include_bytes!("../../bitvm-bridge/inputs/process_blocks_input.bin");
        let chain_state_raw = include_bytes!("../../bitvm-bridge/inputs/chain_state.bin");

        let proof_input: BridgeProofInput = bincode::deserialize(proof_input_raw).unwrap();
        let chain_state: ChainState = borsh::from_slice(chain_state_raw).unwrap();

        let proof_res = make_proof(proof_input, chain_state).unwrap();
        let proof_res = bincode::serialize(&proof_res).unwrap();
        save_to_bin_file(proof_res, "proof_data/proof.bin").unwrap();
    }

    fn save_to_bin_file(data: Vec<u8>, file_path: &str) -> io::Result<()> {
        let mut file = File::create(file_path)?; // Open or create the file
        file.write_all(&data)?; // Write the entire byte vector to the file
        Ok(())
    }
}
