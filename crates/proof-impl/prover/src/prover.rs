use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1VerifyingKey};
use strata_bridge_guest_builder::GUEST_BRIDGE_ELF;
use strata_proofimpl_bitvm_bridge::{BridgeProofInput, StrataBridgeState};
use strata_sp1_adapter::SP1ProofInputBuilder;
use strata_zkvm::ZKVMInputBuilder;

pub fn prove_wrapper(
    input: &[u8],
    strata_bridge_state: &StrataBridgeState,
) -> anyhow::Result<(SP1ProofWithPublicValues, SP1VerifyingKey)> {
    let bridge_proof_input: BridgeProofInput =
        bincode::deserialize(input).expect("should be able to deserialize proof input");

    prove(bridge_proof_input, strata_bridge_state)
}

pub fn prove(
    bridge_proof_input: BridgeProofInput,
    strata_bridge_state: &StrataBridgeState,
) -> anyhow::Result<(SP1ProofWithPublicValues, SP1VerifyingKey)> {
    let input = {
        let mut input_builder = SP1ProofInputBuilder::new();
        input_builder.write(&bridge_proof_input)?;
        input_builder.write_borsh(strata_bridge_state)?;
        input_builder.build()?
    };

    let prover_client = ProverClient::new();
    let (sp1pk, sp1vk) = prover_client.setup(GUEST_BRIDGE_ELF);

    let prover = prover_client.prove(&sp1pk, input).compressed().groth16();

    let proof = prover.run()?;

    anyhow::Ok((proof, sp1vk))
}

#[cfg(test)]
mod test {
    use std::{
        fs::{self, File},
        io::{self, Write},
    };

    use bitcoin::{block::Header, Block};
    use sha2::{Digest, Sha256};
    use sp1_verifier::Groth16Verifier;
    use strata_primitives::l1::OutputRef;
    use strata_proofimpl_bitvm_bridge::{BridgeProofInput, WithInclusionProof};
    use strata_state::{chain_state::ChainState, l1::HeaderVerificationState};

    use super::*;

    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    pub struct CheckpointInputOld {
        pub block: Block,
        pub out_ref: OutputRef,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    pub struct BridgeProofInputOld {
        pub checkpoint_input: CheckpointInputOld,
        pub payment_txn_block: Block,
        pub claim_txn_block: Block,
        pub payment_txn_idx: u32,
        pub claim_txn_idx: u32,
        pub ts_block_header: Header,
        pub headers: Vec<Header>,
        pub start_header_state: HeaderVerificationState,
    }

    #[test]
    fn test_prove() {
        sp1_sdk::utils::setup_logger();

        let bridge_proof_input: BridgeProofInput = bincode::deserialize(include_bytes!(
            "../../bitvm-bridge/inputs/bridge_proof_input.bin"
        ))
        .unwrap();
        let strata_bridge_state: StrataBridgeState = borsh::from_slice(include_bytes!(
            "../../bitvm-bridge/inputs/strata_bridge_state.bin"
        ))
        .unwrap();

        let proof_data = prove(bridge_proof_input, &strata_bridge_state).unwrap();

        fs::write(
            "proof_data/proof_data.bin",
            bincode::serialize(&proof_data).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn test_verify() {
        let (sp1prf, sp1vk): (SP1ProofWithPublicValues, SP1VerifyingKey) =
            bincode::deserialize(include_bytes!("../proof_data/proof_data.bin")).unwrap();
        Groth16Verifier::verify(
            &sp1prf.bytes(),
            sp1prf.public_values.as_slice(),
            &sp1vk.bytes32(),
            &sp1_verifier::GROTH16_VK_BYTES,
        )
        .expect("Invalid groth16 proof");
    }

    #[test]
    fn test_proof_generation_and_save() {
        sp1_sdk::utils::setup_logger();
        let proof_input_raw = include_bytes!("../../bitvm-bridge/inputs/process_blocks_input.bin");
        let chain_state_raw = include_bytes!("../../bitvm-bridge/inputs/chain_state.bin");

        let old_bridge_proof_input: BridgeProofInputOld =
            bincode::deserialize(proof_input_raw).unwrap();

        println!("{:?}", old_bridge_proof_input);

        let BridgeProofInputOld {
            headers,
            start_header_state: initial_header_state,
            payment_txn_block,
            payment_txn_idx,
            checkpoint_input,
            ts_block_header,
            claim_txn_block: _,
            claim_txn_idx: _,
        } = old_bridge_proof_input;

        return;
        let bridge_out_block = payment_txn_block;
        let bridge_out_tx = bridge_out_block.txdata[payment_txn_idx as usize]
            .with_inclusion_proof(&bridge_out_block);
        let (bridge_out_pos, _) = headers
            .iter()
            .enumerate()
            .find(|&(i, header)| header.block_hash() == bridge_out_block.block_hash())
            .unwrap();

        let old_chain_state: ChainState = borsh::from_slice(chain_state_raw).unwrap();
        let hashed_chain_state = old_chain_state.hashed_chain_state();
        let deposits_table = old_chain_state.deposits_table();

        // let proof_input = BridgeProofInput {
        //     headers,
        //     initial_header_state,
        //     bridge_out: (bridge_out_pos, bridge_out_tx),
        //     superblock_period_start_ts: ts_block_header.time,
        //     checkpoint: (),
        // };

        // let proof_res = make_proof(proof_input, chain_state).unwrap();
        // let proof_res = bincode::serialize(&proof_res).unwrap();
        // save_to_bin_file(proof_res, "proof_data/proof.bin").unwrap();
    }

    fn save_to_bin_file(data: Vec<u8>, file_path: &str) -> io::Result<()> {
        let mut file = File::create(file_path)?; // Open or create the file
        file.write_all(&data)?; // Write the entire byte vector to the file
        Ok(())
    }
}
