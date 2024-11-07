use strata_proofimpl_bitvm_bridge::{process_bridge_proof, BridgeProofInput, ChainState};

fn main() {
    let bridge_proof_input: BridgeProofInput = sp1_zkvm::io::read();

    let chain_state_raw = sp1_zkvm::io::read_vec();
    let chain_state: ChainState = borsh::from_slice(&chain_state_raw).unwrap();

    let public_params = process_bridge_proof(bridge_proof_input, chain_state);
    sp1_zkvm::io::commit(&public_params);
}
