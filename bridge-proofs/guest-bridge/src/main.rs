use strata_proofimpl_bitvm_bridge::{process_bridge_proof, BridgeProofInput, StrataBridgeState};

fn main() {
    let bridge_proof_input: BridgeProofInput = sp1_zkvm::io::read();

    let strata_bridge_state = sp1_zkvm::io::read_vec();
    let strata_bridge_state: StrataBridgeState = borsh::from_slice(&strata_bridge_state).unwrap();

    let public_params = process_bridge_proof(bridge_proof_input, strata_bridge_state);
    sp1_zkvm::io::commit(&public_params);
}
