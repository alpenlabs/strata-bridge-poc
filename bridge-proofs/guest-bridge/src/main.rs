use strata_proofimpl_bitvm_bridge::process_bridge_proof;

fn main() {
    let serialized_sigs = sp1_zkvm::io::read_vec();
    let public_params = process_bridge_proof(serialized_sigs);
    // sp1_zkvm::io::commit_slice(&public_params);
}
