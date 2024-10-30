use strata_proofimpl_bitvm_bridge::process_bridge_proof;

fn main() {
    let public_params = process_bridge_proof();
    sp1_zkvm::io::commit(&public_params);
}
