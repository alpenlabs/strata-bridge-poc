use strata_proofimpl_bitvm_bridge::process_checkpoint_proof;

fn main() {
    let input = sp1_zkvm::io::read();
    let public_params = process_checkpoint_proof(input);
    sp1_zkvm::io::commit(&public_params);
}
