use serde::{Deserialize, Serialize};

/// Public Parameters that proof asserts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeProofPublicParams {}

/// Necessary information to prove the execution of the RETH block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeProofInput {}

pub fn process_checkpoint_proof(_prover_input: BridgeProofInput) -> BridgeProofPublicParams {
    // TODO: process bridge proof
    BridgeProofPublicParams {}
}
