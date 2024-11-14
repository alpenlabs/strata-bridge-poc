mod bitcoin;
mod bridge_proof;
mod ckp_verifier;
mod primitives;

pub use bridge_proof::{process_bridge_proof, process_bridge_proof_wrapper};
// pub use primitives::{BridgeProofInput, BridgeProofPublicParams, StrataBridgeState};
pub use primitives::*;
