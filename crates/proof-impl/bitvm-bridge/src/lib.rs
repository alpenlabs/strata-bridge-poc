mod bitcoin;
mod bridge_proof;
mod ckp_verifier;
mod primitives;

pub use bridge_proof::process_bridge_proof;
pub use primitives::{BridgeProofInput, BridgeProofPublicParams};
