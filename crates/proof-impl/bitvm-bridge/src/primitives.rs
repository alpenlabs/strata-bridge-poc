use bitcoin::{hashes::Hash, Txid};
use strata_primitives::params::RollupParams;
use strata_state::{batch::BatchCheckpoint, bridge_state::DepositState, chain_state::ChainState};

pub fn mock_txid() -> Txid {
    // Create a mock Txid by hashing an arbitrary string or using a fixed byte array.
    // Here, we hash a fixed string to get a deterministic Txid for testing purposes.
    Txid::from_slice(&[0u8; 32]).expect("Failed to create Txid from bytes")
}

pub type BridgeProofPublicParams = Txid;

/// Necessary information to prove the execution of the bridge proof.
pub struct BridgeProofInput {
    pub l1_sgements: Vec<L1Segment>,
    pub batch_checkpoint: BatchCheckpoint,
    pub rollup_params: RollupParams,

    pub deposit_state: DepositState,
    pub l2_state: ChainState,
}

pub struct L1Segment {
    pub idx: u64,
    pub header: L1Header,
}

pub struct L1Header {}

impl L1Header {
    pub fn verify(&self) -> bool {
        true
    }
}
