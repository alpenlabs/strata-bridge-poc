use bitcoin::{BlockHash, Txid};
use strata_primitives::params::RollupParams;
use strata_state::{batch::BatchCheckpoint, bridge_state::DepositState, chain_state::ChainState};

pub type BridgeProofPublicParams = (BlockHash, Txid, u32);

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
