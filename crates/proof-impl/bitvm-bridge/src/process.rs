#![allow(unused)]
use bitcoin::{block::Header, hashes::Hash, BlockHash, Txid};
use strata_primitives::{buf::Buf32, params::RollupParams};
use strata_state::{
    batch::BatchCheckpoint,
    bridge_state::DepositState,
    chain_state::ChainState,
    l1::{BtcParams, HeaderVerificationState},
};

use crate::{primitives::get_bridge_proof_public_params, BridgeProofPublicParams};

pub fn process_bridge_proof() -> BridgeProofPublicParams {
    // endblock := block where ckp proof + N blocks; N = 2016
    get_bridge_proof_public_params()
}

pub fn assert_deposit_state(
    deposit_state: &DepositState,
    l2_state: &ChainState,
    batch_checkpoint: &BatchCheckpoint,
    rollup_params: &RollupParams,
) {
    // Validate the chain state w.r.t proof chain state root
    let (_, _l2_state_root) = process_ckp(batch_checkpoint, rollup_params);
    // TODO: compute_root(l2_state) == l2_state_root

    // TODO: Later on we will have that particular UTXO in the deposit table itself
    // Assert Deposit table contains the `DepositState` operator interested in
    let deposits: Vec<DepositState> = l2_state
        .deposits_table()
        .deposits()
        .map(|el| el.deposit_state().clone())
        .collect();
    let _entry_exists = deposits.contains(deposit_state);
    // TODO: assert!(_entry_exists)
}

// BatchCheckpoint <- read the from the L1
// It contains the proof
// To verify this proof we need to
pub fn process_ckp(
    batch_checkpoint: &BatchCheckpoint,
    rollup_params: &RollupParams,
) -> (u64, Buf32) {
    // NOTE: Here, bridge operator is trusting the PP made by the sequencer.
    let public_params = batch_checkpoint.proof_output();
    let public_params_raw = borsh::to_vec(&public_params).unwrap();
    let proof = batch_checkpoint.proof();

    let (l2_idx, l2_id) = (
        public_params.batch_info.l2_range.1,
        public_params.batch_info.l2_transition.1,
    );

    (l2_idx, l2_id)
}
