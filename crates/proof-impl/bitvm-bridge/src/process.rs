#![allow(unused)]
use bitcoin::{block::Header, hashes::Hash, BlockHash, Txid};
use strata_primitives::{buf::Buf32, params::RollupParams};
use strata_state::{
    batch::BatchCheckpoint,
    bridge_state::DepositState,
    chain_state::ChainState,
    l1::{BtcParams, HeaderVerificationState},
};

use crate::BridgeProofPublicParams;

pub fn process_bridge_proof() -> BridgeProofPublicParams {
    // TODO:
    // Assume the inputs and process on it
    // (Ckp <- bid, bidx)
    // (ProcessDeposit <- bid, bidx)
    // (ClaimTxn <- bid, bidx)

    // TODO:
    // On checkpoint
    // Verify the sp1 proof and recover the checkpoint params
    // L1BlockId
    // L2BlockId

    // TODO:
    // Read L2 chain
    // From the L2 state verify the inclusion of the deposit and assignee on that state
    // Verify the settlement of that Withdrawal request on the chain
    // Add the assumptions

    // TODO:
    // Verify the inclusion of claim txn
    // Add assumptions
    // L1 segment
    // start := block where ckp proof is there
    // endblock := block where ckp proof + N blocks; N = 2016

    let super_block_hash =
        BlockHash::from_slice(&[0u8; 32]).expect("Failed to create Block hash from bytes");
    let withdrawal_txnid = Txid::from_slice(&[0u8; 32]).expect("Failed to create Txid from bytes");

    // Assert that the first byte of each hash is `0`
    assert_eq!(
        super_block_hash[0], 0,
        "super_block_hash does not start with 0"
    );
    assert_eq!(
        withdrawal_txnid[0], 0,
        "withdrawal_txnid does not start with 0"
    );

    let timestamp: u32 = 0;

    (super_block_hash, withdrawal_txnid, timestamp)
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
