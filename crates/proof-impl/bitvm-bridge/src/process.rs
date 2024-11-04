#![allow(unused)]
use bitcoin::{block::Header, hashes::Hash, BlockHash, Txid};
use snark_bn254_verifier::Groth16Verifier;
use sp1_core_machine::io::SP1PublicValues;
use strata_primitives::{buf::Buf32, params::RollupParams};
use strata_state::{
    batch::BatchCheckpoint,
    bridge_state::DepositState,
    chain_state::ChainState,
    l1::{BtcParams, HeaderVerificationState},
};
use strata_zkvm::Proof;
use substrate_bn::Fr;

use crate::{primitives::mock_txid, BridgeProofPublicParams};

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

fn verify_l1_chain(
    initial_header_state: &HeaderVerificationState,
    headers: &[Header],
    params: &BtcParams,
) -> HeaderVerificationState {
    let mut state = initial_header_state.clone();

    for header in headers {
        state = state.check_and_update_continuity_new(header, params);
    }

    state
}

// Copied from ~/.sp1/circuits/v2.0.0/groth16_vk.bin
// This is same for all the SP1 programs that uses v2.0.0
pub const GROTH16_VK_BYTES: &[u8] = include_bytes!("groth16_vk.bin");

/// Verifies the Groth16 proof posted on chain
///
/// Note: SP1Verifier::verify_groth16 is not directly used because it depends on `sp1-sdk` which
/// cannot be compiled inside guest code.
fn verify_groth16(proof: &Proof, vkey_hash: &[u8], committed_values_raw: &[u8]) -> bool {
    // Convert vkey_hash to Fr, mapping the error to anyhow::Error
    let vkey_hash_fr = Fr::from_slice(vkey_hash).unwrap();

    let committed_values_digest = SP1PublicValues::from(committed_values_raw)
        .hash_bn254()
        .to_bytes_be();

    // Convert committed_values_digest to Fr, mapping the error to anyhow::Error
    let committed_values_digest_fr = Fr::from_slice(&committed_values_digest).unwrap();

    // Perform the Groth16 verification, mapping any error to anyhow::Error
    Groth16Verifier::verify(
        proof.as_bytes(),
        GROTH16_VK_BYTES,
        &[vkey_hash_fr, committed_values_digest_fr],
    )
    .unwrap()
}
