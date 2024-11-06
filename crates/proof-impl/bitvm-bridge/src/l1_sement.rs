#![allow(unused)]
use bitcoin::{block::Header, Block, Txid};
use strata_primitives::{
    buf::Buf32,
    l1::{BitcoinAmount, XOnlyPk},
};
use strata_proofimpl_btc_blockspace::block::{check_merkle_root, check_witness_commitment};
use strata_state::{
    batch::{BatchCheckpoint, BatchInfo},
    bridge_state::DepositState,
    chain_state::ChainState,
    l1::{get_btc_params, BtcParams, HeaderVerificationState},
    tx::ProtocolOperation,
};
use strata_tx_parser::filter::{filter_relevant_txs, TxFilterRule};

use crate::bitcoin::{
    checkpoint::verify_checkpoint_and_extract_info, claim_txn::get_claim_txn,
    header_chain::verify_l1_chain, payment_txn::get_payment_txn, primitives::WithdrwalInfo,
};

pub fn process_blocks(
    checkpoint: (Block, ChainState),
    payment: Block,
    claim_txn_block: Block,
    headers: &[Header],
    start_header: HeaderVerificationState,
    b4: Block,
) {
    let (ckp_withdrawl_info, batch_info) =
        verify_checkpoint_and_extract_info(checkpoint.0, checkpoint.1);
    let operator_withdrawl_info = get_payment_txn(&payment);
    let claim_txn = get_claim_txn(&claim_txn_block);

    // TODO: Match the info from `ckp_withdrawl_info` & `operator_withdrawl_info`

    // TODO: Link the `operator_withdrawl_info` and `claim_txn`

    // TODO: Assert inclusion of `checkpoint`, `claim_txn_block` & `payment` blocks in headers

    // TODO: Find the super block
    // ts <- claim_txn (B4 time := ts)
    // ckp < payment < B4
    // asseert B4.time == ts
    // super_block = min_block(B4 + 2016)

    // Maybe pass the closure
    let params = get_btc_params();
    let _ = verify_l1_chain(&start_header, headers, &params);
}
