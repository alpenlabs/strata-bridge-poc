#![allow(unused)]
use bitcoin::{block::Header, Block, Txid};
use strata_primitives::{
    buf::Buf32,
    l1::{BitcoinAmount, OutputRef, XOnlyPk},
};
use strata_proofimpl_btc_blockspace::block::{check_merkle_root, check_witness_commitment};
use strata_state::{
    batch::{BatchCheckpoint, BatchInfo},
    bridge_state::DepositState,
    chain_state::ChainState,
    l1::{compute_block_hash, get_btc_params, BtcParams, HeaderVerificationState},
    tx::ProtocolOperation,
};
use strata_tx_parser::filter::{filter_relevant_txs, TxFilterRule};

use crate::bitcoin::{
    checkpoint::verify_checkpoint_and_extract_info, claim_txn::get_claim_txn,
    header_chain::verify_l1_chain, payment_txn::get_payment_txn, primitives::WithdrwalInfo,
};

pub struct ProcessBlockOutput {
    deposit_utxo: Txid,
    withdrawl_txn: Txid,
    super_block_hash: Buf32,
    ts: u32,
}

pub struct CheckpointInput {
    block: Block,
    chain_state: ChainState,
    out_ref: OutputRef,
}

pub struct ProcessBlocksInput {
    checkpoint_input: CheckpointInput,
    payment_txn_block: Block,
    claim_txn_block: Block,
    ts_block_header: Header,
    headers: Vec<Header>,
    start_header_state: HeaderVerificationState,
}

pub fn process_blocks(input: ProcessBlocksInput) -> ProcessBlockOutput {
    let CheckpointInput {
        block: ckp_block,
        chain_state,
        out_ref,
    } = input.checkpoint_input;

    let (ckp_withdrawl_info, batch_info) =
        verify_checkpoint_and_extract_info(&ckp_block, &chain_state, &out_ref);

    // TODO: Actual parsing of the payment txn
    // TODO: Match the info from `ckp_withdrawl_info` & `payment_txn_info`
    let payment_txn_info = get_payment_txn(&input.payment_txn_block);

    // TODO: Actual parsing of the claim txn
    // TODO: assert ts_block_header.timestamp == claim_txn_info.ts
    // TODO: Link the `operator_withdrawl_info` and `claim_txn`
    let claim_txn_info = get_claim_txn(&input.claim_txn_block);

    // Ensure the block we scan falls inside the L1 fragment
    let params = get_btc_params();
    let header_inclusions = [
        compute_block_hash(&ckp_block.header),
        compute_block_hash(&input.payment_txn_block.header),
        compute_block_hash(&input.claim_txn_block.header),
    ];

    let ts_block_hash = compute_block_hash(&input.ts_block_header);
    let super_block_hash = verify_l1_chain(
        &input.start_header_state,
        &input.headers,
        &params,
        ts_block_hash,
        header_inclusions.to_vec(),
    );

    ProcessBlockOutput {
        deposit_utxo: out_ref.outpoint().txid,
        withdrawl_txn: claim_txn_info.1,
        super_block_hash,
        ts: input.ts_block_header.time,
    }
}

#[cfg(test)]
mod test {
    use bitcoin::block::Header;
    use prover_test_utils::{get_bitcoin_client, get_chain_state, get_header_verification_data};
    use strata_btcio::rpc::{traits::Reader, BitcoinClient};
    use strata_primitives::buf::Buf32;
    use strata_state::l1::compute_block_hash;

    use crate::l1_sement::{process_blocks, CheckpointInput, ProcessBlocksInput};

    #[tokio::test]
    async fn test_process_blocks() {
        // Block numbers for the test
        let genesis_block: u64 = 0;
        let ckp_block_num: u64 = 509;
        let start_block_num: u64 = ckp_block_num - 1;
        let end_block_num = 513;

        // Transaction block numbers
        let payment_txn_block_num: u64 = 510;
        let ts_block_num: u64 = 511;
        let claim_txn_block_num: u64 = 512;

        // Retrieve header verification data
        let (start_header_state, headers) =
            get_header_verification_data(start_block_num, end_block_num, genesis_block).await;

        // Initialize Bitcoin client
        let btc_client = get_bitcoin_client();

        // Fetch necessary blocks
        let ckp_block = btc_client.get_block_at(ckp_block_num).await.unwrap();
        let payment_txn_block = btc_client
            .get_block_at(payment_txn_block_num)
            .await
            .unwrap();
        let ts_block_header = btc_client.get_block_at(ts_block_num).await.unwrap().header;
        let claim_txn_block = btc_client.get_block_at(claim_txn_block_num).await.unwrap();

        // Prepare checkpoint input
        let (chain_state, out_ref) = get_chain_state();
        let checkpoint_input = CheckpointInput {
            block: ckp_block,
            chain_state,
            out_ref,
        };

        // Prepare process_blocks input
        let process_blocks_input = ProcessBlocksInput {
            checkpoint_input,
            payment_txn_block,
            claim_txn_block,
            ts_block_header,
            headers,
            start_header_state,
        };

        // Process the blocks
        let res = process_blocks(process_blocks_input);
    }
}
