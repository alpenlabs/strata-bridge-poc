#![allow(unused)]
use strata_state::l1::{compute_block_hash, get_btc_params};

use crate::{
    bitcoin::{
        checkpoint::verify_checkpoint_and_extract_info, claim_txn::get_claim_txn,
        header_chain::verify_l1_chain, payment_txn::get_payment_txn,
    },
    primitives::{BridgeProofPublicParams, CheckpointInput},
    BridgeProofInput,
};

pub fn process_bridge_proof(input: BridgeProofInput) -> BridgeProofPublicParams {
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

    /// BridgeProofPublicParams
    /// Contains:
    ///
    /// - `0`: The Deposit UTXO.
    /// - `1`: The Payment Transaction.
    /// - `2`: The Super Block Hash.
    /// - `3`: The timestamp of the TS block.
    (
        *out_ref.outpoint().txid.as_ref(),
        *claim_txn_info.1.as_ref(),
        *super_block_hash.as_ref(),
        input.ts_block_header.time,
    )
}

#[cfg(test)]
mod test {
    use prover_test_utils::{get_bitcoin_client, get_chain_state, get_header_verification_data};
    use strata_btcio::rpc::traits::Reader;

    use crate::bridge_proof::{process_bridge_proof, BridgeProofInput, CheckpointInput};

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
        let process_blocks_input = BridgeProofInput {
            checkpoint_input,
            payment_txn_block,
            claim_txn_block,
            ts_block_header,
            headers,
            start_header_state,
        };

        // Process the blocks
        let res = process_bridge_proof(process_blocks_input);
    }
}
