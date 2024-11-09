#![allow(unused)]
use strata_state::{
    chain_state::ChainState,
    l1::{compute_block_hash, get_btc_params},
};

use crate::{
    bitcoin::{
        checkpoint::verify_checkpoint_and_extract_info, claim_txn::get_claim_txn,
        header_chain::verify_l1_chain, payment_txn::get_payment_txn,
    },
    primitives::{BridgeProofPublicParams, CheckpointInput},
    BridgeProofInput,
};

pub fn process_bridge_proof(
    input: BridgeProofInput,
    chain_state: ChainState,
) -> BridgeProofPublicParams {
    let CheckpointInput {
        block: ckp_block,
        out_ref,
    } = input.checkpoint_input;

    let (ckp_withdrawl_info, batch_info) =
        verify_checkpoint_and_extract_info(&ckp_block, &chain_state, &out_ref);

    let payment_txn_info = get_payment_txn(&input.payment_txn_block, input.payment_txn_idx);
    assert_eq!(payment_txn_info, ckp_withdrawl_info);

    // TODO: Link the `operator_withdrawl_info` and `claim_txn`
    let claim_txn_info = get_claim_txn(&input.claim_txn_block, input.claim_txn_idx);
    assert_eq!(input.ts_block_header.time, claim_txn_info.0);

    // Ensure the block we scan falls inside the L1 fragment
    let params = get_btc_params();
    let header_inclusions = [
        compute_block_hash(&ckp_block.header),
        compute_block_hash(&input.payment_txn_block.header),
        compute_block_hash(&input.ts_block_header),
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
    use std::{
        fs::File,
        io::{Chain, Write},
    };

    use prover_test_utils::{get_bitcoin_client, get_chain_state, get_header_verification_data};
    use strata_btcio::rpc::traits::Reader;
    use strata_primitives::buf::Buf32;
    use strata_state::{
        batch::BatchCheckpoint, block::L2Block, chain_state::ChainState, tx::ProtocolOperation,
    };
    use strata_tx_parser::filter::{filter_relevant_txs, TxFilterRule};

    use crate::bridge_proof::{process_bridge_proof, BridgeProofInput, CheckpointInput};

    fn save_prover_input(
        process_blocks_input: &BridgeProofInput,
        chain_state: &ChainState,
        bridge_proof_path: &str,
        chain_state_path: &str,
    ) {
        let bridge_proof_ip_ser = bincode::serialize(process_blocks_input).unwrap();
        let chain_state_ser = borsh::to_vec(chain_state).unwrap();

        // Write serialized ChainState to file
        let mut chain_state_file = File::create(chain_state_path).unwrap();
        chain_state_file.write_all(&chain_state_ser).unwrap();

        // Write serialized Bridge proof input to file
        let mut bridge_proof_file = File::create(bridge_proof_path).unwrap();
        bridge_proof_file.write_all(&bridge_proof_ip_ser).unwrap();
    }

    async fn get_all_checkpoint_infos(from: u64, to: u64) -> Vec<(u64, BatchCheckpoint)> {
        // Initialize Bitcoin client
        let btc_client = get_bitcoin_client();
        let mut checkpoints = vec![];

        for height in from..to {
            let block = btc_client.get_block_at(height).await.unwrap();
            let tx_filters = [TxFilterRule::RollupInscription("alpenstrata".to_string())];
            let relevant_txs = filter_relevant_txs(&block, &tx_filters);

            for tx in relevant_txs {
                if let ProtocolOperation::RollupInscription(signed_batch) = tx.proto_op() {
                    // TODO: Apply cred rule
                    let batch: BatchCheckpoint = signed_batch.clone().into();
                    checkpoints.push((height, batch));
                }
            }
        }
        checkpoints
    }

    #[tokio::test]
    async fn test_checkpoint() {
        let checkpoints = get_all_checkpoint_infos(1910, 1950).await;
        dbg!(checkpoints);
    }

    #[tokio::test]
    async fn find_superblock() {
        // Initialize Bitcoin client
        let btc_client = get_bitcoin_client();

        let start = 101;
        let end = 110;

        let mut super_block = Buf32([u8::MAX; 32].into());
        for height in start..end {
            let block_hash = btc_client.get_block_hash(height).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_process_blocks() {
        // Block numbers for the test
        let genesis_block: u64 = 0;

        let ckp_block_num: u64 = 1919;
        let start_block_num: u64 = ckp_block_num - 1;
        let end_block_num = 2100;

        // Transaction block numbers
        let payment_txn_block_num: u64 = 1931;
        let ts_block_num: u64 = payment_txn_block_num + 1;
        let claim_txn_block_num: u64 = 1949;

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
            out_ref,
        };

        // Prepare process_blocks input
        let process_blocks_input = BridgeProofInput {
            checkpoint_input,
            payment_txn_block,
            claim_txn_block,
            ts_block_header,
            claim_txn_idx: 2,
            payment_txn_idx: 1,
            headers,
            start_header_state,
        };

        // Save file paths
        let bridge_proof_path = "inputs/process_blocks_input.bin";
        let chain_state_path = "inputs/chain_state.bin";
        save_prover_input(
            &process_blocks_input,
            &chain_state,
            bridge_proof_path,
            chain_state_path,
        );

        // Process the blocks
        let res = process_bridge_proof(process_blocks_input, chain_state);
    }
}
