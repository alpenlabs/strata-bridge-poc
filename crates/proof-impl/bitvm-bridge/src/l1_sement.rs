#![allow(unused)]
use bitcoin::{block::Header, Block};
use strata_proofimpl_btc_blockspace::block::{check_merkle_root, check_witness_commitment};
use strata_state::{
    batch::BatchCheckpoint,
    l1::{BtcParams, HeaderVerificationState},
    tx::ProtocolOperation,
};
use strata_tx_parser::filter::{filter_relevant_txs, TxFilterRule};

pub fn verify_l1_chain(
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

pub fn filter_out_checkpoint(block: &Block) -> BatchCheckpoint {
    assert!(check_merkle_root(block));
    assert!(check_witness_commitment(block));

    let tx_filters = [TxFilterRule::RollupInscription("strata".to_string())];
    get_batch_checkpoint(block, tx_filters.to_vec()).unwrap()
}

fn get_batch_checkpoint(block: &Block, tx_filters: Vec<TxFilterRule>) -> Option<BatchCheckpoint> {
    let relevant_txs = filter_relevant_txs(block, &tx_filters);
    for tx in relevant_txs {
        if let ProtocolOperation::RollupInscription(signed_batch) = tx.proto_op() {
            // TODO: Apply cred rule
            let batch: BatchCheckpoint = signed_batch.clone().into();
            return Some(batch);
        }
    }
    None
}

#[cfg(test)]
mod test {
    use bitcoin::block::Header;
    use strata_btcio::{
        reader::query::get_verification_state,
        rpc::{traits::Reader, BitcoinClient},
    };
    use strata_state::l1::{get_btc_params, HeaderVerificationState};

    use crate::l1_sement::{filter_out_checkpoint, verify_l1_chain};

    #[tokio::test]
    async fn test_bitcoin() {
        let geneis_block = 0;
        let start_block = 501;
        let end_block = 503;

        let (block_hvs, headers) =
            get_header_verification_data(start_block, end_block, geneis_block).await;

        let params = get_btc_params();
        let res = verify_l1_chain(&block_hvs, &headers, &params);
        println!("got the res {:?} ", res.compute_final_snapshot())
    }

    #[tokio::test]
    async fn get_checkpoint_data() {
        let block_num: u64 = 502;
        let btc_client = get_bitcoin_client();
        let block = btc_client.get_block_at(block_num).await.unwrap();

        let batch_checkpoint = filter_out_checkpoint(&block);
        println!("Got the batch checkpoint {:?}", batch_checkpoint)
    }

    async fn get_header_verification_data(
        start_block: u64,
        end_block: u64,
        genesis_block_num: u64,
    ) -> (HeaderVerificationState, Vec<Header>) {
        let btc_client = get_bitcoin_client();
        let params = get_btc_params();

        let block_hvs =
            get_verification_state(&btc_client, start_block, genesis_block_num, &params)
                .await
                .unwrap();

        let mut headers: Vec<Header> = Vec::new();
        for block_num in start_block..=end_block {
            let block = btc_client.get_block_at(block_num).await.unwrap();
            let header = block.header;
            headers.push(header);
        }

        let params = get_btc_params();

        (block_hvs, headers)
    }

    fn get_bitcoin_client() -> BitcoinClient {
        BitcoinClient::new(
            "http://127.0.0.1:12423".to_string(),
            "alpen".to_string(),
            "alpen".to_string(),
        )
        .expect("failed to connect to the btc client")
    }
}
