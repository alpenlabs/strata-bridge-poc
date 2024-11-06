#![allow(unused)]
use bitcoin::{block::Header, Block};
use strata_primitives::{
    buf::Buf32,
    l1::{BitcoinAmount, XOnlyPk},
};
use strata_proofimpl_btc_blockspace::block::{check_merkle_root, check_witness_commitment};
use strata_state::{
    batch::BatchCheckpoint,
    bridge_state::DepositState,
    chain_state::ChainState,
    l1::{BtcParams, HeaderVerificationState},
    tx::ProtocolOperation,
};
use strata_tx_parser::filter::{filter_relevant_txs, TxFilterRule};

pub fn process_proof_1(check_point_block: Block, chain_state: ChainState) {
    let ckp = filter_out_checkpoint(&check_point_block);
    let (operator_pk, withdraw_info, ckp_state_root) = parse_chain_state(chain_state);
    assert_eq!(*ckp.batch_info().final_l2_state_hash(), ckp_state_root)
}

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
    let batch_info = get_batch_checkpoint(block, tx_filters.to_vec()).unwrap();

    let proof = batch_info.proof();
    if proof.is_empty() {
        println!("Accepting with the emptry proof")
    }

    batch_info
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

fn parse_chain_state(chain_state: ChainState) -> (Buf32, (XOnlyPk, BitcoinAmount), Buf32) {
    let operator_table = chain_state.operator_table();
    let deposit_table = chain_state.deposits_table();

    // TODO: Is this the actaul way to handle the deposit entry ??
    let latest_deposit = deposit_table.len() - 1;
    let deposit_entry = deposit_table.get_deposit(latest_deposit).unwrap();

    // We need the deposit state in `DepositState::Dispatched`
    if let DepositState::Dispatched(deposit_state) = deposit_entry.deposit_state() {
        // Operator
        let operator_idx = deposit_state.assignee();
        let operator = operator_table.get_entry_at_pos(operator_idx).unwrap();
        let operator_pk = operator.wallet_pk();

        // Destination info
        let withdraw_output = deposit_state.cmd().withdraw_outputs().first().unwrap();
        let dest_address = withdraw_output.dest_addr();
        // TODO: BitcoinAmt is always fixed right ???
        let amt = BitcoinAmount::from_sat(1000000000);

        // Chain state root
        let chain_root = chain_state.compute_state_root();

        return (*operator_pk, (*dest_address, amt), chain_root);
    }
    panic!("deposit state not in `DepositState::Dispatched`")
}

// Paid to the user Tap Scripit
// OP Return has the Operator info
// Find these infos and return the:
// i)  User <Address, Aamt>
// ii) Operator address
fn get_payment_txn(block: &Block) -> (u64, Vec<u8>, Vec<u8>) {
    assert!(check_merkle_root(block));
    assert!(check_witness_commitment(block));

    let amt: u64 = 10;
    let dest_addrs: Vec<u8> = Vec::new();
    let operator_address: Vec<u8> = Vec::new();

    (amt, dest_addrs, operator_address)
}

// Ts is commited in the Claim Transaction
fn get_claim_txn(block: &Block) -> u32 {
    assert!(check_merkle_root(block));
    assert!(check_witness_commitment(block));

    // TODO: Filter out the claim txn and parse the Ts
    block.header.time
}

#[cfg(test)]
mod test {
    use bitcoin::block::Header;
    use strata_btcio::{
        reader::query::get_verification_state,
        rpc::{traits::Reader, BitcoinClient},
    };
    use strata_state::{
        block::L2Block,
        chain_state::ChainState,
        l1::{get_btc_params, HeaderVerificationState},
    };

    use super::parse_chain_state;
    use crate::l1_sement::{filter_out_checkpoint, process_proof_1, verify_l1_chain};

    fn get_chain_state() -> ChainState {
        let witness_buf: Vec<u8> = vec![
            77, 159, 210, 174, 194, 181, 134, 6, 61, 216, 221, 4, 119, 78, 48, 47, 88, 175, 72,
            158, 122, 231, 97, 84, 254, 179, 113, 45, 21, 91, 98, 116, 8, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 234, 1, 0, 0, 0, 0, 0, 0, 150, 4, 254, 217, 246, 41, 96, 211, 179,
            207, 39, 146, 139, 117, 63, 56, 140, 158, 37, 196, 246, 222, 150, 170, 169, 78, 116,
            113, 179, 110, 28, 20, 80, 0, 0, 0, 0, 0, 0, 32, 248, 240, 210, 61, 76, 248, 123, 24,
            140, 51, 246, 139, 111, 60, 78, 45, 235, 83, 237, 124, 113, 183, 51, 19, 109, 209, 168,
            162, 166, 124, 236, 20, 230, 46, 18, 139, 229, 42, 0, 135, 102, 157, 243, 191, 233,
            192, 49, 143, 177, 176, 239, 234, 232, 106, 141, 102, 180, 181, 7, 69, 42, 236, 94,
            174, 229, 196, 42, 103, 255, 255, 127, 32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 250, 1, 0, 0, 0, 0, 0,
            0, 1, 0, 0, 0, 104, 254, 8, 167, 103, 150, 94, 70, 118, 208, 19, 250, 141, 58, 32, 51,
            208, 116, 4, 215, 119, 165, 182, 69, 67, 147, 255, 34, 131, 62, 197, 57, 80, 0, 0, 0,
            0, 0, 0, 32, 150, 4, 254, 217, 246, 41, 96, 211, 179, 207, 39, 146, 139, 117, 63, 56,
            140, 158, 37, 196, 246, 222, 150, 170, 169, 78, 116, 113, 179, 110, 28, 20, 130, 109,
            74, 37, 119, 193, 136, 149, 44, 16, 227, 88, 11, 206, 151, 119, 15, 113, 77, 119, 7,
            82, 197, 186, 104, 107, 93, 134, 210, 178, 114, 62, 230, 196, 42, 103, 255, 255, 127,
            32, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 55, 173, 97, 207, 241, 54, 116, 103, 169,
            140, 247, 197, 76, 74, 201, 158, 152, 159, 31, 187, 27, 193, 230, 70, 35, 94, 144, 192,
            101, 197, 101, 186, 0, 0, 0, 0, 53, 23, 20, 175, 114, 215, 66, 89, 244, 92, 215, 234,
            176, 176, 69, 39, 205, 64, 231, 72, 54, 164, 90, 188, 174, 80, 249, 45, 145, 157, 152,
            143, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 180, 99, 76, 81, 90, 98, 228, 123,
            63, 62, 182, 43, 138, 111, 99, 32, 253, 178, 186, 237, 95, 46, 102, 87, 244, 114, 176,
            242, 163, 50, 33, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 187, 177, 235, 115, 143, 26, 170,
            28, 57, 206, 46, 176, 164, 233, 103, 39, 63, 115, 89, 228, 170, 88, 209, 63, 242, 126,
            194, 72, 108, 217, 17, 111, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 202, 154, 59, 0, 0,
            0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 53, 20, 168, 17, 23, 67, 166, 129, 84, 214, 217, 242,
            165, 52, 67, 152, 130, 105, 121, 244, 0, 246, 129, 165, 39, 188, 20, 205, 197, 45, 27,
            93, 0, 202, 154, 59, 0, 0, 0, 0, 0, 0, 0, 0, 57, 2, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0,
            0, 0, 214, 57, 16, 255, 146, 1, 0, 0, 77, 159, 210, 174, 194, 181, 134, 6, 61, 216,
            221, 4, 119, 78, 48, 47, 88, 175, 72, 158, 122, 231, 97, 84, 254, 179, 113, 45, 21, 91,
            98, 116, 231, 133, 68, 128, 66, 228, 177, 55, 90, 209, 208, 41, 99, 213, 55, 101, 208,
            176, 255, 139, 183, 247, 149, 138, 39, 16, 167, 24, 206, 234, 136, 133, 7, 31, 84, 78,
            149, 196, 201, 161, 158, 26, 70, 142, 171, 53, 32, 130, 73, 209, 31, 251, 9, 16, 52,
            220, 113, 76, 211, 225, 251, 232, 106, 112, 149, 97, 209, 6, 79, 49, 12, 54, 70, 38,
            228, 27, 154, 127, 146, 223, 217, 58, 236, 16, 77, 108, 53, 249, 171, 230, 118, 130,
            73, 232, 7, 48, 215, 77, 206, 234, 176, 177, 14, 106, 59, 171, 45, 104, 90, 53, 233,
            194, 207, 219, 168, 175, 69, 177, 98, 58, 96, 64, 212, 45, 231, 46, 21, 152, 109, 74,
            129, 49, 100, 83, 196, 153, 112, 249, 108, 131, 84, 226, 237, 176, 186, 144, 58, 212,
            140, 239, 97, 181, 124, 244, 57, 79, 77, 120, 15, 226, 1, 0, 0, 0, 251, 1, 0, 0, 0, 0,
            0, 0, 227, 165, 76, 116, 117, 70, 16, 75, 95, 27, 52, 151, 6, 101, 177, 200, 25, 76,
            94, 56, 130, 172, 147, 253, 126, 218, 210, 115, 36, 196, 238, 92, 80, 0, 0, 0, 0, 0, 0,
            32, 104, 254, 8, 167, 103, 150, 94, 70, 118, 208, 19, 250, 141, 58, 32, 51, 208, 116,
            4, 215, 119, 165, 182, 69, 67, 147, 255, 34, 131, 62, 197, 57, 222, 227, 121, 239, 106,
            95, 211, 8, 141, 121, 91, 86, 131, 170, 216, 176, 29, 95, 149, 238, 17, 227, 208, 91,
            106, 201, 127, 83, 162, 140, 195, 228, 230, 196, 42, 103, 255, 255, 127, 32, 0, 0, 0,
            0, 39, 203, 11, 224, 201, 108, 211, 115, 181, 89, 105, 136, 27, 142, 68, 177, 223, 211,
            192, 187, 12, 47, 15, 114, 132, 54, 22, 18, 248, 3, 46, 48, 0, 0, 0, 0, 0, 0, 0, 0, 9,
            0, 0, 0, 0, 0, 0, 0, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192,
            248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 32, 0,
            0, 0, 238, 64, 209, 161, 157, 231, 202, 7, 240, 43, 24, 86, 139, 210, 28, 122, 62, 157,
            74, 127, 95, 70, 111, 64, 239, 11, 185, 224, 188, 151, 146, 109, 0, 0, 0, 0, 11, 128,
            189, 78, 236, 14, 79, 208, 62, 102, 249, 194, 168, 146, 208, 20, 216, 118, 250, 217,
            162, 254, 205, 131, 43, 154, 63, 199, 59, 174, 196, 138, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let (chain_state, _): (ChainState, L2Block) = borsh::from_slice(&witness_buf).unwrap();
        chain_state
    }

    #[tokio::test]
    async fn test_ckp() {
        let chain_state = get_chain_state();
        let block_num: u64 = 509;
        let btc_client = get_bitcoin_client();
        let block = btc_client.get_block_at(block_num).await.unwrap();

        process_proof_1(block, chain_state);
    }

    #[test]
    fn check_chain_state() {
        let chain_state = get_chain_state();
        let infos = parse_chain_state(chain_state);
        println!("{:#?}", infos);
    }

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
        let block_num: u64 = 509;
        let btc_client = get_bitcoin_client();
        let block = btc_client.get_block_at(block_num).await.unwrap();

        let batch_checkpoint = filter_out_checkpoint(&block);
        println!("Got the batch checkpoint {:#?}", batch_checkpoint)
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
