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
    use prover_test_utils::{get_bitcoin_client, get_chain_state, get_header_verification_data};
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
}
