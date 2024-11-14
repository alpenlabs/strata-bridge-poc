#![allow(unused)]
use bitcoin::hashes::Hash;
use borsh::BorshDeserialize;
use strata_primitives::{
    buf::Buf32,
    l1::{BitcoinAmount, XOnlyPk},
};
use strata_state::{
    batch::{BatchCheckpoint, SignedBatchCheckpoint},
    bridge_state::DepositState,
    chain_state::ChainState,
    header,
    l1::{compute_block_hash, get_btc_params},
};
use strata_tx_parser::inscription::parse_inscription_data;

use crate::{
    bitcoin::{
        checkpoint::verify_checkpoint_and_extract_info,
        claim_txn::{get_claim_txn, parse_claim_witness},
        header_chain::verify_l1_chain,
        payment_txn::get_payment_txn,
    },
    ckp_verifier::{verify_groth16, STRATA_CKP_VERIFICATION_KEY},
    primitives::{BridgeProofPublicParams, StrataBridgeState},
    BridgeProofInput,
};

pub const ROLLUP_NAME: &str = "alpenstrata";
pub const SUPERBLOCK_PERIOD_BLOCK_INTERVAL: usize = 5;

pub fn process_bridge_proof(
    input: BridgeProofInput,
    strata_bridge_state: StrataBridgeState,
) -> Result<BridgeProofPublicParams, Box<dyn std::error::Error>> {
    let BridgeProofInput {
        headers,
        deposit_txid,
        checkpoint: (checkpoint_height, checkpoint),
        bridge_out: (bridge_out_height, bridge_out),
        superblock_period_start_ts,
        initial_header_state,
    } = input;

    let params = &get_btc_params();

    if bridge_out_height <= checkpoint_height {
        return Err("bridge_out before checkpoint".into());
    }
    let checkpoint_header_index =
        (checkpoint_height - initial_header_state.last_verified_block_num - 1) as usize;
    let bridge_out_header_index =
        (bridge_out_height - initial_header_state.last_verified_block_num - 1) as usize;

    // verify header chain
    let header_hashes = {
        let mut state = initial_header_state.clone();
        headers
            .iter()
            .map(|header| {
                state = state.check_and_update_continuity_new(header, params);
                state.last_verified_block_hash
            })
            .collect::<Vec<_>>()
    };

    // verify checkpoint inclusion proof
    checkpoint
        .verify(&headers[checkpoint_header_index])
        .map_err(|err| "invalid checkpoint tx: non-inclusion")?;

    // verify bridge_out inclusion proof
    bridge_out
        .verify(&headers[bridge_out_header_index])
        .map_err(|err| "invalid bridge_out tx: non-inclusion")?;

    // superblock hash and blocks count
    let (superblock_hash, superblock_period_blocks_count) = headers.iter().zip(header_hashes).fold(
        ([u8::MAX; 32], 0),
        |(mut superblock_hash, mut superblock_period_blocks_count), (header, hash)| {
            if header.time > superblock_period_start_ts
                && superblock_period_blocks_count < SUPERBLOCK_PERIOD_BLOCK_INTERVAL
            {
                superblock_period_blocks_count += 1;
                if hash.as_ref() < &superblock_hash {
                    superblock_hash = *hash.as_ref();
                }
            }
            (superblock_hash, superblock_period_blocks_count)
        },
    );
    assert!(superblock_period_blocks_count >= SUPERBLOCK_PERIOD_BLOCK_INTERVAL);

    // TODO: parse and validate bridge out tx
    let (operator_id, withdrawal_address, withdrawal_amount) = {
        assert!(
            bridge_out.tx.0.output.len() >= 2,
            "bridge-out: not enough outputs!"
        );
        let operator_id = u32::from_be_bytes(
            bridge_out.tx.0.output[0].script_pubkey.as_bytes()[2..6]
                .try_into()
                .expect("invalid operator id"),
        );
        let withdrawal_amount = BitcoinAmount::from_sat(bridge_out.tx.0.output[1].value.to_sat());
        let withdrawal_address =
            XOnlyPk::try_from_slice(&bridge_out.tx.0.output[1].script_pubkey.as_bytes()[2..])
                .expect("invalid withdrawal address");
        (operator_id, withdrawal_address, withdrawal_amount)
    };

    // verify checkpoint proof and withdrawal state
    {
        assert!(!checkpoint.tx.0.input.is_empty());

        // extract batch checkpoint from checkpoint tx
        let script = checkpoint.tx.0.input[0].witness.tapscript().unwrap();
        let inscription = parse_inscription_data(&script.into(), ROLLUP_NAME).unwrap();
        let batch_checkpoint: BatchCheckpoint =
            borsh::from_slice::<SignedBatchCheckpoint>(inscription.batch_data())
                .unwrap()
                .into();

        let batch_checkpoint_proof = batch_checkpoint.proof();
        // TODO: Fix this
        if !batch_checkpoint_proof.is_empty() {
            let public_params = borsh::to_vec(&batch_checkpoint.proof_output()).unwrap();
            assert!(
                verify_groth16(
                    batch_checkpoint_proof,
                    STRATA_CKP_VERIFICATION_KEY.as_ref(),
                    &public_params
                ),
                "Invalid checkpoint proof!"
            );
        }

        let batch_info = batch_checkpoint.batch_info();

        assert_eq!(
            batch_info.final_l2_state_hash().clone(),
            strata_bridge_state.compute_state_root()
        );

        let StrataBridgeState {
            deposits_table,
            hashed_chain_state,
        } = strata_bridge_state;

        let entry = deposits_table
            .deposits()
            .find(|&el| el.output().outpoint().txid.to_byte_array() == deposit_txid)
            .expect("Deposit entry not found for the given deposit_txid");

        // We need the deposit state in `DepositState::Dispatched`
        let dispatched_state = match entry.deposit_state() {
            DepositState::Dispatched(dispatched_state) => dispatched_state,
            _ => panic!("Invalid withdrawal!"),
        };

        let withdrawal = dispatched_state.cmd().withdraw_outputs().first().unwrap();

        assert_eq!(operator_id, dispatched_state.assignee());
        assert_eq!(withdrawal_address, withdrawal.dest_addr().clone());
        assert_eq!(withdrawal_amount, BitcoinAmount::from_sat(800000000));

        // dbg!(&batch_info);
        // dbg!(&initial_header_state.compute_hash().unwrap());

        // // TODO: Fix this; assertion is required
        // assert_eq!(
        //     batch_info.l1_transition.1,
        //     initial_header_state.compute_hash().unwrap(),
        //     "Invalid initial_header_state"
        // );
    }

    Ok(BridgeProofPublicParams {
        deposit_txid,
        superblock_hash,
        bridge_out_txid: bridge_out.tx.0.compute_txid().to_byte_array(),
        superblock_period_start_ts,
    })
}

// #[cfg(test)]
// mod test {
//     use std::{
//         fs::File,
//         io::{Chain, Write},
//     };

//     use prover_test_utils::{get_bitcoin_client, get_chain_state, get_header_verification_data};
//     use strata_btcio::rpc::traits::Reader;
//     use strata_primitives::buf::Buf32;
//     use strata_state::{
//         batch::BatchCheckpoint, block::L2Block, chain_state::ChainState, tx::ProtocolOperation,
//     };
//     use strata_tx_parser::filter::{filter_relevant_txs, TxFilterRule};

//     use crate::bridge_proof::{process_bridge_proof, BridgeProofInput, CheckpointInput};

//     fn save_prover_input(
//         process_blocks_input: &BridgeProofInput,
//         chain_state: &ChainState,
//         bridge_proof_path: &str,
//         chain_state_path: &str,
//     ) {
//         let bridge_proof_ip_ser = bincode::serialize(process_blocks_input).unwrap();
//         let chain_state_ser = borsh::to_vec(chain_state).unwrap();

//         // Write serialized ChainState to file
//         let mut chain_state_file = File::create(chain_state_path).unwrap();
//         chain_state_file.write_all(&chain_state_ser).unwrap();

//         // Write serialized Bridge proof input to file
//         let mut bridge_proof_file = File::create(bridge_proof_path).unwrap();
//         bridge_proof_file.write_all(&bridge_proof_ip_ser).unwrap();
//     }

//     async fn get_all_checkpoint_infos(from: u64, to: u64) -> Vec<(u64, BatchCheckpoint)> {
//         // Initialize Bitcoin client
//         let btc_client = get_bitcoin_client();
//         let mut checkpoints = vec![];

//         for height in from..to {
//             let block = btc_client.get_block_at(height).await.unwrap();
//             let tx_filters = [TxFilterRule::RollupInscription("alpenstrata".to_string())];
//             let relevant_txs = filter_relevant_txs(&block, &tx_filters);

//             for tx in relevant_txs {
//                 if let ProtocolOperation::RollupInscription(signed_batch) = tx.proto_op() {
//                     // TODO: Apply cred rule
//                     let batch: BatchCheckpoint = signed_batch.clone().into();
//                     checkpoints.push((height, batch));
//                 }
//             }
//         }
//         checkpoints
//     }

//     #[tokio::test]
//     async fn test_checkpoint() {
//         let checkpoints = get_all_checkpoint_infos(1910, 1950).await;
//         dbg!(checkpoints);
//     }

//     #[tokio::test]
//     async fn find_superblock() {
//         // Initialize Bitcoin client
//         let btc_client = get_bitcoin_client();

//         let start = 101;
//         let end = 110;

//         let mut super_block = Buf32([u8::MAX; 32].into());
//         for height in start..end {
//             let block_hash = btc_client.get_block_hash(height).await.unwrap();
//         }
//     }

//     #[tokio::test]
//     async fn test_process_blocks() {
//         // Block numbers for the test
//         let genesis_block: u64 = 0;

//         let ckp_block_num: u64 = 1919;
//         let start_block_num: u64 = ckp_block_num - 1;
//         let end_block_num = 2100;

//         // Transaction block numbers
//         let payment_txn_block_num: u64 = 1931;
//         let ts_block_num: u64 = payment_txn_block_num + 1;
//         let claim_txn_block_num: u64 = 1949;

//         // Retrieve header verification data
//         let (start_header_state, headers) =
//             get_header_verification_data(start_block_num, end_block_num, genesis_block).await;

//         // Initialize Bitcoin client
//         let btc_client = get_bitcoin_client();

//         // Fetch necessary blocks
//         let ckp_block = btc_client.get_block_at(ckp_block_num).await.unwrap();
//         let payment_txn_block = btc_client
//             .get_block_at(payment_txn_block_num)
//             .await
//             .unwrap();
//         let ts_block_header = btc_client.get_block_at(ts_block_num).await.unwrap().header;
//         let claim_txn_block = btc_client.get_block_at(claim_txn_block_num).await.unwrap();

//         // Prepare checkpoint input
//         let (chain_state, out_ref) = get_chain_state();
//         let checkpoint_input = CheckpointInput {
//             block: ckp_block,
//             out_ref,
//         };

//         // Prepare process_blocks input
//         let process_blocks_input = BridgeProofInput {
//             checkpoint_input,
//             payment_txn_block,
//             claim_txn_block,
//             ts_block_header,
//             claim_txn_idx: 2,
//             payment_txn_idx: 1,
//             headers,
//             start_header_state,
//         };

//         // Save file paths
//         let bridge_proof_path = "inputs/process_blocks_input.bin";
//         let chain_state_path = "inputs/chain_state.bin";
//         save_prover_input(
//             &process_blocks_input,
//             &chain_state,
//             bridge_proof_path,
//             chain_state_path,
//         );

//         // Process the blocks
//         let res = process_bridge_proof(process_blocks_input, chain_state);
//     }
// }
