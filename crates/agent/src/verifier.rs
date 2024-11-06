use bitcoin::{hex::DisplayHex, ScriptBuf, Transaction, Txid};
use bitvm::{groth16::g16, signatures::wots::SignatureImpl, treepp::*};
use rand::RngCore;
use strata_bridge_db::{connector_db::ConnectorDb, public::PublicDb};
use strata_bridge_primitives::{
    build_context::{BuildContext, TxBuildContext},
    scripts::{
        parse_witness::{parse_assertion_witnesses, parse_claim_witness},
        prelude::hash_to_bn254_fq,
        wots::{bridge_poc_verification_key, Signatures},
    },
    types::OperatorIdx,
};
use strata_bridge_tx_graph::{
    connectors::prelude::ConnectorA31Leaf,
    transactions::constants::{NUM_ASSERT_DATA_TX1, NUM_ASSERT_DATA_TX2},
};
use tokio::sync::broadcast;
use tracing::info;

use crate::base::Agent;

#[derive(Clone, Debug)]
pub enum VerifierDuty {
    VerifyClaim {
        operator_idx: OperatorIdx,
        deposit_txid: Txid,

        claim_tx: Transaction,
    },
    VerifyAssertions {
        operator_idx: OperatorIdx,
        deposit_txid: Txid,

        claim_tx: Transaction,
        assert_data_txs: [Transaction; NUM_ASSERT_DATA_TX1 + NUM_ASSERT_DATA_TX2],
    },
}

pub type VerifierIdx = u32;

#[derive(Debug)]
pub struct Verifier {
    pub agent: Agent,

    build_context: TxBuildContext,

    public_db: PublicDb,
}

impl Verifier {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(agent: Agent, build_context: TxBuildContext, public_db: PublicDb) -> Self {
        let mut msk_bytes: [u8; 32] = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut msk_bytes);

        let msk = msk_bytes.to_lower_hex_string();

        Self {
            agent,
            build_context,
            public_db,
        }
    }

    pub async fn start(&mut self, duty_receiver: &mut broadcast::Receiver<VerifierDuty>) {
        info!(action = "starting operator", operator_idx=%self.build_context.own_index());

        while let Ok(bridge_duty) = duty_receiver.recv().await {
            self.process_event(bridge_duty).await;
        }
    }

    pub async fn process_event(&mut self, duty: VerifierDuty) {
        match duty {
            VerifierDuty::VerifyClaim {
                operator_idx,
                deposit_txid,
                claim_tx,
            } => {
                println!("No challenging yet!");
            }
            VerifierDuty::VerifyAssertions {
                operator_idx,
                deposit_txid,
                claim_tx,
                assert_data_txs,
            } => {
                // parse claim tx
                let claim_witness_script = script!().push_script(ScriptBuf::from_bytes(
                    claim_tx
                        .input
                        .first()
                        .unwrap()
                        .witness
                        .to_vec()
                        .first()
                        .unwrap()
                        .clone(),
                ));
                let (superblock_period_start_ts, bridge_out_txid) =
                    parse_claim_witness(claim_witness_script);

                // parse assert data txs
                let (witness160, mut witness256): (Vec<Vec<Script>>, Vec<Script>) = assert_data_txs
                    [..NUM_ASSERT_DATA_TX1]
                    .iter()
                    .map(|tx| {
                        let witness_scripts = tx
                            .input
                            .iter()
                            .map(|txin| {
                                script!().push_script(ScriptBuf::from_bytes(
                                    txin.witness.to_vec()[0].clone(),
                                ))
                            })
                            .collect::<Vec<_>>();
                        let witness_scripts = witness_scripts.split_at(10);
                        (witness_scripts.0.to_vec(), witness_scripts.1[0].clone())
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .unzip();

                let mut witness160 = witness160.into_iter().flatten().collect::<Vec<_>>();

                let residuals = assert_data_txs[NUM_ASSERT_DATA_TX1]
                    .input
                    .iter()
                    .map(|txin| {
                        script!()
                            .push_script(ScriptBuf::from_bytes(txin.witness.to_vec()[0].clone()))
                    })
                    .collect::<Vec<_>>();

                witness160.extend(residuals[..2].to_vec());

                witness256.push(residuals[3].clone());

                let assert_sigs = parse_assertion_witnesses(
                    witness256.try_into().unwrap(),
                    None,
                    witness160.try_into().unwrap(),
                    Some(residuals[2].clone()),
                );

                let (superblock_hash, groth16) = (assert_sigs);

                let mut signatures = Signatures {
                    bridge_out_txid,
                    superblock_hash,
                    superblock_period_start_ts,
                    groth16,
                };

                let public_keys = self
                    .public_db
                    .get_wots_public_keys(operator_idx, deposit_txid)
                    .await;

                let connector_leaf = {
                    // 1. public input hash validation
                    let public_inputs = (
                        deposit_txid,
                        superblock_hash.parse(),
                        bridge_out_txid.parse(),
                        superblock_period_start_ts,
                    );
                    let serialized_public_inputs = bincode::serialize(&public_inputs).unwrap();
                    let public_inputs_hash = hash_to_bn254_fq(&serialized_public_inputs);
                    let committed_public_inputs_hash = groth16.0[0].parse();
                    if public_inputs_hash != committed_public_inputs_hash {
                        Some(ConnectorA31Leaf::InvalidatePublicDataHash(Some((
                            superblock_hash,
                            bridge_out_txid,
                            superblock_period_start_ts,
                            groth16.0[0],
                        ))))
                    } else {
                        // 2. do superblock validation
                        let is_superblock_invalid = false;
                        if is_superblock_invalid {
                            None
                        } else {
                            // 3. groth16 proof validation
                            if let Some((tapleaf_index, witness_script)) =
                                g16::verify_signed_assertions(
                                    bridge_poc_verification_key(),
                                    public_keys.groth16,
                                    signatures.groth16,
                                )
                            {
                                let disprove_script = g16::generate_disprove_scripts(
                                    public_keys.groth16,
                                    &self.public_db.get_partial_disprove_scripts().await,
                                )[tapleaf_index]
                                    .clone();
                                Some(ConnectorA31Leaf::InvalidateProof((
                                    disprove_script,
                                    Some(witness_script),
                                )))
                            } else {
                                None
                            }
                        }
                    }
                };

                if let Some(connector_leaf) = connector_leaf {
                    // build graph for operator_idx, and deposit_txid
                    // finalize disprove tx and submit to bitcoin
                }
            }
        }
    }
}
