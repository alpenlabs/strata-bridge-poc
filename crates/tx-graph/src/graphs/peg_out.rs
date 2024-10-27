use std::{
    collections::HashMap,
    fmt::{Display, Formatter, Result as FmtResult},
};

use bitcoin::{
    hex::{Case::Upper, DisplayHex},
    key::Keypair,
    Amount, Network, OutPoint, PublicKey, ScriptBuf, Txid, XOnlyPublicKey,
};
use esplora_client::{AsyncClient, Error, TxStatus};
use musig2::SecNonce;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use strata_bridge_contexts::{
    base::BaseContext, operator::OperatorContext, verifier::VerifierContext,
};

use super::{
    super::transactions::{
        assert::AssertTransaction,
        base::{
            validate_transaction, verify_public_nonces_for_tx, BaseTransaction, Input,
            InputWithScript,
        },
        challenge::ChallengeTransaction,
        claim::ClaimTransaction,
        disprove::DisproveTransaction,
        kick_off::KickOffTransaction,
        payout::PayoutTransaction,
        payout_optimistic::PayoutOptimisticTransaction,
        peg_out::PegOutTransaction,
        pre_signed::PreSignedTransaction,
    },
    base::{get_block_height, verify_if_not_mined, verify_tx_result, BaseGraph, GRAPH_VERSION},
    peg_in::PegInGraph,
};

#[derive(Debug)]
pub enum PegOutDepositorStatus {
    PegOutNotStarted, // peg-out transaction not created yet
    PegOutWait,       // peg-out not confirmed yet, wait
    PegOutComplete,   // peg-out complete
}

impl Display for PegOutDepositorStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            PegOutDepositorStatus::PegOutNotStarted => {
                write!(f, "Peg-out available. Request peg-out?")
            }
            PegOutDepositorStatus::PegOutWait => write!(f, "No action available. Wait..."),
            PegOutDepositorStatus::PegOutComplete => write!(f, "Peg-out complete. Done."),
        }
    }
}

#[derive(Debug)]
pub enum PegOutVerifierStatus {
    PegOutPresign,            // should presign peg-out graph
    PegOutComplete,           // peg-out complete
    PegOutWait,               // no action required, wait
    PegOutChallengeAvailable, // can call challenge
    PegOutStartTimeTimeoutAvailable,
    PegOutKickOffTimeoutAvailable,
    PegOutDisproveChainAvailable,
    PegOutDisproveAvailable,
    PegOutFailed, // timeouts or disproves executed
}

impl Display for PegOutVerifierStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            PegOutVerifierStatus::PegOutPresign => {
                write!(f, "Signatures required. Presign peg-out transactions?")
            }
            PegOutVerifierStatus::PegOutComplete => {
                write!(f, "Peg-out complete, reimbursement succeeded. Done.")
            }
            PegOutVerifierStatus::PegOutWait => write!(f, "No action available. Wait..."),
            PegOutVerifierStatus::PegOutChallengeAvailable => {
                write!(
                    f,
                    "Kick-off 1 transaction confirmed, dispute available. Broadcast challenge transaction?"
                )
            }
            PegOutVerifierStatus::PegOutStartTimeTimeoutAvailable => {
                write!(f, "Start time timed out. Broadcast timeout transaction?")
            }
            PegOutVerifierStatus::PegOutKickOffTimeoutAvailable => {
                write!(f, "Kick-off 1 timed out. Broadcast timeout transaction?")
            }
            PegOutVerifierStatus::PegOutDisproveChainAvailable => {
                write!(
                    f,
                    "Kick-off 2 transaction confirmed. Broadcast disprove chain transaction?"
                )
            }
            PegOutVerifierStatus::PegOutDisproveAvailable => {
                write!(
                    f,
                    "Assert transaction confirmed. Broadcast disprove transaction?"
                )
            }
            PegOutVerifierStatus::PegOutFailed => {
                write!(f, "Peg-out complete, reimbursement failed. Done.")
            }
        }
    }
}

#[derive(Debug)]
pub enum PegOutOperatorStatus {
    PegOutWait,
    PegOutComplete,    // peg-out complete
    PegOutFailed,      // timeouts or disproves executed
    PegOutStartPegOut, // should execute peg-out tx
    PegOutKickOffAvailable,
    PegOutClaimAvailable,
    PegOutAssertAvailable,
    PegOutPayoutOptimisticAvailable,
    PegOutPayoutAvailable,
}

impl Display for PegOutOperatorStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            PegOutOperatorStatus::PegOutWait => write!(f, "No action available. Wait..."),
            PegOutOperatorStatus::PegOutComplete => {
                write!(f, "Peg-out complete, reimbursement succeeded. Done.")
            }
            PegOutOperatorStatus::PegOutFailed => {
                write!(f, "Peg-out complete, reimbursement failed. Done.")
            }
            PegOutOperatorStatus::PegOutStartPegOut => {
                write!(f, "Peg-out requested. Broadcast peg-out transaction?")
            }
            PegOutOperatorStatus::PegOutKickOffAvailable => {
                write!(f, "Peg-out confirmed. Broadcast kick-off 1 transaction?")
            }
            PegOutOperatorStatus::PegOutClaimAvailable => {
                write!(f, "Start time confirmed. Broadcast kick-off 2 transaction?")
            }
            PegOutOperatorStatus::PegOutAssertAvailable => {
                write!(f, "Dispute raised. Broadcast assert transaction?")
            }
            PegOutOperatorStatus::PegOutPayoutOptimisticAvailable => write!(
                f,
                "Dispute timed out, reimbursement available. Broadcast take 1 transaction?"
            ),
            PegOutOperatorStatus::PegOutPayoutAvailable => write!(
                f,
                "Dispute timed out, reimbursement available. Broadcast take 2 transaction?"
            ),
        }
    }
}

#[derive(Debug)]
pub struct TxGraphStatus {
    pub assert_status: Result<TxStatus, Error>,
    pub challenge_status: Result<TxStatus, Error>,
    pub disprove_status: Result<TxStatus, Error>,
    pub kick_off_status: Result<TxStatus, Error>,
    pub claim_status: Result<TxStatus, Error>,
    pub peg_out_status: Option<Result<TxStatus, Error>>,
    pub payout_status: Result<TxStatus, Error>,
    pub payout_optimistic_status: Result<TxStatus, Error>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegOutGraph {
    version: String,
    network: Network,
    id: String,

    // state: State,
    // n_of_n_pre_signing_state: PreSigningState,
    n_of_n_presigned: bool,
    n_of_n_public_key: PublicKey,
    n_of_n_taproot_public_key: XOnlyPublicKey,

    pub peg_in_graph_id: String,
    peg_in_confirm_txid: Txid,

    assert_transaction: AssertTransaction,
    challenge_transaction: ChallengeTransaction,
    disprove_transaction: DisproveTransaction,
    claim_transaction: ClaimTransaction,
    kick_off_transaction: KickOffTransaction,
    payout_transaction: PayoutTransaction,
    payout_optimistic_transaction: PayoutOptimisticTransaction,

    operator_public_key: PublicKey,
    operator_taproot_public_key: XOnlyPublicKey,

    withdrawer_public_key: Option<PublicKey>,
    withdrawer_taproot_public_key: Option<XOnlyPublicKey>,
    withdrawer_evm_address: Option<String>,

    peg_out_transaction: Option<PegOutTransaction>,
}

impl BaseGraph for PegOutGraph {
    fn network(&self) -> Network {
        self.network
    }

    fn id(&self) -> &String {
        &self.id
    }
}

impl PegOutGraph {
    pub fn new(context: &OperatorContext, peg_in_graph: &PegInGraph, kickoff_input: Input) -> Self {
        let peg_in_confirm_transaction = peg_in_graph.peg_in_confirm_transaction_ref();
        let peg_in_confirm_txid = peg_in_confirm_transaction.tx().compute_txid();

        let kick_off_transaction = KickOffTransaction::new(context, kickoff_input);
        let kick_off_txid = kick_off_transaction.tx().compute_txid();

        let claim_vout_0 = 0;
        let claim_transaction = ClaimTransaction::new(
            context,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_txid,
                    vout: claim_vout_0 as u32,
                },
                amount: kick_off_transaction.tx().output[claim_vout_0].value,
            },
        );
        let claim_txid = claim_transaction.tx().compute_txid();

        let input_amount_crowdfunding = Amount::from_btc(1.0).unwrap(); // TODO replace placeholder
        let claim_vout_1 = 1;
        let challenge_transaction = ChallengeTransaction::new(
            context,
            Input {
                outpoint: OutPoint {
                    txid: claim_txid,
                    vout: claim_vout_1 as u32,
                },
                amount: claim_transaction.tx().output[claim_vout_1].value,
            },
            input_amount_crowdfunding,
        );

        let peg_in_vout_0 = 0;
        let claim_vout_0 = 0;
        let claim_vout_1 = 1;
        let payout_transaction = PayoutOptimisticTransaction::new(
            context,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_confirm_txid,
                    vout: peg_in_vout_0 as u32,
                },
                amount: peg_in_confirm_transaction.tx().output[peg_in_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: claim_txid,
                    vout: claim_vout_0 as u32,
                },
                amount: claim_transaction.tx().output[claim_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: claim_txid,
                    vout: claim_vout_1 as u32,
                },
                amount: claim_transaction.tx().output[claim_vout_1].value,
            },
        );

        let claim_vout_0 = 0;
        let assert_transaction = AssertTransaction::new(
            context,
            Input {
                outpoint: OutPoint {
                    txid: claim_txid,
                    vout: claim_vout_0 as u32,
                },
                amount: claim_transaction.tx().output[claim_vout_0].value,
            },
        );
        let assert_txid = assert_transaction.tx().compute_txid();

        let peg_in_vout_0 = 0;
        let assert_vout_0 = 0;
        let payout_optimistic_transaction = PayoutTransaction::new(
            context,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_confirm_txid,
                    vout: peg_in_vout_0 as u32,
                },
                amount: peg_in_confirm_transaction.tx().output[peg_in_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: assert_vout_0 as u32,
                },
                amount: assert_transaction.tx().output[assert_vout_0].value,
            },
        );

        let script_index = 1; // TODO replace placeholder
        let disprove_vout_0 = 0;
        let disprove_vout_1 = 1;
        let disprove_transaction = DisproveTransaction::new(
            context,
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: disprove_vout_0 as u32,
                },
                amount: assert_transaction.tx().output[disprove_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: disprove_vout_1 as u32,
                },
                amount: assert_transaction.tx().output[disprove_vout_1].value,
            },
            script_index,
        );

        PegOutGraph {
            version: GRAPH_VERSION.to_string(),
            network: context.network,
            id: generate_id(peg_in_graph, &context.operator_public_key),
            n_of_n_presigned: false,
            n_of_n_public_key: context.n_of_n_public_key,
            n_of_n_taproot_public_key: context.n_of_n_taproot_public_key,
            peg_in_graph_id: peg_in_graph.id().clone(),
            peg_in_confirm_txid,
            assert_transaction,
            challenge_transaction,
            disprove_transaction,
            kick_off_transaction,
            claim_transaction,
            payout_optimistic_transaction: payout_transaction,
            payout_transaction: payout_optimistic_transaction,
            operator_public_key: context.operator_public_key,
            operator_taproot_public_key: context.operator_taproot_public_key,
            withdrawer_public_key: None,
            withdrawer_taproot_public_key: None,
            withdrawer_evm_address: None,
            peg_out_transaction: None,
        }
    }

    pub fn new_for_validation(&self) -> Self {
        let peg_in_confirm_txid = self.payout_optimistic_transaction.tx().input[0]
            .previous_output
            .txid; // Self-referencing

        let kick_off_vout_0 = 0;
        let kick_off_transaction = KickOffTransaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &self.operator_taproot_public_key,
            &self.n_of_n_taproot_public_key,
            Input {
                outpoint: self.kick_off_transaction.tx().input[kick_off_vout_0].previous_output, /* Self-referencing */
                amount: self.kick_off_transaction.prev_outs()[kick_off_vout_0].value, /* Self-referencing */
            },
        );
        let kick_off_txid = kick_off_transaction.tx().compute_txid();

        let claim_vout_0 = 1;
        let claim_transaction = ClaimTransaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &self.operator_taproot_public_key,
            &self.n_of_n_taproot_public_key,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_txid,
                    vout: claim_vout_0 as u32,
                },
                amount: kick_off_transaction.tx().output[claim_vout_0].value,
            },
        );
        let claim_txid = claim_transaction.tx().compute_txid();

        let input_amount_crowdfunding = Amount::from_btc(1.0).unwrap(); // TODO replace placeholder
        let challenge_vout_0 = 0;
        let challenge_transaction = ChallengeTransaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &self.operator_taproot_public_key,
            &self.n_of_n_taproot_public_key,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_txid,
                    vout: challenge_vout_0 as u32,
                },
                amount: kick_off_transaction.tx().output[challenge_vout_0].value,
            },
            input_amount_crowdfunding,
        );

        let peg_in_vout_0 = 0;
        let claim_vout_0 = 0;
        let claim_vout_1 = 1;
        let payout_optimistic_transaction = PayoutOptimisticTransaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &self.operator_taproot_public_key,
            &self.n_of_n_taproot_public_key,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_confirm_txid,
                    vout: peg_in_vout_0 as u32,
                },
                amount: self.payout_optimistic_transaction.prev_outs()[peg_in_vout_0].value, /* Self-referencing */
            },
            Input {
                outpoint: OutPoint {
                    txid: claim_txid,
                    vout: claim_vout_0 as u32,
                },
                amount: claim_transaction.tx().output[claim_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: claim_txid,
                    vout: claim_vout_1 as u32,
                },
                amount: claim_transaction.tx().output[claim_vout_1].value,
            },
        );

        let claim_vout_0 = 0;
        let assert_transaction = AssertTransaction::new_for_validation(
            self.network,
            &self.operator_taproot_public_key,
            &self.n_of_n_taproot_public_key,
            Input {
                outpoint: OutPoint {
                    txid: claim_txid,
                    vout: claim_vout_0 as u32,
                },
                amount: claim_transaction.tx().output[claim_vout_0].value,
            },
        );
        let assert_txid = assert_transaction.tx().compute_txid();

        let peg_in_vout_0 = 0;
        let assert_vout_0 = 0;
        let payout_transaction = PayoutTransaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &self.operator_taproot_public_key,
            &self.n_of_n_taproot_public_key,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_confirm_txid,
                    vout: peg_in_vout_0 as u32,
                },
                amount: self.payout_optimistic_transaction.prev_outs()[peg_in_vout_0].value, /* Self-referencing */
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: assert_vout_0 as u32,
                },
                amount: assert_transaction.tx().output[assert_vout_0].value,
            },
        );

        let script_index = 1; // TODO replace placeholder
        let disprove_vout_0 = 1;
        let disprove_vout_1 = 2;
        let disprove_transaction = DisproveTransaction::new_for_validation(
            self.network,
            &self.operator_taproot_public_key,
            &self.n_of_n_taproot_public_key,
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: disprove_vout_0 as u32,
                },
                amount: assert_transaction.tx().output[disprove_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_txid,
                    vout: disprove_vout_1 as u32,
                },
                amount: assert_transaction.tx().output[disprove_vout_1].value,
            },
            script_index,
        );

        PegOutGraph {
            version: GRAPH_VERSION.to_string(),
            network: self.network,
            id: self.id.clone(),
            n_of_n_presigned: false,
            n_of_n_public_key: self.n_of_n_public_key,
            n_of_n_taproot_public_key: self.n_of_n_taproot_public_key,
            peg_in_graph_id: self.peg_in_graph_id.clone(),
            peg_in_confirm_txid,
            assert_transaction,
            challenge_transaction,
            disprove_transaction,
            kick_off_transaction,
            claim_transaction,
            payout_optimistic_transaction,
            payout_transaction,
            operator_public_key: self.operator_public_key,
            operator_taproot_public_key: self.operator_taproot_public_key,
            withdrawer_public_key: None,
            withdrawer_taproot_public_key: None,
            withdrawer_evm_address: None,
            peg_out_transaction: None,
        }
    }

    pub fn push_nonces(
        &mut self,
        context: &VerifierContext,
    ) -> HashMap<Txid, HashMap<usize, SecNonce>> {
        let mut secret_nonces = HashMap::new();

        secret_nonces.insert(
            self.assert_transaction.tx().compute_txid(),
            self.assert_transaction.push_nonces(context),
        );
        secret_nonces.insert(
            self.disprove_transaction.tx().compute_txid(),
            self.disprove_transaction.push_nonces(context),
        );
        secret_nonces.insert(
            self.payout_optimistic_transaction.tx().compute_txid(),
            self.payout_optimistic_transaction.push_nonces(context),
        );
        secret_nonces.insert(
            self.payout_transaction.tx().compute_txid(),
            self.payout_transaction.push_nonces(context),
        );

        secret_nonces
    }

    pub fn pre_sign(
        &mut self,
        context: &VerifierContext,
        secret_nonces: &HashMap<Txid, HashMap<usize, SecNonce>>,
    ) {
        self.assert_transaction.pre_sign(
            context,
            &secret_nonces[&self.assert_transaction.tx().compute_txid()],
        );
        self.disprove_transaction.pre_sign(
            context,
            &secret_nonces[&self.disprove_transaction.tx().compute_txid()],
        );
        self.payout_optimistic_transaction.pre_sign(
            context,
            &secret_nonces[&self.payout_optimistic_transaction.tx().compute_txid()],
        );
        self.payout_transaction.pre_sign(
            context,
            &secret_nonces[&self.payout_transaction.tx().compute_txid()],
        );

        self.n_of_n_presigned = true; // TODO: set to true after collecting all n of n signatures
    }

    pub async fn verifier_status(&self, client: &AsyncClient) -> PegOutVerifierStatus {
        if self.n_of_n_presigned {
            let TxGraphStatus {
                assert_status,
                challenge_status,
                disprove_status,
                kick_off_status,
                claim_status,
                payout_status,
                payout_optimistic_status,
                peg_out_status: _,
            } = Self::get_peg_out_statuses(self, client).await;

            if claim_status.as_ref().is_ok_and(|status| status.confirmed) {
                if payout_status.as_ref().is_ok_and(|status| status.confirmed)
                    || payout_optimistic_status
                        .as_ref()
                        .is_ok_and(|status| status.confirmed)
                {
                    PegOutVerifierStatus::PegOutComplete
                } else if disprove_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                {
                    return PegOutVerifierStatus::PegOutFailed; // TODO: can be also
                                                               // `PegOutVerifierStatus::PegOutComplete`
                } else if assert_status.as_ref().is_ok_and(|status| status.confirmed) {
                    return PegOutVerifierStatus::PegOutDisproveAvailable;
                } else {
                    return PegOutVerifierStatus::PegOutDisproveChainAvailable;
                }
            } else if kick_off_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
            {
                if challenge_status
                    .as_ref()
                    .is_ok_and(|status| !status.confirmed)
                {
                    return PegOutVerifierStatus::PegOutChallengeAvailable;
                } else {
                    return PegOutVerifierStatus::PegOutWait;
                }
            } else {
                return PegOutVerifierStatus::PegOutWait;
            }
        } else {
            PegOutVerifierStatus::PegOutPresign
        }
    }

    pub async fn operator_status(&self, client: &AsyncClient) -> PegOutOperatorStatus {
        if self.n_of_n_presigned {
            let TxGraphStatus {
                assert_status,
                challenge_status,
                disprove_status,
                kick_off_status,
                claim_status,
                peg_out_status,
                payout_status,
                payout_optimistic_status,
            } = Self::get_peg_out_statuses(self, client).await;
            let blockchain_height = get_block_height(client).await;

            if peg_out_status.is_some_and(|status| status.unwrap().confirmed) {
                if claim_status.as_ref().is_ok_and(|status| status.confirmed) {
                    if payout_status.as_ref().is_ok_and(|status| status.confirmed)
                        || payout_optimistic_status
                            .as_ref()
                            .is_ok_and(|status| status.confirmed)
                    {
                        return PegOutOperatorStatus::PegOutComplete;
                    } else if disprove_status
                        .as_ref()
                        .is_ok_and(|status| status.confirmed)
                    {
                        return PegOutOperatorStatus::PegOutFailed; // TODO: can be also
                                                                   // `PegOutOperatorStatus::PegOutComplete`
                    } else if challenge_status.is_ok_and(|status| status.confirmed) {
                        if assert_status.as_ref().is_ok_and(|status| status.confirmed) {
                            if assert_status.as_ref().unwrap().block_height.is_some_and(
                                |block_height| {
                                    block_height + self.payout_transaction.num_blocks_timelock_0()
                                        <= blockchain_height
                                },
                            ) {
                                return PegOutOperatorStatus::PegOutPayoutAvailable;
                            } else {
                                return PegOutOperatorStatus::PegOutWait;
                            }
                        } else if claim_status.as_ref().unwrap().block_height.is_some_and(
                            |block_height| {
                                block_height + self.assert_transaction.num_blocks_timelock_0()
                                    <= blockchain_height
                            },
                        ) {
                            return PegOutOperatorStatus::PegOutAssertAvailable;
                        } else {
                            return PegOutOperatorStatus::PegOutWait;
                        }
                    } else if claim_status.as_ref().unwrap().block_height.is_some_and(
                        |block_height| {
                            block_height
                                + self.payout_optimistic_transaction.num_blocks_timelock_2()
                                <= blockchain_height
                        },
                    ) {
                        return PegOutOperatorStatus::PegOutPayoutOptimisticAvailable;
                    } else {
                        return PegOutOperatorStatus::PegOutWait;
                    }
                } else if kick_off_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                {
                    return PegOutOperatorStatus::PegOutClaimAvailable;
                } else {
                    return PegOutOperatorStatus::PegOutKickOffAvailable;
                }
            } else {
                return PegOutOperatorStatus::PegOutStartPegOut;
            }
        }

        PegOutOperatorStatus::PegOutWait
    }

    pub async fn depositor_status(&self, client: &AsyncClient) -> PegOutDepositorStatus {
        if self.peg_out_transaction.is_some() {
            let peg_out_txid = self
                .peg_out_transaction
                .as_ref()
                .unwrap()
                .tx()
                .compute_txid();
            let peg_out_status = client.get_tx_status(&peg_out_txid).await;

            if peg_out_status.is_ok_and(|status| status.confirmed) {
                PegOutDepositorStatus::PegOutComplete
            } else {
                PegOutDepositorStatus::PegOutWait
            }
        } else {
            PegOutDepositorStatus::PegOutNotStarted
        }
    }

    pub async fn kick_off(&mut self, client: &AsyncClient) {
        verify_if_not_mined(client, self.kick_off_transaction.tx().compute_txid()).await;

        // complete kick-off 1 tx
        let kick_off_tx = self.kick_off_transaction.finalize();

        // broadcast kick-off 1 tx
        let kick_off_result = client.broadcast(&kick_off_tx).await;

        // verify kick-off 1 tx result
        verify_tx_result(&kick_off_result);
    }

    pub async fn challenge(
        &mut self,
        client: &AsyncClient,
        context: &dyn BaseContext,
        crowdfundng_inputs: &Vec<InputWithScript<'_>>,
        keypair: &Keypair,
        output_script_pubkey: ScriptBuf,
    ) {
        verify_if_not_mined(client, self.challenge_transaction.tx().compute_txid()).await;

        let kick_off_txid = self.kick_off_transaction.tx().compute_txid();
        let kick_off_status = client.get_tx_status(&kick_off_txid).await;

        if kick_off_status.is_ok_and(|status| status.confirmed) {
            // complete challenge tx
            self.challenge_transaction.add_inputs_and_output(
                context,
                crowdfundng_inputs,
                keypair,
                output_script_pubkey,
            );
            let challenge_tx = self.challenge_transaction.finalize();

            // broadcast challenge tx
            let challenge_result = client.broadcast(&challenge_tx).await;

            // verify challenge tx result
            verify_tx_result(&challenge_result);
        } else {
            panic!("Kick-off 1 tx has not been confirmed!");
        }
    }

    pub async fn claim(&mut self, client: &AsyncClient) {
        verify_if_not_mined(client, self.claim_transaction.tx().compute_txid()).await;

        let kick_off_txid = self.kick_off_transaction.tx().compute_txid();
        let kick_off_status = client.get_tx_status(&kick_off_txid).await;

        let blockchain_height = get_block_height(client).await;

        if kick_off_status
            .as_ref()
            .is_ok_and(|status| status.confirmed)
        {
            if kick_off_status
                .as_ref()
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.claim_transaction.num_blocks_timelock_0()
                        <= blockchain_height
                })
            {
                // complete kick-off 2 tx
                let claim_tx = self.claim_transaction.finalize();

                // broadcast kick-off 2 tx
                let claim_result = client.broadcast(&claim_tx).await;

                // verify kick-off 2 tx result
                verify_tx_result(&claim_result);
            } else {
                panic!("Kick-off 1 timelock has not elapsed!");
            }
        } else {
            panic!("Kick-off 1 tx has not been confirmed!");
        }
    }

    pub async fn assert(&mut self, client: &AsyncClient) {
        verify_if_not_mined(client, self.assert_transaction.tx().compute_txid()).await;

        let claim_txid = self.claim_transaction.tx().compute_txid();
        let claim_status = client.get_tx_status(&claim_txid).await;

        let blockchain_height = get_block_height(client).await;

        if claim_status.as_ref().is_ok_and(|status| status.confirmed) {
            if claim_status
                .as_ref()
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.assert_transaction.num_blocks_timelock_0()
                        <= blockchain_height
                })
            {
                // complete assert tx
                let assert_tx = self.assert_transaction.finalize();

                // broadcast assert tx
                let assert_result = client.broadcast(&assert_tx).await;

                // verify assert tx result
                verify_tx_result(&assert_result);
            } else {
                panic!("Kick-off 2 timelock has not elapsed!");
            }
        } else {
            panic!("Kick-off 2 tx has not been confirmed!");
        }
    }

    pub async fn disprove(
        &mut self,
        client: &AsyncClient,
        input_script_index: u32,
        output_script_pubkey: ScriptBuf,
    ) {
        verify_if_not_mined(client, self.disprove_transaction.tx().compute_txid()).await;

        let assert_txid = self.assert_transaction.tx().compute_txid();
        let assert_status = client.get_tx_status(&assert_txid).await;

        if assert_status.is_ok_and(|status| status.confirmed) {
            // complete disprove tx
            self.disprove_transaction
                .add_input_output(input_script_index, output_script_pubkey);
            let disprove_tx = self.disprove_transaction.finalize();

            // broadcast disprove tx
            let disprove_result = client.broadcast(&disprove_tx).await;

            // verify disprove tx result
            verify_tx_result(&disprove_result);
        } else {
            panic!("Assert tx has not been confirmed!");
        }
    }

    pub async fn payout(&mut self, client: &AsyncClient) {
        verify_if_not_mined(
            client,
            self.payout_optimistic_transaction.tx().compute_txid(),
        )
        .await;
        verify_if_not_mined(client, self.challenge_transaction.tx().compute_txid()).await;
        verify_if_not_mined(client, self.assert_transaction.tx().compute_txid()).await;

        let peg_in_confirm_status = client.get_tx_status(&self.peg_in_confirm_txid).await;

        let kick_off_txid = self.kick_off_transaction.tx().compute_txid();
        let kick_off_status = client.get_tx_status(&kick_off_txid).await;

        let claim_txid = self.claim_transaction.tx().compute_txid();
        let claim_status = client.get_tx_status(&claim_txid).await;

        let blockchain_height = get_block_height(client).await;

        if peg_in_confirm_status.is_ok_and(|status| status.confirmed)
            && kick_off_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
            && claim_status.as_ref().is_ok_and(|status| status.confirmed)
        {
            if claim_status
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.payout_optimistic_transaction.num_blocks_timelock_2()
                        <= blockchain_height
                })
            {
                // complete take 1 tx
                let payout_tx = self.payout_optimistic_transaction.finalize();

                // broadcast take 1 tx
                let payout_result = client.broadcast(&payout_tx).await;

                // verify take 1 tx result
                verify_tx_result(&payout_result);
            } else {
                panic!("Kick-off 2 tx timelock has not elapsed!");
            }
        } else {
            panic!("Peg-in confirm tx, kick-off 1 and kick-off 2 tx have not been confirmed!");
        }
    }

    pub async fn payout_optimistic(&mut self, client: &AsyncClient) {
        verify_if_not_mined(client, self.payout_transaction.tx().compute_txid()).await;
        verify_if_not_mined(
            client,
            self.payout_optimistic_transaction.tx().compute_txid(),
        )
        .await;
        verify_if_not_mined(client, self.disprove_transaction.tx().compute_txid()).await;

        let peg_in_confirm_status = client.get_tx_status(&self.peg_in_confirm_txid).await;

        let assert_txid = self.assert_transaction.tx().compute_txid();
        let assert_status = client.get_tx_status(&assert_txid).await;

        let blockchain_height = get_block_height(client).await;

        if peg_in_confirm_status.is_ok_and(|status| status.confirmed)
            && assert_status.as_ref().is_ok_and(|status| status.confirmed)
        {
            if assert_status
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.payout_transaction.num_blocks_timelock_0()
                        <= blockchain_height
                })
            {
                // complete take 2 tx
                let payout_tx = self.payout_optimistic_transaction.finalize();

                // broadcast take 2 tx
                let payout_result = client.broadcast(&payout_tx).await;

                // verify take 2 tx result
                verify_tx_result(&payout_result);
            } else {
                panic!("Assert tx timelock has not elapsed!");
            }
        } else {
            panic!("Peg-in confirm tx and assert tx have not been confirmed!");
        }
    }

    async fn get_peg_out_statuses(&self, client: &AsyncClient) -> TxGraphStatus {
        let assert_status = client
            .get_tx_status(&self.assert_transaction.tx().compute_txid())
            .await;

        let challenge_status = client
            .get_tx_status(&self.challenge_transaction.tx().compute_txid())
            .await;

        let disprove_status = client
            .get_tx_status(&self.disprove_transaction.tx().compute_txid())
            .await;

        let kick_off_status = client
            .get_tx_status(&self.kick_off_transaction.tx().compute_txid())
            .await;

        let claim_status = client
            .get_tx_status(&self.claim_transaction.tx().compute_txid())
            .await;

        let mut peg_out_status: Option<Result<TxStatus, Error>> = None;
        if self.peg_out_transaction.is_some() {
            peg_out_status = Some(
                client
                    .get_tx_status(
                        &self
                            .peg_out_transaction
                            .as_ref()
                            .unwrap()
                            .tx()
                            .compute_txid(),
                    )
                    .await,
            );
        }

        let payout_status = client
            .get_tx_status(&self.payout_optimistic_transaction.tx().compute_txid())
            .await;

        let payout_optimistic_status = client
            .get_tx_status(&self.payout_transaction.tx().compute_txid())
            .await;

        TxGraphStatus {
            assert_status,
            challenge_status,
            disprove_status,
            kick_off_status,
            claim_status,
            peg_out_status,
            payout_status,
            payout_optimistic_status,
        }
    }

    pub fn validate(&self) -> bool {
        let mut ret_val = true;
        let peg_out_graph = self.new_for_validation();
        if !validate_transaction(
            self.assert_transaction.tx(),
            peg_out_graph.assert_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.challenge_transaction.tx(),
            peg_out_graph.challenge_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.disprove_transaction.tx(),
            peg_out_graph.disprove_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.kick_off_transaction.tx(),
            peg_out_graph.kick_off_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.claim_transaction.tx(),
            peg_out_graph.claim_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.payout_optimistic_transaction.tx(),
            peg_out_graph.payout_optimistic_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.payout_transaction.tx(),
            peg_out_graph.payout_transaction.tx(),
        ) {
            ret_val = false;
        }

        if !verify_public_nonces_for_tx(&self.assert_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.disprove_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.payout_optimistic_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.payout_transaction) {
            ret_val = false;
        }

        ret_val
    }

    pub fn merge(&mut self, source_peg_out_graph: &PegOutGraph) {
        self.assert_transaction
            .merge(&source_peg_out_graph.assert_transaction);

        self.challenge_transaction
            .merge(&source_peg_out_graph.challenge_transaction);

        self.disprove_transaction
            .merge(&source_peg_out_graph.disprove_transaction);

        self.payout_optimistic_transaction
            .merge(&source_peg_out_graph.payout_optimistic_transaction);

        self.payout_transaction
            .merge(&source_peg_out_graph.payout_transaction);
    }
}

pub fn generate_id(peg_in_graph: &PegInGraph, operator_public_key: &PublicKey) -> String {
    let mut hasher = Sha256::new();

    hasher.update(peg_in_graph.id().to_string() + &operator_public_key.to_string());

    hasher.finalize().to_hex_string(Upper)
}
