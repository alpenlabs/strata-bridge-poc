use core::fmt;
use std::{collections::HashSet, sync::Arc, time::Duration};

use anyhow::bail;
#[cfg(not(feature = "mock"))]
use bitcoin::hex::DisplayHex;
use bitcoin::{
    block::Header,
    consensus,
    hashes::Hash,
    sighash::{Prevouts, SighashCache},
    TapSighashType, Transaction, TxOut, Txid,
};
use musig2::{
    aggregate_partial_signatures, sign_partial, AggNonce, KeyAggContext, PartialSignature, PubNonce,
};
#[cfg(not(feature = "mock"))]
use rand::{rngs::OsRng, Rng, RngCore};
use secp256k1::schnorr::Signature;
#[cfg(not(feature = "mock"))]
use secp256k1::XOnlyPublicKey;
#[cfg(not(feature = "mock"))]
use strata_bridge_btcio::traits::Reader;
use strata_bridge_btcio::traits::{Broadcaster, Signer};
use strata_bridge_db::{
    operator::{KickoffInfo, OperatorDb},
    public::PublicDb,
};
#[cfg(feature = "mock")]
use strata_bridge_primitives::scripts::wots::mock;
use strata_bridge_primitives::{
    bitcoin::BitcoinAddress,
    build_context::{BuildContext, TxBuildContext, TxKind},
    deposit::DepositInfo,
    duties::{BridgeDuty, BridgeDutyStatus, DepositStatus, WithdrawalStatus},
    params::prelude::*,
    scripts::{
        taproot::{create_message_hash, finalize_input, TaprootWitness},
        wots::{generate_wots_public_keys, generate_wots_signatures, Assertions},
    },
    types::TxSigningData,
    withdrawal::WithdrawalInfo,
};
use strata_bridge_tx_graph::{
    connectors::params::{PAYOUT_TIMELOCK, SUPERBLOCK_MEASUREMENT_PERIOD},
    peg_out_graph::{PegOutGraph, PegOutGraphConnectors, PegOutGraphInput},
    transactions::prelude::*,
};
use strata_rpc::StrataApiClient;
use strata_state::{block::L2Block, chain_state::ChainState};
use tokio::sync::{
    broadcast::{self, error::RecvError},
    mpsc,
};
use tracing::{debug, error, info, trace, warn};

use crate::{
    base::Agent,
    signal::{
        AggNonces, CovenantNonceRequest, CovenantNonceRequestFulfilled, CovenantNonceSignal,
        CovenantSigRequest, CovenantSigRequestFulfilled, CovenantSignatureSignal, DepositSignal,
    },
};

pub type OperatorIdx = u32;

#[derive(Debug)]
pub struct Operator<O: OperatorDb, P: PublicDb> {
    pub agent: Agent,
    msk: String,
    build_context: TxBuildContext,
    db: Arc<O>,
    public_db: Arc<P>,
    is_faulty: bool,

    duty_status_sender: mpsc::Sender<(Txid, BridgeDutyStatus)>,
    deposit_signal_sender: broadcast::Sender<DepositSignal>,
    deposit_signal_receiver: broadcast::Receiver<DepositSignal>,
    covenant_nonce_sender: broadcast::Sender<CovenantNonceSignal>,
    covenant_nonce_receiver: broadcast::Receiver<CovenantNonceSignal>,
    covenant_sig_sender: broadcast::Sender<CovenantSignatureSignal>,
    covenant_sig_receiver: broadcast::Receiver<CovenantSignatureSignal>,
}

impl<O, P> Operator<O, P>
where
    O: OperatorDb,
    P: PublicDb + Clone,
{
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        agent: Agent,
        build_context: TxBuildContext,
        is_faulty: bool,
        db: Arc<O>,
        public_db: Arc<P>,
        duty_status_sender: mpsc::Sender<(Txid, BridgeDutyStatus)>,
        deposit_signal_sender: broadcast::Sender<DepositSignal>,
        deposit_signal_receiver: broadcast::Receiver<DepositSignal>,
        covenant_nonce_sender: broadcast::Sender<CovenantNonceSignal>,
        covenant_nonce_receiver: broadcast::Receiver<CovenantNonceSignal>,
        covenant_sig_sender: broadcast::Sender<CovenantSignatureSignal>,
        covenant_sig_receiver: broadcast::Receiver<CovenantSignatureSignal>,
    ) -> Self {
        #[cfg(feature = "mock")]
        let msk = "secret".to_string();

        #[cfg(not(feature = "mock"))]
        let msk = {
            let mut msk_bytes: [u8; 32] = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut msk_bytes);
            msk_bytes.to_lower_hex_string()
        };

        Self {
            agent,
            msk,
            build_context,
            db,
            public_db,
            is_faulty,

            duty_status_sender,
            deposit_signal_sender,
            deposit_signal_receiver,
            covenant_nonce_sender,
            covenant_nonce_receiver,
            covenant_sig_sender,
            covenant_sig_receiver,
        }
    }

    pub fn am_i_faulty(&self) -> bool {
        self.is_faulty
    }

    pub async fn start(&mut self, duty_receiver: &mut broadcast::Receiver<BridgeDuty>) {
        let own_index = self.build_context.own_index();
        info!(action = "starting operator", %own_index);

        loop {
            match duty_receiver.recv().await {
                Ok(bridge_duty) => {
                    debug!(event = "received duty", ?bridge_duty, %own_index);
                    self.process_duty(bridge_duty).await;
                }
                Err(RecvError::Lagged(skipped_messages)) => {
                    warn!(action = "processing last available duty", event = "duty executor lagging behind, please adjust '--duty-interval' arg", %skipped_messages);
                }
                Err(err) => {
                    error!(msg = "error receiving duties", ?err);

                    panic!("duty sender closed unexpectedly");
                }
            }
        }
    }

    pub async fn process_duty(&mut self, duty: BridgeDuty) {
        let own_index = self.build_context.own_index();

        match duty {
            BridgeDuty::SignDeposit {
                details: deposit_info,
                status: _,
            } => {
                let txid = deposit_info.deposit_request_outpoint().txid;
                info!(event = "received deposit", %own_index, drt_txid = %txid);

                let duty_id = deposit_info.deposit_request_outpoint().txid;
                self.handle_deposit(deposit_info).await;

                let duty_status = BridgeDutyStatus::Deposit(DepositStatus::Executed);
                info!(action = "reporting deposit duty status", %duty_id, ?duty_status);

                if let Err(cause) = self.duty_status_sender.send((duty_id, duty_status)).await {
                    error!(msg = "could not report deposit duty status", %cause);
                }
            }
            BridgeDuty::FulfillWithdrawal {
                details: withdrawal_info,
                status: _,
            } => {
                let txid = withdrawal_info.deposit_outpoint().txid;
                let assignee_id = withdrawal_info.assigned_operator_idx();

                info!(event = "received withdrawal", dt_txid = %txid, assignee = %assignee_id, %own_index);

                if assignee_id != own_index {
                    warn!(action = "ignoring withdrawal duty unassigned to this operator", %assignee_id, %own_index);
                    return;
                }

                info!(action = "getting the latest checkpoint index");
                let latest_checkpoint_idx = self
                    .agent
                    .strata_client
                    .get_latest_checkpoint_index(Some(true))
                    .await
                    .expect("should be able to get latest checkpoint index")
                    .expect("checkpoint index must exist");
                info!(event = "received latest checkpoint index", %latest_checkpoint_idx);

                let deposit_txid = withdrawal_info.deposit_outpoint().txid;
                self.db
                    .set_checkpoint_index(deposit_txid, latest_checkpoint_idx)
                    .await;

                self.handle_withdrawal(withdrawal_info).await;

                let duty_status = BridgeDutyStatus::Withdrawal(WithdrawalStatus::Executed);
                info!(action = "reporting withdrawal duty status", duty_id=%deposit_txid, ?duty_status);

                if let Err(cause) = self
                    .duty_status_sender
                    .send((deposit_txid, duty_status))
                    .await
                {
                    error!(msg = "could not report withdrawal duty status", %cause);
                }
            }
        }
    }

    pub async fn handle_deposit(&mut self, deposit_info: DepositInfo) {
        let own_index = self.build_context.own_index();

        // 1. aggregate_tx_graph
        let mut deposit_tx = deposit_info
            .construct_signing_data(&self.build_context)
            .expect("should be able to create build context");

        #[cfg(feature = "mock")]
        let deposit_txid = Txid::from_byte_array(mock::PUBLIC_INPUTS.0);

        #[cfg(not(feature = "mock"))]
        let deposit_txid = deposit_tx.psbt.unsigned_tx.compute_txid();

        info!(action = "generating wots public keys", %deposit_txid, %own_index);
        let public_keys = generate_wots_public_keys(&self.msk, deposit_txid);
        self.public_db
            .set_wots_public_keys(self.build_context.own_index(), deposit_txid, &public_keys)
            .await;

        info!(action = "generating kickoff", %deposit_txid, %own_index);

        let reserved_outpoints = self.db.selected_outpoints().await;
        info!(event = "got reserved outpoints", ?reserved_outpoints);

        let (change_address, funding_input, total_amount, funding_utxo) = self
            .agent
            .select_utxo(OPERATOR_STAKE, reserved_outpoints)
            .await
            .expect("should be able to get outpoints");

        self.db.add_outpoint(funding_input).await;

        let funding_inputs = vec![funding_input];
        let funding_utxos = vec![funding_utxo];
        let change_amt = total_amount - OPERATOR_STAKE - MIN_RELAY_FEE;

        let change_address =
            BitcoinAddress::parse(&change_address.to_string(), self.build_context.network())
                .expect("address and network must match");

        info!(action = "composing pegout graph input", %deposit_txid, %own_index);
        let peg_out_graph_input = PegOutGraphInput {
            network: self.build_context.network(),
            deposit_amount: BRIDGE_DENOMINATION,
            operator_pubkey: self.agent.public_key().x_only_public_key().0,
            kickoff_data: KickoffTxData {
                funding_inputs: funding_inputs.clone(),
                funding_utxos: funding_utxos.clone(),
                change_address: change_address.clone(),
                change_amt,
                deposit_txid,
            },
        };

        info!(action = "adding kickoff info to db", %deposit_txid, %own_index, ?funding_inputs, ?funding_utxos);
        self.db
            .add_kickoff_info(
                deposit_txid,
                KickoffInfo {
                    funding_inputs,
                    funding_utxos,
                    change_address,
                    change_amt,
                },
            )
            .await;

        info!(action = "composing pegout graph connectors", %deposit_txid, %own_index);
        let peg_out_graph_connectors = PegOutGraphConnectors::new(
            self.public_db.clone(),
            &self.build_context,
            deposit_txid,
            self.build_context.own_index(),
        )
        .await;

        info!(action = "generating pegout graph", %deposit_txid, %own_index);
        let peg_out_graph = PegOutGraph::generate(
            peg_out_graph_input.clone(),
            deposit_txid,
            peg_out_graph_connectors,
            own_index,
            self.public_db.clone(),
        )
        .await;

        // 2. Aggregate nonces for peg out graph txs that require covenant.
        info!(action = "aggregating nonces for emulated covenant", %deposit_txid, %own_index);
        self.aggregate_covenant_nonces(
            deposit_txid,
            peg_out_graph_input.clone(),
            peg_out_graph.clone(),
        )
        .await;

        // 3. Aggregate signatures for peg out graph txs that require covenant.
        info!(action = "aggregating signatures for emulated covenant", %deposit_txid, %own_index);
        self.aggregate_covenant_signatures(deposit_txid, peg_out_graph_input, peg_out_graph)
            .await;

        // 4. Collect nonces and signatures for deposit tx.
        info!(action = "aggregating nonces for deposit sweeping", %deposit_txid, %own_index);
        let agg_nonce = self
            .aggregate_nonces(deposit_tx.clone())
            .await
            .expect("nonce aggregation must complete");

        info!(action = "aggregating signatures for deposit sweeping", %deposit_txid, %own_index);
        let signed_deposit_tx = self
            .aggregate_signatures(agg_nonce, &mut deposit_tx)
            .await
            .expect("should be able to construct fully signed deposit tx");

        // 5. Broadcast deposit tx.
        info!(action = "broadcasting deposit tx", operator_id=%own_index, %deposit_txid);
        match self
            .agent
            .btc_client
            .send_raw_transaction(&signed_deposit_tx)
            .await
        {
            Ok(txid) => {
                info!(event = "deposit tx successfully broadcasted", %txid);
            }
            Err(e) => {
                error!(?e, "could not broadcast deposit tx");
            }
        }
    }

    pub async fn aggregate_covenant_nonces(
        &mut self,
        deposit_txid: Txid,
        self_peg_out_graph_input: PegOutGraphInput,
        self_peg_out_graph: PegOutGraph,
    ) {
        let own_index = self.build_context.own_index();

        // 1. Prepare txs
        let PegOutGraph {
            kickoff_tx: _,
            claim_tx: _,
            assert_chain,
            payout_tx,
            disprove_tx,
        } = self_peg_out_graph;
        let AssertChain {
            pre_assert,
            assert_data: _,
            post_assert,
        } = assert_chain;

        // 2. Generate own nonces
        info!(action = "generating nonce for this operator", %deposit_txid, %own_index);
        self.generate_covenant_nonces(
            pre_assert.clone(),
            post_assert.clone(),
            payout_tx.clone(),
            disprove_tx.clone(),
            self.build_context.own_index(),
        )
        .await;

        // 3. Broadcast nonce request
        info!(action = "broadcasting this operator's nonce", %deposit_txid, %own_index);
        let details = CovenantNonceRequest {
            peg_out_graph_input: self_peg_out_graph_input,
        };

        self.covenant_nonce_sender
            .send(CovenantNonceSignal::Request {
                details,
                sender_id: self.build_context.own_index(),
            })
            .expect("should be able to send covenant signal");

        // 4. Listen for requests and fulfillment data from others.
        self.gather_and_fulfill_nonces(
            deposit_txid,
            pre_assert.compute_txid(),
            post_assert.compute_txid(),
            payout_tx.compute_txid(),
            disprove_tx.compute_txid(),
        )
        .await;
    }

    async fn generate_covenant_nonces(
        &self,
        pre_assert: PreAssertTx,
        post_assert: PostAssertTx,
        payout_tx: PayoutTx,
        disprove_tx: DisproveTx,
        operator_index: OperatorIdx,
    ) -> CovenantNonceRequestFulfilled {
        let key_agg_ctx = KeyAggContext::new(self.build_context.pubkey_table().0.values().copied())
            .expect("should be able to create key agg ctx");
        let key_agg_ctx_keypath = key_agg_ctx
            .clone()
            .with_unspendable_taproot_tweak()
            .expect("should be able to create key agg ctx with unspendable key");

        // As all these calls lock on the same `HashMap`, there is no point in making these
        // concurrent.
        trace!(action = "creating secnonce and pubnonce for pre-assert tx", %operator_index);
        let pre_assert_pubnonce = self
            .generate_nonces(operator_index, &key_agg_ctx, 0, &pre_assert)
            .await;

        trace!(action = "creating secnonce and pubnonce for post-assert tx", %operator_index);
        let post_assert_pubnonce = self
            .generate_nonces(operator_index, &key_agg_ctx_keypath, 0, &post_assert)
            .await;

        trace!(action = "creating secnonce and pubnonce for payout tx output 0", %operator_index);
        let payout_pubnonce_0 = self
            .generate_nonces(operator_index, &key_agg_ctx_keypath, 0, &payout_tx)
            .await;

        trace!(action = "creating secnonce and pubnonce for payout tx output 1", %operator_index);
        let payout_pubnonce_1 = self
            .generate_nonces(operator_index, &key_agg_ctx, 1, &payout_tx)
            .await;

        trace!(action = "creating secnonce and pubnonce for disprove tx", %operator_index);
        let disprove_pubnonce = self
            .generate_nonces(operator_index, &key_agg_ctx, 0, &disprove_tx)
            .await;

        CovenantNonceRequestFulfilled {
            pre_assert: pre_assert_pubnonce,
            post_assert: post_assert_pubnonce,
            disprove: disprove_pubnonce,
            payout_0: payout_pubnonce_0,
            payout_1: payout_pubnonce_1,
        }
    }

    async fn gather_and_fulfill_nonces(
        &mut self,
        deposit_txid: Txid,
        pre_assert_txid: Txid,
        post_assert_txid: Txid,
        payout_txid: Txid,
        disprove_txid: Txid,
    ) {
        let own_index = self.build_context.own_index();

        let mut requests_served = HashSet::new();
        requests_served.insert(own_index);

        let mut self_requests_fulfilled = false;

        let num_signers = self.build_context.pubkey_table().0.len();

        // FIXME: beware of `continue`-ing in this while loop. Since we don't close the sender
        // ever (as it is shared), continue-ing may cause the loop to wait for a message that will
        // never be received.
        while let Ok(msg) = self.covenant_nonce_receiver.recv().await {
            match msg {
                CovenantNonceSignal::Request { details, sender_id } => {
                    if sender_id == self.build_context.own_index() {
                        if self_requests_fulfilled && requests_served.len() == num_signers {
                            info!(event = "all nonce requests fulfilled and served", %deposit_txid, %own_index);

                            return;
                        }

                        info!(event = "self request ignored", %deposit_txid, %sender_id, %own_index);

                        // ignore own request
                        continue;
                    }

                    // fulfill request
                    let CovenantNonceRequest {
                        peg_out_graph_input,
                    } = details;
                    info!(event = "received covenant request for nonce", %deposit_txid, %sender_id, %own_index);
                    let connectors = PegOutGraphConnectors::new(
                        self.public_db.clone(),
                        &self.build_context,
                        deposit_txid,
                        sender_id,
                    )
                    .await;
                    let PegOutGraph {
                        kickoff_tx: _,
                        claim_tx: _,
                        assert_chain,
                        disprove_tx,
                        payout_tx,
                    } = PegOutGraph::generate(
                        peg_out_graph_input,
                        deposit_txid,
                        connectors,
                        sender_id,
                        self.public_db.clone(),
                    )
                    .await;
                    let AssertChain {
                        pre_assert,
                        assert_data: _,
                        post_assert,
                    } = assert_chain;

                    info!(action = "fulfilling covenant request for nonce", %deposit_txid, %sender_id, %own_index);
                    let request_fulfilled = self
                        .generate_covenant_nonces(
                            pre_assert,
                            post_assert,
                            payout_tx,
                            disprove_tx,
                            sender_id,
                        )
                        .await;

                    info!(action = "sending covenant request fulfillment signal for nonce", %deposit_txid, %sender_id, %own_index);
                    self.covenant_nonce_sender
                        .send(CovenantNonceSignal::RequestFulfilled {
                            details: request_fulfilled,
                            sender_id: self.build_context.own_index(),
                            destination_id: sender_id,
                        })
                        .expect("should be able to send through the covenant signal sender");

                    requests_served.insert(sender_id);
                    let count = requests_served.len();
                    trace!(event = "requests served", %deposit_txid, %count, %own_index);

                    if count == num_signers && self_requests_fulfilled {
                        info!(event = "all nonce requests served and fulfilled", %deposit_txid, %count, %own_index);

                        return;
                    }
                }
                CovenantNonceSignal::RequestFulfilled {
                    details,
                    sender_id,
                    destination_id,
                } => {
                    info!(event = "received covenant fulfillment data for nonce", %deposit_txid, %sender_id, %destination_id, %own_index);

                    if destination_id != own_index {
                        if self_requests_fulfilled && requests_served.len() == num_signers {
                            info!(event = "all nonce requests fulfilled and served", %deposit_txid, %own_index);

                            return;
                        }

                        // ignore messages meant for others
                        continue;
                    }

                    let CovenantNonceRequestFulfilled {
                        pre_assert,
                        post_assert,
                        disprove,
                        payout_0,
                        payout_1,
                    } = details;
                    info!(event = "received covenant fulfillment data for nonce", %deposit_txid, %sender_id, %own_index);

                    let txid_input_index_and_nonce = [
                        (pre_assert_txid, 0, pre_assert),
                        (post_assert_txid, 0, post_assert),
                        (disprove_txid, 0, disprove),
                        (payout_txid, 0, payout_0),
                        (payout_txid, 1, payout_1),
                    ];

                    let mut all_done = true;
                    for (txid, input_index, nonce) in txid_input_index_and_nonce {
                        self.db
                            .add_pubnonce(txid, input_index, sender_id, nonce)
                            .await;

                        all_done = self
                            .db
                            .collected_pubnonces(txid, input_index)
                            .await
                            .is_some_and(|v| v.len() == num_signers);
                    }

                    self_requests_fulfilled = all_done;
                    if self_requests_fulfilled && requests_served.len() == num_signers {
                        info!(event = "nonce requests fulfilled and served", %own_index);

                        return;
                    }
                }
            }
        }
    }

    pub async fn aggregate_covenant_signatures(
        &mut self,
        deposit_txid: Txid,
        self_peg_out_graph_input: PegOutGraphInput,
        self_peg_out_graph: PegOutGraph,
    ) {
        let own_index = self.build_context.own_index();

        // 1. Prepare txs
        let PegOutGraph {
            kickoff_tx: _,
            claim_tx: _,
            assert_chain,
            payout_tx,
            disprove_tx,
        } = self_peg_out_graph;
        let AssertChain {
            pre_assert,
            assert_data: _,
            post_assert,
        } = assert_chain;

        // 2. Generate agg nonces
        info!(action = "getting aggregated nonces", %deposit_txid, %own_index);
        let pre_assert_agg_nonce = self
            .get_aggregated_nonce(pre_assert.compute_txid(), 0)
            .await
            .expect("pre-assert nonce must exist");
        let post_assert_agg_nonce = self
            .get_aggregated_nonce(post_assert.compute_txid(), 0)
            .await
            .expect("post-assert nonce must exist");
        let disprove_agg_nonce = self
            .get_aggregated_nonce(disprove_tx.compute_txid(), 0)
            .await
            .expect("disprove nonce must exist");
        let payout_agg_nonce_0 = self
            .get_aggregated_nonce(payout_tx.compute_txid(), 0)
            .await
            .expect("payout 0 nonce must exist");
        let payout_agg_nonce_1 = self
            .get_aggregated_nonce(payout_tx.compute_txid(), 1)
            .await
            .expect("payout nonce 1 must exist");

        let agg_nonces = AggNonces {
            pre_assert: pre_assert_agg_nonce,
            post_assert: post_assert_agg_nonce,
            disprove: disprove_agg_nonce,
            payout_0: payout_agg_nonce_0,
            payout_1: payout_agg_nonce_1,
        };

        // 3. Generate own signatures
        info!(action = "generating signature for this operator",  deposit_txid = %deposit_txid, %own_index);
        self.generate_covenant_signatures(
            agg_nonces.clone(),
            own_index,
            pre_assert.clone(),
            post_assert.clone(),
            payout_tx.clone(),
            disprove_tx.clone(),
        )
        .await;

        // 3. Broadcast signature request
        info!(action = "broadcasting this operator's signature", %deposit_txid, %own_index);
        let details = CovenantSigRequest {
            peg_out_graph_input: self_peg_out_graph_input,
            agg_nonces: agg_nonces.clone(),
        };
        self.covenant_sig_sender
            .send(CovenantSignatureSignal::Request {
                details,
                sender_id: own_index,
            })
            .expect("should be able to send covenant signal");

        // 4. Listen for requests and fulfillment data from others.
        info!(action = "listening for signature requests and fulfillments",  deposit_txid = %deposit_txid, %own_index );
        self.gather_and_fulfill_signatures(
            deposit_txid,
            pre_assert.compute_txid(),
            post_assert.compute_txid(),
            payout_tx.compute_txid(),
            disprove_tx.compute_txid(),
        )
        .await;

        // 5. Update public db with aggregated signatures
        info!(action = "computing aggregate signatures",  deposit_txid = %deposit_txid, %own_index );
        let key_agg_ctx = KeyAggContext::new(self.build_context.pubkey_table().0.values().copied())
            .expect("should be able to create key agg ctx");

        let all_inputs = pre_assert.witnesses().len();
        self.compute_agg_sig(
            &key_agg_ctx,
            all_inputs,
            pre_assert,
            vec![agg_nonces.pre_assert; all_inputs].as_ref(),
        )
        .await;
        debug!(event = "computed aggregate signature for pre-assert", deposit_txid = %deposit_txid, %own_index);

        let all_inputs = post_assert.witnesses().len();
        self.compute_agg_sig(
            &key_agg_ctx,
            all_inputs,
            post_assert,
            vec![agg_nonces.post_assert; all_inputs].as_ref(),
        )
        .await;
        debug!(event = "computed aggregate signature for post-assert", deposit_txid = %deposit_txid, %own_index);

        self.compute_agg_sig(
            &key_agg_ctx,
            all_inputs,
            payout_tx,
            &[agg_nonces.payout_0, agg_nonces.payout_1],
        )
        .await;
        debug!(event = "computed aggregate signature for payout", deposit_txid = %deposit_txid, %own_index);

        let all_inputs = disprove_tx.witnesses().len();
        self.compute_agg_sig(
            &key_agg_ctx,
            1,
            disprove_tx,
            vec![agg_nonces.disprove; all_inputs].as_ref(),
        )
        .await;
        debug!(event = "computed aggregate signature for disprove", deposit_txid = %deposit_txid, %own_index);
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn generate_covenant_signatures(
        &self,
        agg_nonces: AggNonces,
        operator_index: OperatorIdx,
        pre_assert: PreAssertTx,
        post_assert: PostAssertTx,
        payout_tx: PayoutTx,
        disprove_tx: DisproveTx,
    ) -> CovenantSigRequestFulfilled {
        let own_index = self.build_context.own_index();

        let key_agg_ctx = KeyAggContext::new(self.build_context.pubkey_table().0.values().copied())
            .expect("should be able to create key agg ctx");

        let all_inputs = pre_assert.witnesses().len();
        trace!(action = "signing pre-assert tx partially", %operator_index);
        let pre_assert_partial_sigs = self
            .sign_partial(
                &key_agg_ctx,
                TapSighashType::Default,
                all_inputs,
                own_index,
                operator_index,
                pre_assert,
                vec![agg_nonces.pre_assert; all_inputs].as_ref(),
            )
            .await;

        trace!(action = "signing post-assert tx partially", %operator_index);
        let all_inputs = post_assert.witnesses().len();
        let post_assert_partial_sigs = self
            .sign_partial(
                &key_agg_ctx,
                TapSighashType::Default,
                all_inputs,
                own_index,
                operator_index,
                post_assert,
                vec![agg_nonces.post_assert; all_inputs].as_ref(),
            )
            .await;

        trace!(action = "signing payout tx partially", %operator_index);
        let payout_partial_sigs = self
            .sign_partial(
                &key_agg_ctx,
                TapSighashType::Default,
                all_inputs,
                own_index,
                operator_index,
                payout_tx,
                &[agg_nonces.payout_0, agg_nonces.payout_1],
            )
            .await;

        trace!(action = "signing disprove tx partially", %operator_index);
        let inputs_to_sign = disprove_tx.witnesses().len();
        let disprove_partial_sigs = self
            .sign_partial(
                &key_agg_ctx,
                TapSighashType::Single,
                inputs_to_sign,
                own_index,
                operator_index,
                disprove_tx,
                vec![agg_nonces.disprove; inputs_to_sign].as_ref(),
            )
            .await;

        CovenantSigRequestFulfilled {
            pre_assert: pre_assert_partial_sigs,
            post_assert: post_assert_partial_sigs,
            disprove: disprove_partial_sigs,
            payout: payout_partial_sigs,
        }
    }

    pub async fn gather_and_fulfill_signatures(
        &mut self,
        deposit_txid: Txid,
        pre_assert_txid: Txid,
        post_assert_txid: Txid,
        payout_txid: Txid,
        disprove_txid: Txid,
    ) {
        let own_index = self.build_context.own_index();

        let mut requests_served = HashSet::new();
        requests_served.insert(own_index);

        let mut self_requests_fulfilled = false;

        let num_signers = self.build_context.pubkey_table().0.len();

        // FIXME: beware of `continue`-ing in this while loop. Since we don't close the sender
        // ever (as it is shared), continue-ing may cause the loop to wait for a message that will
        // never be received.
        while let Ok(msg) = self.covenant_sig_receiver.recv().await {
            match msg {
                CovenantSignatureSignal::Request { details, sender_id } => {
                    if sender_id == own_index {
                        if self_requests_fulfilled && requests_served.len() == num_signers {
                            info!(event = "all nonce requests fulfilled and served", %deposit_txid, %own_index);

                            return;
                        }

                        info!(event = "ignored self request for signatures", %deposit_txid, %own_index);
                        continue;
                    }

                    // fulfill request
                    let CovenantSigRequest {
                        agg_nonces,
                        peg_out_graph_input,
                    } = details;
                    info!(event = "received covenant request for signatures", %deposit_txid, %sender_id, %own_index);
                    let connectors = PegOutGraphConnectors::new(
                        self.public_db.clone(),
                        &self.build_context,
                        deposit_txid,
                        sender_id,
                    )
                    .await;
                    let PegOutGraph {
                        kickoff_tx: _,
                        claim_tx: _,
                        assert_chain,
                        disprove_tx,
                        payout_tx,
                    } = PegOutGraph::generate(
                        peg_out_graph_input,
                        deposit_txid,
                        connectors,
                        sender_id,
                        self.public_db.clone(),
                    )
                    .await;
                    let AssertChain {
                        pre_assert,
                        assert_data: _,
                        post_assert,
                    } = assert_chain;

                    info!(action = "fulfilling covenant request for signatures", %deposit_txid, %sender_id, %own_index);
                    let request_fulfilled = self
                        .generate_covenant_signatures(
                            agg_nonces,
                            sender_id,
                            pre_assert,
                            post_assert,
                            payout_tx,
                            disprove_tx,
                        )
                        .await;

                    info!(action = "sending covenant request fulfillment signal for signatures", %deposit_txid, destination_id = %sender_id, %own_index);
                    self.covenant_sig_sender
                        .send(CovenantSignatureSignal::RequestFulfilled {
                            details: request_fulfilled,
                            sender_id: own_index,
                            destination_id: sender_id,
                        })
                        .expect("should be able to send through the covenant signal sender");

                    requests_served.insert(sender_id);
                    let count = requests_served.len();
                    trace!(event = "requests served", %deposit_txid, %count, %own_index);

                    if count == num_signers && self_requests_fulfilled {
                        info!(event = "all signature requests served and fulfilled", %deposit_txid, %own_index);

                        return;
                    }
                }
                CovenantSignatureSignal::RequestFulfilled {
                    details,
                    sender_id,
                    destination_id,
                } => {
                    if destination_id != own_index {
                        if self_requests_fulfilled && requests_served.len() == num_signers {
                            info!(event = "all nonce requests fulfilled and served", %deposit_txid, %own_index);

                            return;
                        }

                        // ignore messages meant for others
                        continue;
                    }

                    let CovenantSigRequestFulfilled {
                        pre_assert,
                        post_assert,
                        disprove,
                        payout,
                    } = details;
                    info!(event = "received covenant fulfillment data for signature", %deposit_txid, %sender_id, %own_index);

                    let txid_and_signatures = [
                        (pre_assert_txid, pre_assert),
                        (post_assert_txid, post_assert),
                        (disprove_txid, disprove),
                        (payout_txid, payout),
                    ];

                    let mut all_done = true;
                    for (txid, signatures) in txid_and_signatures {
                        for (input_index, partial_sig) in signatures.into_iter().enumerate() {
                            self.db
                                .add_partial_signature(
                                    txid,
                                    input_index as u32,
                                    sender_id,
                                    partial_sig,
                                )
                                .await;

                            all_done = all_done
                                && self
                                    .db
                                    .collected_signatures_per_msg(txid, input_index as u32)
                                    .await
                                    .is_some_and(|v| {
                                        let sig_count = v.1.len();
                                        debug!(event = "got sig count", %sig_count, %txid, %input_index, %own_index);

                                        sig_count == num_signers
                                    });
                        }
                    }

                    self_requests_fulfilled = all_done;
                    if self_requests_fulfilled && requests_served.len() == num_signers {
                        info!(event = "all signature requests fulfilled and served", %deposit_txid, %own_index);

                        return;
                    }
                }
            }
        }
    }

    pub async fn aggregate_nonces(&mut self, tx_signing_data: TxSigningData) -> Option<AggNonce> {
        let tx = tx_signing_data.psbt.unsigned_tx.clone();
        let txid = tx.compute_txid();

        let own_index = self.build_context.own_index();

        info!(action = "generating one's own nonce for deposit sweeping", deposit_txid=%txid, operator_idx=%own_index);
        let key_agg_ctx = KeyAggContext::new(self.build_context.pubkey_table().0.values().copied())
            .expect("should be able to create key agg context");

        let secnonce = self.agent.generate_sec_nonce(&txid, &key_agg_ctx);
        self.db.add_secnonce(txid, 0, secnonce.clone()).await;

        let pubnonce = secnonce.public_nonce();

        self.db
            .add_pubnonce(txid, 0, own_index, pubnonce.clone())
            .await;

        info!(action = "broadcasting one's own nonce for deposit sweeping", deposit_txid=%txid, %own_index);
        self.deposit_signal_sender
            .send(DepositSignal::Nonce {
                txid,
                pubnonce,
                sender_id: own_index,
            })
            .expect("should be able to send deposit pubnonce");

        info!(action = "listening for nonces for deposit sweeping", deposit_txid=%txid, %own_index);

        let expected_nonce_count = self.build_context.pubkey_table().0.len();
        while let Ok(deposit_signal) = self.deposit_signal_receiver.recv().await {
            if let DepositSignal::Nonce {
                txid,
                pubnonce,
                sender_id,
            } = deposit_signal
            {
                info!(event = "received nonce for deposit sweeping", deposit_txid=%txid, %own_index, %sender_id);
                self.db.add_pubnonce(txid, 0, sender_id, pubnonce).await;

                if let Some(collected_nonces) = self.db.collected_pubnonces(txid, 0).await {
                    let nonce_count = collected_nonces.len();
                    if nonce_count != expected_nonce_count {
                        // NOTE: there is still some nonce to be received, so continuing to listen
                        // on the channel is fine.
                        debug!(event = "collected nonces but not sufficient yet", %nonce_count, %expected_nonce_count);

                        continue;
                    }

                    info!(event = "received all required nonces for deposit sweeping", deposit_txid=%txid, %own_index, %sender_id);
                    return Some(collected_nonces.values().sum());
                }
            } else {
                // ignore signatures in this function
                warn!(
                    ?deposit_signal,
                    %own_index,
                    "should not receive signatures in this function"
                );
            }
        }

        error!(event = "deposit signal sender closed before completion", deposit_txid=%txid, %own_index);
        None
    }

    pub async fn aggregate_signatures(
        &mut self,
        agg_nonce: AggNonce,
        tx_signing_data: &mut TxSigningData,
    ) -> Option<Transaction> {
        let own_index = self.build_context.own_index();

        let tx = &tx_signing_data.psbt.unsigned_tx;
        let txid = tx.compute_txid();

        let prevouts = tx_signing_data
            .psbt
            .inputs
            .iter()
            .map(|i| {
                i.witness_utxo
                    .clone()
                    .expect("witness UTXO must be present")
            })
            .collect::<Vec<TxOut>>();
        let prevouts = Prevouts::All(&prevouts);

        let key_agg_ctx = KeyAggContext::new(self.build_context.pubkey_table().0.values().copied())
            .expect("should be able to generate agg key context");
        let seckey = self.agent.secret_key();
        let secnonce = self
            .db
            .get_secnonce(txid, 0)
            .await
            .expect("secnonce should exist before adding signatures");

        info!(action = "generating one's own signature for deposit sweeping", deposit_txid=%txid, operator_idx=%own_index);

        let mut sighash_cache = SighashCache::new(tx);
        let message = create_message_hash(
            &mut sighash_cache,
            prevouts,
            &tx_signing_data.spend_path,
            TapSighashType::Default,
            0,
        )
        .expect("should be able to create message hash");
        let message = message.as_ref();

        let partial_signature = sign_partial(&key_agg_ctx, seckey, secnonce, &agg_nonce, message)
            .expect("should be able to sign deposit");
        self.db
            .add_message_hash_and_signature(txid, 0, message.to_vec(), own_index, partial_signature)
            .await;

        info!(action = "broadcasting one's own signature for deposit sweeping", deposit_txid=%txid, operator_idx=%own_index);
        self.deposit_signal_sender
            .send(DepositSignal::Signature {
                txid,
                signature: partial_signature,
                sender_id: own_index,
            })
            .expect("should be able to send signature");

        info!(action = "listening for signatures for deposit sweeping", deposit_txid=%txid, operator_idx=%own_index);

        let expected_signature_count = self.build_context.pubkey_table().0.len();
        while let Ok(deposit_signal) = self.deposit_signal_receiver.recv().await {
            if let DepositSignal::Signature {
                txid,
                signature,
                sender_id,
            } = deposit_signal
            {
                // TODO: add signature verification logic in prod
                // for now, this is fine because musig2 validates every signature during generation.
                self.db
                    .add_partial_signature(txid, 0, sender_id, signature)
                    .await;

                if let Some((_, collected_signatures)) =
                    self.db.collected_signatures_per_msg(txid, 0).await
                {
                    let sig_count = collected_signatures.len();
                    if collected_signatures.len() != expected_signature_count {
                        // NOTE: there is still some signature to be received, so continuing to
                        // listen on the channel is fine.
                        debug!(event = "collected signatures but not sufficient yet", %sig_count, %expected_signature_count);

                        continue;
                    }

                    info!(event = "received all required signatures for deposit sweeping");

                    let agg_signature: Signature = aggregate_partial_signatures(
                        &key_agg_ctx,
                        &agg_nonce,
                        collected_signatures.values().copied(),
                        message,
                    )
                    .expect("should be able to aggregate signatures");

                    info!(event = "signature aggregation complete for deposit sweeping", deposit_txid=%txid, operator_idx=%own_index);

                    if let TaprootWitness::Script {
                        script_buf,
                        control_block,
                    } = tx_signing_data.spend_path.clone()
                    {
                        let witnesses = [
                            agg_signature.as_ref().to_vec(),
                            script_buf.to_bytes(),
                            control_block.serialize(),
                        ];
                        finalize_input(
                            tx_signing_data
                                .psbt
                                .inputs
                                .first_mut()
                                .expect("the first input must exist"),
                            witnesses,
                        );

                        let signed_tx = tx_signing_data
                            .psbt
                            .clone()
                            .extract_tx()
                            .expect("should be able to extract fully signed tx");
                        debug!(event = "created signed tx", ?signed_tx);
                        info!(event = "deposit transaction fully signed and ready for broadcasting", deposit_txid=%txid, operator_idx=%own_index);

                        return Some(signed_tx);
                    } else {
                        unreachable!("deposit request should have a script spend path");
                    };
                }
            } else {
                // ignore nonces in this function
                warn!(?deposit_signal, %own_index, "should not receive nonces in this function");
            }
        }

        error!(event = "deposit signal sender closed before completion", deposit_txid=%txid, %own_index);
        None
    }

    pub async fn generate_nonces(
        &self,
        operator_idx: OperatorIdx,
        key_agg_ctx: &KeyAggContext,
        input_index: u32,
        tx: &impl CovenantTx,
    ) -> PubNonce {
        let txid = tx.compute_txid();

        let secnonce = self.agent.generate_sec_nonce(&txid, key_agg_ctx);
        let pubnonce = secnonce.public_nonce();

        // add the secnonce and pubnonce to db even for txid from others as it is required for
        // partial signing later.
        self.db.add_secnonce(txid, input_index, secnonce).await;
        self.db
            .add_pubnonce(txid, input_index, operator_idx, pubnonce.clone())
            .await;

        pubnonce
    }

    /// Get the aggregated nonce from the list of collected nonces for the transaction
    /// corresponding to the given [`Txid`].
    ///
    /// Please refer to MuSig2 nonce aggregation section in
    /// [BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).
    /// # Errors
    ///
    /// If not all nonces have been colllected yet.
    pub async fn get_aggregated_nonce(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> anyhow::Result<AggNonce> {
        if let Some(collected_nonces) = self.db.collected_pubnonces(txid, input_index).await {
            let expected_nonce_count = self.build_context.pubkey_table().0.len();
            if collected_nonces.len() != expected_nonce_count {
                let collected: Vec<u32> = collected_nonces.keys().copied().collect();
                error!(?collected, %expected_nonce_count, "nonce collection incomplete");

                bail!("nonce collection incomplete");
            }

            Ok(collected_nonces.values().sum())
        } else {
            error!(%txid, %input_index, "nonces not found");

            bail!("nonce not found");
        }
    }

    /// Create partial signature for the tx.
    ///
    /// Make sure that `prevouts`, `agg_nonces` and `witnesses` have the same length.
    #[expect(clippy::too_many_arguments)]
    async fn sign_partial<Tx: CovenantTx + fmt::Debug>(
        &self,
        key_agg_ctx: &KeyAggContext,
        sighash_type: TapSighashType,
        inputs_to_sign: usize,
        own_index: OperatorIdx,
        operator_index: OperatorIdx,
        covenant_tx: Tx,
        agg_nonces: &[AggNonce],
    ) -> Vec<PartialSignature> {
        let tx = &covenant_tx.psbt().unsigned_tx;
        let txid = tx.compute_txid();

        let prevouts = covenant_tx.prevouts();
        let witnesses = covenant_tx.witnesses();

        let mut sighash_cache = SighashCache::new(tx);

        let mut partial_sigs: Vec<PartialSignature> = Vec::with_capacity(witnesses.len());
        for (input_index, (agg_nonce, witness)) in agg_nonces
            .iter()
            .zip(witnesses)
            .enumerate()
            .take(inputs_to_sign)
        {
            trace!(action = "creating message hash", ?covenant_tx, %input_index);

            let message = create_message_hash(
                &mut sighash_cache,
                prevouts.clone(),
                witness,
                sighash_type,
                input_index,
            )
            .expect("should be able to create a message hash");
            let message = message.as_ref();

            let secnonce =
                if let Some(secnonce) = self.db.get_secnonce(txid, input_index as u32).await {
                    secnonce
                } else {
                    // use the first secnonce if the given input_index does not exist
                    // this is the case for post_assert inputs (but not for payout)
                    self.db
                        .get_secnonce(txid, 0)
                        .await
                        .expect("first secnonce should exist")
                };

            let seckey = self.agent.secret_key();

            let agg_ctx = if matches!(witness, TaprootWitness::Key) {
                &key_agg_ctx
                    .clone()
                    .with_unspendable_taproot_tweak()
                    .expect("should be able to add unspendable key tweak")
            } else {
                key_agg_ctx
            };

            let partial_sig: PartialSignature =
                sign_partial(agg_ctx, seckey, secnonce, agg_nonce, message)
                    .expect("should be able to sign pre-assert");

            partial_sigs.push(partial_sig);

            if own_index == operator_index {
                self.db
                    .add_message_hash_and_signature(
                        txid,
                        input_index as u32,
                        message.to_vec(),
                        own_index,
                        partial_sig,
                    )
                    .await;
            }
        }

        partial_sigs
    }

    async fn compute_agg_sig(
        &self,
        key_agg_ctx: &KeyAggContext,
        inputs_to_sign: usize,
        covenant_tx: impl CovenantTx,
        agg_nonces: &[AggNonce],
    ) {
        let txid = covenant_tx.compute_txid();

        let witnesses = covenant_tx.witnesses();

        for (input_index, (agg_nonce, witness)) in agg_nonces
            .iter()
            .zip(witnesses)
            .enumerate()
            .take(inputs_to_sign)
        {
            let agg_ctx = if matches!(witness, TaprootWitness::Key) {
                &key_agg_ctx
                    .clone()
                    .with_unspendable_taproot_tweak()
                    .expect("should be able to add unspendable key tweak")
            } else {
                key_agg_ctx
            };

            let collected_msgs_and_sigs = self
                .db
                .collected_signatures_per_msg(txid, input_index as u32)
                .await
                .expect("partial signatures must be present");
            let message = collected_msgs_and_sigs.0;
            let partial_sigs: Vec<PartialSignature> =
                collected_msgs_and_sigs.1.values().copied().collect();

            let agg_sig: Signature =
                aggregate_partial_signatures(agg_ctx, agg_nonce, partial_sigs, message)
                    .expect("signature aggregation must succeed");

            self.public_db
                .set_signature(
                    self.build_context.own_index(),
                    txid,
                    input_index as u32,
                    agg_sig,
                )
                .await;
        }
    }

    pub async fn handle_withdrawal(&self, withdrawal_info: WithdrawalInfo) {
        // 0. get context
        let network = self.build_context.network();
        let own_index = self.build_context.own_index();

        #[cfg(feature = "mock")]
        let deposit_txid = Txid::from_byte_array(mock::PUBLIC_INPUTS.0);

        #[cfg(not(feature = "mock"))]
        let deposit_txid = withdrawal_info.deposit_outpoint().txid;

        let own_pubkey = self.agent.public_key().x_only_public_key().0;

        // 1. pay the user with PoW transaction
        let user_pk = withdrawal_info.user_pk();

        info!(action = "paying out the user", %user_pk, %own_index);
        #[cfg(feature = "mock")]
        let bridge_out_txid = Txid::from_byte_array(mock::PUBLIC_INPUTS.2);

        #[cfg(not(feature = "mock"))]
        let bridge_out_txid = self
            .pay_user(user_pk, network, own_index)
            .await
            .expect("must be able to pay user");

        self.duty_status_sender
            .send((
                deposit_txid,
                BridgeDutyStatus::Withdrawal(WithdrawalStatus::PaidUser),
            ))
            .await
            .expect("should be able to send duty status");

        // 2. create tx graph from public data
        info!(action = "reconstructing pegout graph", %deposit_txid, %own_index);
        let KickoffInfo {
            funding_inputs,
            funding_utxos,
            change_address,
            change_amt,
        } = self
            .db
            .get_kickoff_info(deposit_txid)
            .await
            .expect("kickoff data for the deposit must be present");

        let peg_out_graph_input = PegOutGraphInput {
            network,
            deposit_amount: BRIDGE_DENOMINATION,
            operator_pubkey: own_pubkey,
            kickoff_data: KickoffTxData {
                funding_inputs,
                funding_utxos,
                change_address,
                change_amt,
                deposit_txid,
            },
        };

        let connectors = PegOutGraphConnectors::new(
            self.public_db.clone(),
            &self.build_context,
            deposit_txid,
            own_index,
        )
        .await;

        let PegOutGraph {
            kickoff_tx,
            claim_tx,
            assert_chain,
            payout_tx,
            disprove_tx: _,
        } = PegOutGraph::generate(
            peg_out_graph_input,
            deposit_txid,
            connectors.clone(),
            own_index,
            self.public_db.clone(),
        )
        .await;

        // 3. publish kickoff -> claim
        let superblock_period_start_ts = self
            .broadcast_kickoff_and_claim(
                &connectors,
                own_index,
                deposit_txid,
                kickoff_tx,
                claim_tx,
                bridge_out_txid,
            )
            .await;

        // 4. compute superblock and proof (skip)
        info!(event = "challenge received, computing proof");
        #[cfg(not(feature = "mock"))]
        self.generate_g16_proof(deposit_txid, bridge_out_txid, superblock_period_start_ts)
            .await;

        info!(action = "creating assertion signatures", %own_index);

        // #[cfg(feature = "mock")]
        let assert_data_signatures = {
            let mut assertions = mock_assertions();
            if self.am_i_faulty() {
                warn!(action = "making a faulty assertion");
                assertions.groth16.0[0] = [0u8; 32];
            }
            generate_wots_signatures(&self.msk, deposit_txid, assertions)
        };

        // 5. publish assert chain
        let AssertChain {
            pre_assert,
            assert_data,
            post_assert,
        } = assert_chain;

        let pre_assert_txid = pre_assert.compute_txid();
        let n_of_n_sig = self
            .public_db
            .get_signature(own_index, pre_assert_txid, 0)
            .await;
        let signed_pre_assert = pre_assert.finalize(n_of_n_sig, connectors.claim_out_0);
        let vsize = signed_pre_assert.vsize();
        let total_size = signed_pre_assert.total_size();
        let weight = signed_pre_assert.weight();
        info!(event = "finalized pre-assert tx", %pre_assert_txid, %vsize, %total_size, %weight, %own_index);

        let txid = self
            .agent
            .wait_and_broadcast(&signed_pre_assert, BTC_CONFIRM_PERIOD)
            .await
            .expect("should settle pre-assert");
        info!(event = "broadcasted pre-assert", %txid, %own_index);

        self.duty_status_sender
            .send((
                deposit_txid,
                BridgeDutyStatus::Withdrawal(WithdrawalStatus::PreAssert),
            ))
            .await
            .expect("should be able to send duty status");

        let signed_assert_data_txs = assert_data.finalize(
            connectors.assert_data160_factory,
            connectors.assert_data256_factory,
            &self.msk,
            assert_data_signatures,
        );

        let num_assert_data_txs = signed_assert_data_txs.len();
        info!(
            event = "finalized signed assert data txs",
            num_assert_data_txs
        );

        info!(action = "estimating finalized assert data tx sizes", %own_index);
        for (index, signed_assert_data_tx) in signed_assert_data_txs.iter().enumerate() {
            let txid = signed_assert_data_tx.compute_txid();
            let vsize = signed_assert_data_tx.vsize();
            let total_size = signed_assert_data_tx.total_size();
            let weight = signed_assert_data_tx.weight();
            info!(event = "assert-data tx", %index, %txid, %vsize, %total_size, %weight, %own_index);
        }

        info!(action = "broadcasting finalized assert data txs", %own_index);
        let mut broadcasted_assert_data_txids = Vec::with_capacity(TOTAL_CONNECTORS);
        for (index, signed_assert_data_tx) in signed_assert_data_txs.iter().enumerate() {
            info!(event = "broadcasting signed assert data tx", %index, %num_assert_data_txs);

            let txid = self
                .agent
                .wait_and_broadcast(signed_assert_data_tx, Duration::from_secs(1))
                .await
                .expect("should settle assert-data");

            broadcasted_assert_data_txids.push(txid);

            self.duty_status_sender
                .send((
                    deposit_txid,
                    BridgeDutyStatus::Withdrawal(WithdrawalStatus::AssertData(index)),
                ))
                .await
                .expect("should be able to send duty status");

            info!(event = "broadcasted signed assert data tx", %index, %num_assert_data_txs);
        }

        let post_assert_txid = post_assert.compute_txid();
        let mut signatures = Vec::new();
        // num_assert_data_tx + 1 for stake
        for input_index in 0..=num_assert_data_txs {
            let n_of_n_sig = self
                .public_db
                .get_signature(own_index, post_assert_txid, input_index as u32)
                .await;

            signatures.push(n_of_n_sig);
        }

        let signed_post_assert = post_assert.finalize(&signatures);
        let vsize = signed_pre_assert.vsize();
        let total_size = signed_pre_assert.total_size();
        let weight = signed_pre_assert.weight();
        info!(event = "finalized post-assert tx", %post_assert_txid, %vsize, %total_size, %weight, %own_index);

        let txid = self
            .agent
            .btc_client
            .send_raw_transaction(&signed_post_assert)
            .await
            .expect("should be able to finalize post-assert tx");

        self.duty_status_sender
            .send((
                deposit_txid,
                BridgeDutyStatus::Withdrawal(WithdrawalStatus::PostAssert),
            ))
            .await
            .expect("should be able to send duty status");
        info!(event = "broadcasted post-assert tx", %post_assert_txid, %own_index);

        // 6. settle reimbursement tx after wait time
        let wait_time = Duration::from_secs(PAYOUT_TIMELOCK as u64 + 20);
        info!(action = "waiting for timeout period before seeking reimbursement", wait_time_secs=%wait_time.as_secs());
        tokio::time::sleep(wait_time).await;

        let n_of_n_signature = self
            .public_db
            .get_signature(own_index, payout_tx.compute_txid(), 0)
            .await;
        let signed_payout_tx = payout_tx.finalize(n_of_n_signature);

        info!(action = "trying to get reimbursement", payout_txid=%signed_payout_tx.compute_txid(), %own_index);

        match self
            .agent
            .wait_and_broadcast(&signed_payout_tx, BTC_CONFIRM_PERIOD)
            .await
        {
            Ok(txid) => {
                self.duty_status_sender
                    .send((
                        deposit_txid,
                        BridgeDutyStatus::Withdrawal(WithdrawalStatus::Executed),
                    ))
                    .await
                    .expect("should be able to send duty status");
                info!(event = "successfully received reimbursement", %txid, %own_index);
            }
            Err(e) => {
                error!(msg = "unable to get reimbursement :(", %e, %txid, %own_index);
            }
        }
    }

    async fn broadcast_kickoff_and_claim(
        &self,
        connectors: &PegOutGraphConnectors<P>,
        own_index: u32,
        deposit_txid: Txid,
        kickoff_tx: KickOffTx,
        claim_tx: ClaimTx,
        bridge_out_txid: Txid,
    ) -> u32 {
        #[cfg(feature = "mock")]
        let superblock_period_start_ts = mock::PUBLIC_INPUTS.3;

        #[cfg(not(feature = "mock"))]
        let superblock_period_start_ts = self
            .agent
            .btc_client
            .get_current_timestamp()
            .await
            .expect("should be able to get the latest timestamp from the best block");
        debug!(event = "got current timestamp (T_s)", %superblock_period_start_ts, %own_index);

        let unsigned_kickoff = &kickoff_tx.psbt().unsigned_tx;
        info!(action = "funding kickoff tx with wallet", ?unsigned_kickoff);
        let funded_kickoff = self
            .agent
            .btc_client
            .sign_raw_transaction_with_wallet(unsigned_kickoff)
            .await
            .expect("should be able to sign kickoff tx with wallet");
        let funded_kickoff_tx: Transaction =
            consensus::encode::deserialize_hex(&funded_kickoff.hex)
                .expect("must be able to decode kickoff tx");
        info!(event = "funded kickoff tx with wallet", ?funded_kickoff_tx);

        let kickoff_txid = funded_kickoff_tx.compute_txid();
        info!(action = "broadcasting kickoff tx", %deposit_txid, %kickoff_txid, %own_index);
        let kickoff_txid = self
            .agent
            .btc_client
            .send_raw_transaction(&funded_kickoff_tx)
            .await
            .expect("should be able to broadcast signed kickoff tx");

        self.duty_status_sender
            .send((
                deposit_txid,
                BridgeDutyStatus::Withdrawal(WithdrawalStatus::Kickoff),
            ))
            .await
            .expect("should be able to send duty status");

        info!(event = "broadcasted kickoff tx", %deposit_txid, %kickoff_txid, %own_index);

        let claim_tx_with_commitment = claim_tx
            .finalize(
                deposit_txid,
                &connectors.kickoff,
                &self.msk,
                bridge_out_txid,
                superblock_period_start_ts,
            )
            .await;

        let raw_claim_tx: String = consensus::encode::serialize_hex(&claim_tx_with_commitment);
        trace!(event = "finalized claim tx", %deposit_txid, ?claim_tx_with_commitment, %raw_claim_tx, %own_index);

        let claim_txid = self
            .agent
            .btc_client
            .send_raw_transaction(&claim_tx_with_commitment)
            .await
            .expect("should be able to publish claim tx with commitment to bridge_out_txid and superblock period start_ts");

        info!(event = "broadcasted claim tx", %deposit_txid, %claim_txid, %own_index);

        self.duty_status_sender
            .send((
                deposit_txid,
                BridgeDutyStatus::Withdrawal(WithdrawalStatus::Claim),
            ))
            .await
            .expect("should be able to send duty status");

        superblock_period_start_ts
    }

    #[cfg(not(feature = "mock"))]
    async fn pay_user(
        &self,
        user_pk: XOnlyPublicKey,
        network: bitcoin::Network,
        own_index: OperatorIdx,
    ) -> anyhow::Result<Txid> {
        if self.am_i_faulty() {
            let buffer: [u8; 32] = OsRng.gen();
            let fake_txid = Txid::from_byte_array(buffer);

            warn!(action = "faking bridge out", %fake_txid, %own_index);
            return Ok(fake_txid);
        }

        let net_payment = BRIDGE_DENOMINATION - OPERATOR_FEE;

        // don't use kickoff utxo for payment
        let reserved_utxos = self.db.selected_outpoints().await;

        let (change_address, outpoint, total_amount, prevout) = self
            .agent
            .select_utxo(net_payment, reserved_utxos)
            .await
            .expect("at least one funding utxo must be present in wallet");

        let change_amount = total_amount - net_payment - MIN_RELAY_FEE;
        debug!(%change_address, %change_amount, %outpoint, %total_amount, %net_payment, ?prevout, "found funding utxo for bridge out");

        let bridge_out = BridgeOut::new(
            network,
            own_index,
            vec![outpoint],
            net_payment,
            change_address,
            change_amount,
            user_pk,
        );

        let signed_tx_result = self
            .agent
            .btc_client
            .sign_raw_transaction_with_wallet(&bridge_out.tx())
            .await
            .expect("must be able to sign bridge out transaction");

        assert!(
            signed_tx_result.complete,
            "bridge out tx must be completely signed"
        );

        let signed_tx: Transaction = consensus::encode::deserialize_hex(&signed_tx_result.hex)
            .expect("should be able to deserialize signed tx");

        match self.agent.btc_client.send_raw_transaction(&signed_tx).await {
            Ok(txid) => {
                info!(event = "paid the user successfully", %txid, %own_index);
                Ok(txid)
            }
            Err(e) => {
                error!(?e, "could not broadcast bridge out tx");

                bail!(e.to_string());
            }
        }
    }

    // #[cfg(not(feature = "mock"))]
    async fn generate_g16_proof(
        &self,
        deposit_txid: Txid,
        bridge_out_txid: Txid,
        superblock_period_start_ts: u32,
    ) {
        info!(action = "getting latest checkpoint at the time of withdrawal duty reception");
        let latest_checkpoint_at_payout = self
            .db
            .get_checkpoint_index(deposit_txid)
            .await
            .expect("checkpoint index must exist");

        info!(action = "getting the checkpoint info for the index", %latest_checkpoint_at_payout);
        let checkpoint_info = self
            .agent
            .strata_client
            .get_checkpoint_info(latest_checkpoint_at_payout)
            .await
            .expect("should be able to get checkpoint info")
            .expect("checkpoit info must exist");

        let l1_range = checkpoint_info.l1_range;
        let l2_range = checkpoint_info.l2_range;
        let l1_block_id = checkpoint_info.l1_blockid;
        let l2_block_id = checkpoint_info.l2_blockid;

        info!(event = "got checkpoint info", %latest_checkpoint_at_payout, ?l1_range, ?l2_range, %l1_block_id, %l2_block_id);

        let l2_height_to_query = l2_range.1 + 1;
        info!(action = "getting chain state", %l2_height_to_query);
        let cl_block_witness = self
            .agent
            .strata_client
            .get_cl_block_witness_raw(l2_height_to_query)
            .await
            .expect("should be able to query for CL block witness")
            .expect("cl block witness must exist");

        let _strata_bridge_state = borsh::from_slice::<(ChainState, L2Block)>(&cl_block_witness)
            .expect("should be able to deserialize CL block witness")
            .0;

        let l1_start_height = checkpoint_info.l1_range.1 + 1;
        let superblock_period_end_time = superblock_period_start_ts + SUPERBLOCK_MEASUREMENT_PERIOD;

        let mut height = l1_start_height as u32;
        let mut headers: Vec<Header> = vec![];
        let mut found_bridge_out = false;
        let mut found_checkpoint = false;

        loop {
            let block = self
                .agent
                .btc_client
                .get_block_at(height)
                .await
                .expect("should be able to get block at height");

            if !found_bridge_out {
                // check and get bridge out txid with proof
                found_bridge_out = true;
            }

            if !found_checkpoint {
                // check and get checkpoint idx with proof
                found_checkpoint = true;
            }

            let header = block.header;
            if header.time > superblock_period_end_time {
                break;
            }

            headers.push(header);

            height += 1;
        }

        // let input = BridgeProofInput {
        //     headers,
        //     checkpoint: todo!(),
        //     bridge_out: todo!(),
        //     initial_header_state: todo!(),
        //     superblock_period_start_ts,
        // };
        //
        // let bridge_proof_public_params = process_bridge_proof(input, strata_bridge_state);
    }
}

pub fn mock_assertions() -> Assertions {
    Assertions {
        bridge_out_txid: [
            16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 32, 17, 34, 51,
            68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 32,
        ],
        superblock_hash: [
            170, 187, 204, 221, 238, 255, 32, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187,
            204, 221, 238, 255, 32, 17, 34, 51, 68, 85, 102, 119, 136, 153,
        ],
        superblock_period_start_ts: [239, 190, 173, 222],
        groth16: (
            [[
                80, 109, 248, 180, 9, 193, 114, 154, 115, 169, 168, 240, 183, 156, 241, 46, 0, 195,
                134, 12, 230, 246, 101, 202, 24, 228, 13, 116, 183, 37, 201, 128,
            ]],
            [
                [
                    112, 32, 253, 238, 88, 207, 72, 195, 44, 15, 28, 45, 111, 218, 102, 212, 59,
                    62, 92, 205, 53, 209, 79, 23, 87, 165, 0, 22, 142, 131, 210, 116,
                ],
                [
                    177, 135, 40, 180, 190, 166, 111, 221, 234, 212, 8, 155, 1, 162, 125, 235, 228,
                    15, 224, 181, 139, 66, 227, 106, 118, 195, 110, 65, 62, 146, 11, 174,
                ],
                [
                    96, 67, 40, 63, 210, 100, 68, 67, 214, 86, 1, 22, 44, 130, 135, 244, 41, 213,
                    154, 166, 25, 183, 13, 58, 206, 22, 59, 119, 155, 206, 164, 7,
                ],
                [
                    161, 121, 10, 93, 68, 113, 217, 16, 116, 190, 44, 205, 49, 203, 204, 151, 29,
                    64, 97, 119, 220, 119, 161, 205, 165, 142, 60, 253, 251, 164, 35, 102,
                ],
                [
                    49, 164, 104, 126, 26, 19, 151, 135, 154, 195, 146, 177, 199, 88, 105, 212, 55,
                    99, 238, 5, 201, 100, 61, 237, 129, 46, 207, 160, 5, 222, 135, 113,
                ],
                [
                    177, 101, 136, 196, 109, 10, 161, 23, 222, 239, 198, 72, 186, 53, 129, 183, 11,
                    169, 19, 90, 210, 42, 21, 233, 37, 62, 94, 92, 233, 138, 38, 221,
                ],
                [
                    65, 111, 124, 126, 121, 141, 146, 7, 244, 45, 7, 234, 109, 117, 143, 250, 187,
                    31, 40, 105, 45, 110, 231, 13, 208, 112, 33, 98, 222, 18, 248, 182,
                ],
                [
                    225, 84, 108, 194, 119, 110, 110, 100, 36, 85, 157, 165, 159, 96, 252, 210,
                    185, 57, 95, 149, 195, 81, 156, 52, 88, 214, 244, 12, 247, 11, 150, 71,
                ],
                [
                    97, 64, 80, 35, 13, 233, 167, 154, 124, 78, 178, 162, 106, 54, 59, 64, 229,
                    179, 205, 196, 179, 223, 128, 226, 154, 243, 232, 177, 81, 68, 225, 216,
                ],
                [
                    161, 235, 105, 177, 186, 96, 116, 226, 41, 91, 243, 16, 241, 48, 178, 229, 142,
                    128, 16, 246, 216, 208, 89, 32, 239, 124, 63, 233, 126, 76, 180, 23,
                ],
                [
                    209, 164, 126, 151, 173, 208, 97, 238, 235, 5, 224, 7, 170, 235, 4, 111, 116,
                    29, 236, 170, 243, 230, 80, 104, 195, 75, 164, 95, 185, 53, 160, 200,
                ],
                [
                    18, 237, 242, 40, 102, 5, 209, 218, 203, 74, 198, 220, 106, 192, 241, 142, 48,
                    170, 113, 196, 156, 149, 152, 116, 126, 63, 208, 214, 111, 195, 2, 134,
                ],
                [
                    2, 118, 176, 214, 113, 165, 255, 95, 224, 25, 139, 17, 73, 243, 154, 101, 2,
                    132, 23, 136, 64, 114, 71, 63, 147, 223, 126, 135, 172, 229, 202, 46,
                ],
                [
                    225, 174, 132, 233, 32, 201, 204, 25, 231, 53, 13, 57, 118, 65, 43, 6, 44, 10,
                    246, 127, 187, 252, 10, 118, 144, 48, 173, 111, 177, 232, 52, 242,
                ],
                [
                    161, 238, 13, 77, 218, 255, 35, 80, 161, 139, 171, 94, 167, 97, 85, 133, 185,
                    254, 205, 2, 202, 32, 222, 196, 152, 2, 158, 85, 82, 183, 194, 43,
                ],
                [
                    66, 40, 154, 53, 235, 37, 20, 104, 168, 251, 111, 239, 167, 14, 29, 246, 251,
                    129, 195, 129, 43, 143, 225, 43, 37, 10, 249, 219, 153, 244, 81, 69,
                ],
                [
                    66, 148, 190, 211, 17, 10, 225, 206, 34, 114, 27, 22, 10, 245, 246, 229, 241,
                    243, 190, 26, 8, 159, 9, 69, 69, 22, 216, 100, 82, 178, 209, 192,
                ],
                [
                    226, 128, 110, 219, 218, 31, 84, 117, 203, 190, 151, 2, 182, 60, 152, 50, 228,
                    226, 113, 85, 201, 228, 147, 231, 30, 85, 93, 7, 188, 199, 21, 130,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                [
                    240, 2, 111, 140, 141, 170, 146, 156, 123, 129, 139, 28, 145, 231, 173, 147,
                    67, 224, 16, 227, 126, 213, 11, 245, 2, 63, 96, 228, 99, 183, 243, 153,
                ],
                [
                    48, 250, 81, 177, 119, 8, 60, 97, 236, 87, 237, 15, 206, 171, 148, 158, 63,
                    212, 185, 82, 223, 90, 219, 222, 81, 101, 40, 161, 223, 41, 21, 34,
                ],
                [
                    50, 122, 72, 143, 82, 176, 116, 146, 90, 178, 11, 62, 220, 97, 27, 42, 71, 131,
                    187, 165, 151, 31, 43, 113, 197, 175, 166, 237, 95, 160, 193, 49,
                ],
                [
                    130, 60, 21, 130, 34, 229, 41, 195, 72, 175, 30, 0, 239, 16, 211, 164, 38, 224,
                    6, 180, 249, 252, 116, 123, 29, 54, 207, 71, 31, 252, 177, 136,
                ],
                [
                    146, 119, 142, 36, 1, 73, 54, 239, 41, 236, 201, 145, 97, 184, 197, 82, 161,
                    148, 11, 6, 91, 21, 204, 98, 144, 7, 81, 53, 1, 227, 4, 156,
                ],
                [
                    96, 72, 119, 220, 79, 200, 158, 38, 193, 169, 124, 194, 123, 92, 241, 152, 212,
                    180, 246, 186, 105, 179, 171, 181, 143, 38, 42, 59, 119, 70, 248, 71,
                ],
                [
                    194, 6, 108, 27, 82, 109, 131, 35, 198, 133, 189, 198, 159, 231, 156, 33, 5,
                    101, 87, 175, 165, 57, 35, 144, 61, 178, 57, 128, 85, 52, 217, 63,
                ],
                [
                    225, 19, 214, 240, 111, 230, 42, 175, 121, 238, 205, 215, 242, 188, 146, 232,
                    70, 11, 116, 173, 66, 2, 104, 11, 207, 99, 41, 159, 146, 157, 2, 23,
                ],
                [
                    146, 116, 206, 214, 98, 58, 7, 94, 70, 102, 163, 46, 31, 171, 104, 32, 149, 57,
                    53, 222, 215, 125, 170, 131, 173, 134, 101, 87, 221, 143, 151, 174,
                ],
                [
                    33, 160, 77, 9, 52, 137, 255, 131, 189, 194, 178, 99, 236, 56, 226, 119, 188,
                    219, 238, 255, 26, 235, 48, 168, 52, 20, 146, 108, 12, 163, 35, 26,
                ],
                [
                    161, 164, 82, 52, 34, 242, 246, 38, 232, 70, 77, 148, 15, 219, 212, 148, 39,
                    29, 85, 15, 216, 125, 37, 219, 54, 79, 175, 203, 197, 31, 84, 233,
                ],
            ],
            [
                [
                    53, 97, 8, 126, 205, 170, 108, 97, 149, 233, 13, 68, 51, 217, 183, 26, 169, 55,
                    27, 144,
                ],
                [
                    68, 156, 85, 148, 242, 169, 175, 91, 208, 190, 113, 253, 70, 150, 124, 80, 67,
                    82, 221, 144,
                ],
                [
                    20, 102, 248, 19, 244, 7, 157, 84, 22, 135, 65, 2, 175, 59, 115, 28, 63, 57,
                    219, 225,
                ],
                [
                    7, 99, 180, 128, 201, 48, 60, 2, 254, 124, 34, 223, 52, 122, 230, 113, 253,
                    198, 193, 171,
                ],
                [
                    81, 173, 157, 193, 190, 169, 69, 64, 134, 135, 98, 116, 82, 74, 213, 240, 128,
                    135, 30, 162,
                ],
                [
                    41, 96, 163, 78, 226, 27, 34, 213, 50, 126, 78, 164, 231, 164, 224, 230, 218,
                    130, 110, 248,
                ],
                [
                    194, 66, 145, 64, 22, 197, 140, 64, 81, 178, 183, 100, 126, 235, 73, 208, 48,
                    250, 90, 12,
                ],
                [
                    1, 250, 184, 76, 55, 239, 238, 224, 108, 74, 140, 130, 176, 205, 18, 213, 168,
                    167, 134, 140,
                ],
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                [
                    186, 190, 195, 165, 99, 209, 112, 248, 62, 5, 197, 146, 50, 65, 57, 164, 221,
                    201, 14, 205,
                ],
                [
                    186, 178, 209, 41, 9, 247, 140, 37, 182, 5, 78, 93, 55, 145, 192, 184, 40, 140,
                    31, 45,
                ],
                [
                    165, 73, 71, 32, 214, 193, 67, 161, 30, 215, 123, 132, 244, 173, 230, 34, 41,
                    1, 153, 129,
                ],
                [
                    43, 193, 157, 22, 1, 57, 173, 66, 169, 219, 218, 197, 254, 46, 190, 212, 188,
                    227, 223, 156,
                ],
                [
                    99, 183, 228, 207, 41, 53, 29, 170, 195, 119, 1, 1, 230, 67, 84, 88, 166, 83,
                    110, 232,
                ],
                [
                    94, 253, 71, 217, 180, 8, 207, 67, 109, 248, 149, 196, 120, 13, 169, 27, 169,
                    88, 53, 202,
                ],
                [
                    1, 109, 28, 218, 244, 69, 57, 231, 54, 76, 164, 43, 215, 103, 1, 178, 181, 181,
                    228, 153,
                ],
                [
                    130, 95, 162, 67, 152, 201, 119, 14, 23, 102, 132, 6, 20, 100, 63, 82, 70, 234,
                    140, 171,
                ],
                [
                    251, 7, 160, 74, 10, 35, 248, 53, 12, 50, 18, 5, 95, 89, 118, 185, 253, 97, 74,
                    86,
                ],
                [
                    19, 41, 2, 182, 219, 167, 72, 54, 69, 128, 28, 108, 253, 71, 144, 18, 92, 247,
                    52, 124,
                ],
                [
                    140, 139, 61, 168, 12, 37, 69, 182, 164, 101, 131, 161, 92, 103, 82, 230, 18,
                    64, 172, 15,
                ],
                [
                    220, 90, 113, 13, 182, 186, 25, 233, 229, 31, 106, 53, 8, 248, 154, 207, 7,
                    241, 151, 45,
                ],
                [
                    9, 33, 170, 238, 51, 70, 36, 34, 213, 31, 130, 204, 178, 80, 18, 21, 74, 236,
                    103, 230,
                ],
                [
                    194, 108, 99, 78, 10, 19, 61, 207, 251, 118, 61, 122, 220, 127, 252, 80, 172,
                    8, 105, 143,
                ],
                [
                    79, 35, 248, 41, 56, 124, 41, 227, 32, 254, 255, 13, 208, 196, 114, 202, 120,
                    164, 4, 2,
                ],
                [
                    101, 253, 79, 200, 193, 227, 195, 172, 155, 187, 155, 56, 127, 207, 146, 148,
                    192, 21, 161, 104,
                ],
                [
                    36, 229, 111, 131, 207, 67, 39, 200, 178, 163, 223, 100, 45, 35, 48, 67, 44,
                    97, 59, 142,
                ],
                [
                    32, 206, 225, 15, 239, 200, 45, 254, 183, 204, 79, 215, 125, 183, 36, 95, 6,
                    92, 38, 255,
                ],
                [
                    89, 57, 45, 54, 150, 13, 29, 94, 137, 226, 85, 126, 82, 112, 40, 244, 149, 29,
                    118, 136,
                ],
                [
                    120, 33, 170, 53, 8, 136, 11, 29, 217, 212, 24, 46, 214, 233, 227, 198, 85, 77,
                    13, 42,
                ],
                [
                    128, 108, 16, 98, 229, 27, 241, 248, 127, 48, 112, 244, 147, 118, 169, 231, 20,
                    120, 149, 46,
                ],
                [
                    162, 36, 43, 207, 223, 231, 241, 66, 102, 40, 72, 71, 11, 247, 178, 141, 238,
                    109, 113, 253,
                ],
                [
                    86, 169, 195, 159, 75, 98, 69, 66, 40, 219, 140, 138, 45, 214, 117, 37, 93, 43,
                    201, 138,
                ],
                [
                    212, 207, 77, 229, 120, 63, 80, 103, 110, 95, 72, 220, 158, 229, 249, 0, 228,
                    151, 98, 87,
                ],
                [
                    136, 231, 135, 102, 160, 122, 93, 225, 255, 167, 253, 87, 163, 77, 188, 253,
                    223, 227, 102, 58,
                ],
                [
                    174, 222, 136, 142, 155, 38, 151, 115, 156, 221, 36, 30, 64, 69, 28, 98, 33,
                    46, 193, 84,
                ],
                [
                    142, 240, 102, 46, 48, 62, 20, 182, 222, 173, 138, 111, 198, 129, 72, 187, 66,
                    142, 154, 7,
                ],
                [
                    23, 145, 74, 201, 44, 121, 239, 204, 176, 57, 192, 194, 145, 172, 31, 89, 50,
                    13, 239, 43,
                ],
                [
                    199, 217, 94, 129, 216, 196, 92, 41, 40, 202, 212, 178, 186, 200, 174, 165,
                    248, 182, 60, 124,
                ],
                [
                    100, 87, 201, 223, 79, 86, 247, 248, 39, 245, 173, 93, 49, 107, 217, 181, 155,
                    121, 204, 66,
                ],
                [
                    252, 159, 26, 49, 229, 254, 114, 95, 31, 3, 135, 134, 254, 78, 122, 16, 151,
                    235, 73, 252,
                ],
                [
                    181, 67, 179, 64, 85, 200, 33, 95, 196, 122, 173, 186, 228, 156, 65, 115, 31,
                    98, 114, 12,
                ],
                [
                    218, 207, 169, 142, 43, 204, 7, 235, 60, 238, 202, 28, 172, 137, 249, 195, 120,
                    60, 50, 165,
                ],
                [
                    155, 195, 3, 80, 70, 133, 53, 206, 243, 173, 80, 208, 21, 10, 168, 59, 29, 34,
                    15, 24,
                ],
                [
                    89, 251, 162, 79, 164, 82, 111, 130, 148, 133, 218, 7, 36, 172, 93, 151, 68,
                    58, 185, 169,
                ],
                [
                    150, 104, 230, 250, 31, 37, 38, 235, 143, 244, 81, 56, 25, 250, 129, 121, 171,
                    224, 204, 179,
                ],
                [
                    111, 19, 21, 208, 180, 213, 65, 41, 215, 50, 91, 28, 127, 115, 83, 68, 207,
                    113, 213, 11,
                ],
                [
                    181, 11, 247, 66, 223, 178, 19, 65, 45, 141, 235, 10, 245, 198, 18, 231, 7,
                    136, 225, 219,
                ],
                [
                    32, 123, 43, 203, 136, 150, 158, 43, 123, 102, 224, 15, 130, 129, 120, 241, 84,
                    170, 143, 234,
                ],
                [
                    229, 255, 214, 58, 215, 84, 129, 64, 218, 78, 115, 6, 150, 99, 231, 120, 102,
                    132, 90, 183,
                ],
                [
                    21, 21, 64, 161, 176, 180, 135, 204, 246, 228, 107, 88, 5, 77, 197, 46, 232,
                    211, 250, 60,
                ],
                [
                    101, 242, 191, 132, 56, 38, 132, 101, 223, 201, 185, 88, 34, 247, 78, 132, 253,
                    54, 252, 191,
                ],
                [
                    234, 16, 221, 38, 223, 178, 231, 109, 106, 26, 169, 53, 16, 59, 77, 116, 129,
                    8, 34, 182,
                ],
                [
                    214, 247, 216, 161, 249, 211, 27, 149, 182, 112, 221, 96, 155, 140, 172, 47,
                    133, 192, 81, 109,
                ],
                [
                    179, 108, 39, 196, 126, 2, 189, 60, 101, 230, 140, 58, 162, 149, 57, 187, 59,
                    137, 152, 222,
                ],
                [
                    10, 40, 154, 133, 18, 33, 154, 130, 42, 79, 111, 1, 13, 141, 198, 250, 185,
                    210, 247, 144,
                ],
                [
                    147, 112, 58, 90, 145, 103, 205, 106, 192, 96, 250, 31, 52, 157, 72, 213, 5,
                    156, 222, 20,
                ],
                [
                    77, 179, 121, 196, 169, 217, 40, 172, 7, 192, 2, 168, 234, 217, 4, 230, 102,
                    118, 33, 160,
                ],
                [
                    197, 76, 225, 121, 20, 116, 89, 195, 250, 232, 46, 183, 80, 207, 35, 153, 173,
                    206, 50, 208,
                ],
                [
                    236, 224, 63, 120, 177, 191, 96, 252, 93, 13, 23, 231, 72, 189, 112, 150, 7,
                    152, 135, 19,
                ],
                [
                    167, 44, 224, 96, 35, 250, 26, 189, 84, 198, 161, 188, 126, 35, 35, 171, 196,
                    250, 24, 51,
                ],
                [
                    157, 24, 71, 138, 144, 106, 145, 215, 98, 97, 70, 11, 102, 248, 152, 130, 230,
                    11, 236, 55,
                ],
                [
                    49, 162, 205, 68, 127, 190, 55, 235, 124, 71, 40, 233, 121, 19, 71, 153, 27,
                    152, 138, 64,
                ],
                [
                    50, 166, 226, 38, 183, 245, 82, 29, 27, 202, 177, 193, 91, 248, 52, 100, 133,
                    215, 179, 36,
                ],
                [
                    166, 196, 254, 115, 63, 83, 44, 56, 27, 84, 228, 115, 176, 48, 47, 121, 206,
                    159, 219, 169,
                ],
                [
                    134, 168, 201, 87, 249, 120, 103, 217, 64, 171, 149, 183, 180, 44, 9, 75, 242,
                    10, 127, 119,
                ],
                [
                    25, 73, 39, 239, 120, 189, 152, 141, 174, 90, 117, 117, 192, 35, 107, 112, 100,
                    119, 195, 129,
                ],
                [
                    252, 236, 121, 241, 91, 198, 165, 239, 91, 160, 166, 203, 192, 238, 11, 205,
                    61, 194, 199, 230,
                ],
                [
                    70, 44, 123, 81, 215, 116, 221, 237, 52, 201, 148, 249, 211, 13, 77, 148, 17,
                    184, 86, 215,
                ],
                [
                    109, 148, 235, 158, 56, 81, 91, 84, 156, 173, 73, 11, 65, 249, 249, 97, 121,
                    220, 89, 40,
                ],
                [
                    88, 20, 4, 32, 234, 69, 66, 190, 16, 111, 92, 234, 238, 43, 144, 214, 215, 37,
                    202, 233,
                ],
                [
                    37, 201, 175, 12, 193, 38, 141, 15, 77, 131, 53, 238, 42, 195, 223, 8, 236, 87,
                    30, 2,
                ],
                [
                    140, 107, 226, 226, 73, 97, 156, 189, 147, 106, 103, 223, 38, 89, 183, 29, 49,
                    135, 135, 90,
                ],
                [
                    174, 230, 167, 136, 156, 238, 78, 184, 101, 7, 101, 64, 105, 192, 8, 23, 55,
                    223, 250, 246,
                ],
                [
                    74, 227, 28, 145, 141, 158, 57, 208, 125, 127, 198, 46, 217, 3, 135, 198, 215,
                    44, 134, 152,
                ],
                [
                    169, 241, 178, 138, 192, 162, 39, 38, 88, 235, 6, 251, 234, 210, 92, 55, 171,
                    197, 158, 139,
                ],
                [
                    242, 61, 232, 35, 243, 73, 203, 245, 229, 224, 46, 171, 138, 254, 29, 129, 129,
                    174, 141, 58,
                ],
                [
                    21, 178, 78, 19, 120, 116, 65, 188, 94, 23, 1, 212, 84, 19, 183, 99, 251, 107,
                    159, 148,
                ],
                [
                    208, 39, 225, 131, 7, 231, 155, 239, 186, 91, 50, 108, 173, 222, 211, 196, 205,
                    81, 80, 56,
                ],
                [
                    29, 226, 49, 0, 201, 210, 34, 214, 156, 86, 18, 174, 231, 215, 172, 8, 237, 23,
                    227, 29,
                ],
                [
                    4, 113, 58, 245, 88, 66, 218, 149, 29, 42, 197, 122, 219, 134, 113, 226, 226,
                    170, 228, 4,
                ],
                [
                    185, 22, 92, 127, 54, 137, 96, 0, 42, 49, 6, 137, 33, 242, 18, 87, 76, 32, 132,
                    85,
                ],
                [
                    79, 27, 74, 33, 250, 87, 37, 46, 226, 45, 173, 188, 191, 50, 235, 105, 208,
                    145, 103, 242,
                ],
                [
                    85, 90, 49, 57, 9, 197, 207, 103, 117, 13, 108, 197, 88, 174, 185, 14, 182, 68,
                    95, 158,
                ],
                [
                    173, 176, 72, 104, 224, 199, 247, 196, 112, 53, 47, 203, 225, 44, 24, 141, 228,
                    131, 63, 197,
                ],
                [
                    24, 37, 219, 63, 220, 219, 20, 96, 204, 132, 136, 35, 184, 228, 214, 188, 200,
                    237, 98, 203,
                ],
                [
                    106, 140, 171, 171, 218, 31, 219, 61, 37, 13, 185, 87, 162, 27, 16, 70, 119,
                    231, 134, 196,
                ],
                [
                    144, 34, 177, 204, 187, 110, 148, 215, 153, 86, 216, 181, 84, 130, 162, 145,
                    140, 114, 221, 83,
                ],
                [
                    34, 174, 122, 41, 93, 65, 154, 224, 196, 30, 85, 203, 254, 192, 244, 21, 206,
                    208, 70, 174,
                ],
                [
                    103, 204, 201, 132, 83, 146, 137, 73, 16, 55, 153, 112, 166, 248, 230, 134,
                    154, 214, 151, 185,
                ],
                [
                    160, 38, 37, 22, 73, 105, 127, 210, 224, 174, 6, 151, 151, 186, 61, 76, 113,
                    62, 126, 168,
                ],
                [
                    45, 164, 116, 84, 30, 108, 120, 56, 145, 158, 37, 119, 135, 214, 94, 231, 162,
                    109, 29, 174,
                ],
                [
                    5, 130, 61, 57, 158, 99, 22, 88, 62, 208, 253, 0, 101, 227, 88, 194, 11, 221,
                    251, 75,
                ],
                [
                    64, 133, 79, 202, 144, 157, 236, 15, 54, 191, 101, 110, 251, 70, 47, 242, 234,
                    129, 144, 26,
                ],
                [
                    98, 68, 199, 193, 116, 32, 158, 110, 139, 248, 201, 106, 33, 218, 234, 44, 37,
                    251, 91, 109,
                ],
                [
                    37, 237, 209, 7, 129, 194, 233, 239, 160, 26, 247, 37, 86, 95, 247, 3, 41, 56,
                    85, 237,
                ],
                [
                    16, 19, 3, 95, 37, 21, 79, 5, 118, 91, 116, 205, 51, 28, 230, 214, 172, 133,
                    73, 40,
                ],
                [
                    144, 105, 10, 22, 146, 44, 97, 137, 220, 189, 191, 161, 216, 82, 126, 82, 12,
                    81, 251, 171,
                ],
                [
                    112, 75, 141, 242, 31, 73, 233, 232, 164, 142, 15, 96, 119, 31, 32, 135, 65,
                    76, 105, 225,
                ],
                [
                    100, 61, 65, 215, 28, 253, 107, 116, 68, 113, 226, 135, 9, 149, 250, 92, 180,
                    61, 143, 176,
                ],
                [
                    65, 240, 192, 94, 225, 114, 159, 197, 217, 187, 234, 15, 167, 124, 202, 199,
                    42, 68, 217, 119,
                ],
                [
                    64, 91, 95, 106, 200, 255, 162, 63, 135, 206, 239, 224, 16, 35, 43, 197, 239,
                    104, 115, 175,
                ],
                [
                    72, 47, 7, 200, 183, 197, 236, 20, 164, 151, 244, 131, 167, 187, 86, 184, 62,
                    122, 54, 18,
                ],
                [
                    208, 62, 23, 247, 134, 116, 148, 75, 51, 171, 80, 132, 75, 41, 42, 55, 119,
                    156, 169, 221,
                ],
                [
                    189, 61, 156, 6, 246, 16, 255, 228, 221, 39, 211, 187, 251, 175, 6, 177, 50,
                    173, 55, 29,
                ],
                [
                    121, 112, 237, 115, 138, 191, 148, 111, 92, 242, 103, 187, 36, 24, 135, 211,
                    248, 98, 183, 225,
                ],
                [
                    156, 226, 144, 114, 53, 43, 193, 98, 249, 1, 234, 184, 252, 116, 88, 143, 89,
                    123, 220, 226,
                ],
                [
                    192, 245, 91, 16, 5, 16, 231, 131, 101, 75, 224, 156, 14, 233, 0, 42, 76, 210,
                    72, 53,
                ],
                [
                    238, 148, 119, 163, 80, 72, 38, 62, 239, 49, 242, 191, 178, 233, 17, 230, 129,
                    34, 146, 32,
                ],
                [
                    148, 90, 214, 0, 149, 149, 228, 63, 146, 255, 21, 138, 103, 93, 134, 150, 247,
                    236, 24, 170,
                ],
                [
                    34, 200, 46, 152, 169, 118, 33, 139, 253, 4, 35, 81, 94, 128, 204, 81, 206,
                    225, 6, 124,
                ],
                [
                    250, 108, 179, 20, 87, 229, 31, 175, 191, 95, 45, 122, 138, 142, 42, 172, 80,
                    133, 102, 4,
                ],
                [
                    177, 95, 245, 193, 39, 222, 232, 210, 207, 103, 122, 137, 66, 125, 84, 62, 23,
                    197, 100, 42,
                ],
                [
                    199, 199, 185, 252, 149, 232, 160, 16, 125, 246, 4, 237, 40, 181, 45, 206, 184,
                    97, 95, 55,
                ],
                [
                    171, 213, 235, 216, 162, 253, 228, 83, 22, 40, 106, 52, 72, 14, 115, 98, 170,
                    48, 187, 191,
                ],
                [
                    73, 175, 177, 58, 117, 190, 58, 216, 135, 211, 43, 53, 204, 109, 213, 217, 131,
                    193, 130, 103,
                ],
                [
                    157, 233, 219, 70, 104, 34, 35, 182, 42, 2, 171, 255, 234, 192, 155, 5, 50, 78,
                    214, 65,
                ],
                [
                    73, 137, 189, 41, 217, 91, 212, 73, 104, 173, 240, 12, 132, 9, 171, 18, 144,
                    111, 76, 90,
                ],
                [
                    105, 218, 90, 13, 119, 118, 97, 174, 138, 183, 103, 231, 43, 212, 15, 72, 22,
                    158, 44, 3,
                ],
                [
                    38, 108, 243, 6, 193, 198, 229, 219, 155, 18, 221, 195, 213, 146, 241, 216,
                    124, 217, 235, 175,
                ],
                [
                    176, 209, 42, 182, 170, 49, 89, 194, 37, 151, 112, 240, 135, 130, 158, 133, 89,
                    100, 63, 186,
                ],
                [
                    206, 172, 2, 17, 104, 126, 171, 170, 5, 219, 45, 150, 70, 125, 244, 17, 90,
                    182, 252, 92,
                ],
                [
                    230, 178, 84, 14, 111, 23, 40, 64, 116, 155, 186, 89, 124, 227, 47, 120, 134,
                    241, 2, 162,
                ],
                [
                    204, 72, 170, 7, 17, 182, 131, 189, 54, 229, 45, 51, 136, 142, 105, 95, 226,
                    227, 171, 50,
                ],
                [
                    252, 36, 153, 6, 229, 55, 133, 23, 114, 147, 51, 97, 182, 237, 158, 233, 127,
                    30, 111, 26,
                ],
                [
                    240, 219, 185, 48, 239, 134, 164, 216, 67, 6, 87, 10, 63, 226, 150, 93, 90,
                    187, 29, 21,
                ],
                [
                    135, 41, 241, 245, 192, 102, 193, 215, 64, 72, 58, 39, 221, 190, 147, 18, 251,
                    14, 36, 242,
                ],
                [
                    185, 135, 227, 198, 115, 69, 122, 249, 141, 193, 202, 247, 14, 5, 164, 66, 191,
                    149, 41, 231,
                ],
                [
                    46, 209, 107, 115, 212, 92, 218, 242, 212, 101, 224, 26, 200, 178, 85, 248,
                    205, 79, 180, 185,
                ],
                [
                    51, 169, 142, 166, 199, 174, 5, 61, 204, 90, 42, 17, 48, 250, 37, 230, 118,
                    170, 138, 251,
                ],
                [
                    21, 4, 138, 214, 218, 192, 161, 211, 125, 66, 116, 50, 171, 156, 42, 138, 25,
                    81, 210, 27,
                ],
                [
                    80, 239, 128, 9, 124, 13, 200, 221, 48, 37, 94, 111, 139, 19, 24, 93, 51, 30,
                    150, 151,
                ],
                [
                    151, 7, 100, 230, 123, 171, 250, 190, 33, 132, 144, 116, 81, 104, 185, 69, 33,
                    129, 132, 71,
                ],
                [
                    148, 16, 24, 119, 120, 31, 220, 101, 247, 83, 66, 0, 128, 55, 251, 255, 34,
                    112, 225, 141,
                ],
                [
                    192, 233, 227, 143, 151, 250, 141, 254, 228, 212, 20, 2, 2, 70, 117, 148, 140,
                    39, 134, 34,
                ],
                [
                    58, 229, 237, 174, 133, 105, 61, 93, 146, 175, 216, 63, 251, 95, 70, 88, 177,
                    226, 72, 235,
                ],
                [
                    22, 229, 248, 98, 1, 99, 178, 62, 198, 100, 17, 44, 146, 46, 96, 117, 212, 34,
                    170, 236,
                ],
                [
                    1, 145, 113, 254, 232, 28, 151, 122, 43, 135, 219, 10, 80, 251, 222, 120, 249,
                    180, 63, 9,
                ],
                [
                    0, 185, 7, 117, 77, 69, 243, 64, 60, 223, 57, 47, 213, 231, 155, 1, 29, 184, 0,
                    168,
                ],
                [
                    181, 113, 17, 65, 90, 102, 182, 154, 26, 1, 95, 159, 114, 55, 216, 7, 101, 37,
                    36, 180,
                ],
                [
                    67, 227, 74, 226, 196, 231, 48, 81, 126, 60, 170, 23, 235, 147, 5, 34, 67, 58,
                    2, 251,
                ],
                [
                    93, 70, 237, 19, 215, 246, 173, 117, 135, 145, 91, 181, 156, 133, 216, 155, 15,
                    79, 134, 242,
                ],
                [
                    143, 186, 108, 111, 212, 53, 183, 160, 76, 141, 133, 224, 91, 175, 243, 98,
                    187, 88, 173, 128,
                ],
                [
                    148, 21, 204, 111, 61, 87, 155, 186, 65, 105, 217, 1, 188, 76, 134, 201, 148,
                    242, 143, 7,
                ],
                [
                    150, 93, 56, 52, 178, 168, 28, 228, 169, 111, 3, 28, 220, 141, 160, 176, 39,
                    154, 116, 215,
                ],
                [
                    223, 106, 14, 181, 238, 209, 238, 244, 118, 130, 43, 77, 103, 121, 2, 1, 178,
                    0, 219, 88,
                ],
                [
                    6, 226, 244, 108, 50, 134, 249, 50, 101, 249, 168, 240, 190, 153, 229, 152,
                    154, 189, 234, 164,
                ],
                [
                    184, 169, 115, 177, 172, 28, 193, 113, 147, 100, 235, 36, 164, 112, 235, 97,
                    102, 16, 80, 51,
                ],
                [
                    200, 83, 245, 31, 178, 177, 152, 158, 196, 239, 47, 157, 154, 6, 130, 45, 192,
                    209, 169, 174,
                ],
                [
                    52, 137, 153, 213, 42, 78, 175, 153, 79, 175, 142, 137, 208, 14, 125, 181, 189,
                    212, 26, 233,
                ],
                [
                    76, 35, 226, 136, 26, 85, 34, 66, 76, 118, 161, 13, 23, 136, 238, 137, 201,
                    246, 122, 156,
                ],
                [
                    84, 157, 189, 139, 187, 126, 46, 64, 146, 56, 227, 157, 77, 158, 121, 242, 165,
                    45, 251, 190,
                ],
                [
                    96, 143, 181, 238, 74, 175, 218, 181, 19, 92, 170, 120, 27, 172, 89, 64, 117,
                    209, 155, 117,
                ],
                [
                    13, 152, 39, 89, 134, 6, 182, 1, 139, 14, 13, 5, 254, 110, 52, 249, 254, 164,
                    191, 45,
                ],
                [
                    230, 98, 108, 134, 196, 228, 178, 136, 93, 119, 181, 214, 165, 50, 232, 25, 63,
                    190, 247, 53,
                ],
                [
                    76, 97, 2, 93, 83, 26, 205, 115, 215, 223, 118, 71, 136, 29, 189, 147, 36, 21,
                    37, 77,
                ],
                [
                    224, 223, 107, 41, 142, 92, 254, 25, 154, 212, 224, 43, 164, 59, 192, 19, 4,
                    70, 176, 64,
                ],
                [
                    232, 181, 86, 215, 197, 45, 221, 211, 126, 184, 166, 178, 154, 185, 90, 156,
                    30, 250, 138, 17,
                ],
                [
                    233, 26, 4, 224, 44, 106, 89, 126, 198, 232, 20, 245, 43, 163, 12, 126, 21,
                    168, 6, 130,
                ],
                [
                    38, 123, 216, 228, 115, 124, 135, 125, 101, 68, 119, 225, 237, 162, 195, 102,
                    207, 77, 17, 10,
                ],
                [
                    239, 80, 245, 221, 144, 61, 9, 104, 34, 72, 125, 142, 204, 178, 65, 190, 156,
                    156, 189, 45,
                ],
                [
                    138, 222, 173, 46, 149, 38, 20, 205, 85, 28, 171, 206, 19, 134, 165, 31, 184,
                    84, 187, 36,
                ],
                [
                    90, 42, 99, 219, 115, 11, 46, 251, 208, 111, 31, 175, 108, 69, 126, 220, 162,
                    233, 244, 51,
                ],
                [
                    129, 192, 205, 33, 198, 125, 199, 187, 94, 151, 228, 235, 50, 144, 20, 140,
                    156, 133, 211, 49,
                ],
                [
                    37, 213, 19, 174, 117, 129, 9, 146, 87, 223, 133, 126, 52, 163, 39, 77, 223, 3,
                    85, 11,
                ],
                [
                    225, 66, 97, 246, 130, 20, 161, 119, 225, 229, 99, 235, 51, 23, 80, 253, 38,
                    249, 177, 90,
                ],
                [
                    224, 49, 90, 82, 38, 49, 92, 192, 91, 215, 77, 108, 57, 166, 181, 194, 12, 223,
                    212, 213,
                ],
                [
                    235, 205, 220, 105, 126, 101, 96, 111, 40, 59, 171, 84, 73, 182, 143, 25, 176,
                    187, 19, 83,
                ],
                [
                    18, 178, 209, 128, 58, 134, 167, 140, 106, 3, 43, 40, 152, 88, 112, 81, 166,
                    252, 151, 159,
                ],
                [
                    114, 201, 84, 103, 153, 172, 239, 158, 103, 145, 63, 201, 189, 139, 190, 139,
                    44, 115, 132, 13,
                ],
                [
                    195, 25, 200, 251, 196, 26, 163, 192, 250, 37, 146, 10, 111, 243, 137, 17, 209,
                    102, 15, 233,
                ],
                [
                    109, 169, 253, 134, 34, 210, 164, 253, 181, 38, 229, 66, 157, 38, 29, 21, 77,
                    11, 54, 9,
                ],
                [
                    247, 187, 220, 13, 198, 164, 38, 252, 150, 57, 163, 19, 97, 82, 62, 193, 73,
                    246, 253, 154,
                ],
                [
                    191, 16, 121, 44, 167, 59, 57, 244, 119, 204, 186, 13, 72, 99, 56, 174, 207, 1,
                    126, 201,
                ],
                [
                    252, 194, 99, 172, 202, 8, 170, 94, 122, 224, 83, 103, 128, 93, 196, 253, 106,
                    34, 222, 51,
                ],
                [
                    21, 53, 124, 177, 27, 157, 176, 255, 11, 97, 195, 83, 50, 133, 220, 153, 38,
                    204, 63, 1,
                ],
                [
                    121, 181, 165, 241, 130, 84, 159, 56, 250, 95, 170, 75, 76, 168, 119, 214, 19,
                    33, 107, 35,
                ],
                [
                    92, 181, 59, 161, 250, 183, 211, 248, 237, 253, 210, 29, 115, 235, 214, 43, 28,
                    24, 223, 96,
                ],
                [
                    170, 141, 119, 179, 113, 26, 115, 176, 152, 218, 54, 5, 209, 228, 212, 79, 229,
                    93, 61, 200,
                ],
                [
                    15, 72, 108, 22, 127, 22, 101, 112, 122, 61, 212, 179, 64, 2, 72, 185, 0, 130,
                    198, 214,
                ],
                [
                    153, 19, 114, 82, 176, 115, 214, 160, 250, 236, 166, 57, 224, 132, 61, 128, 51,
                    100, 46, 68,
                ],
                [
                    171, 66, 109, 167, 99, 238, 97, 132, 178, 70, 109, 197, 134, 83, 25, 157, 158,
                    183, 140, 151,
                ],
                [
                    25, 28, 95, 36, 83, 167, 81, 4, 199, 80, 121, 201, 113, 181, 138, 161, 108,
                    221, 40, 17,
                ],
                [
                    54, 200, 102, 66, 243, 110, 216, 27, 202, 215, 125, 89, 218, 136, 226, 119, 69,
                    207, 119, 160,
                ],
                [
                    60, 211, 17, 117, 115, 16, 210, 20, 153, 23, 104, 198, 234, 168, 4, 146, 75,
                    22, 136, 180,
                ],
                [
                    32, 30, 201, 251, 171, 231, 228, 71, 97, 193, 249, 91, 233, 236, 201, 129, 201,
                    78, 59, 118,
                ],
                [
                    203, 216, 23, 19, 10, 121, 252, 209, 184, 8, 38, 19, 28, 17, 166, 18, 215, 30,
                    35, 192,
                ],
                [
                    248, 28, 194, 227, 140, 130, 204, 124, 89, 26, 118, 196, 207, 232, 200, 27, 64,
                    50, 248, 209,
                ],
                [
                    127, 39, 85, 244, 124, 11, 194, 211, 208, 160, 76, 169, 118, 0, 28, 123, 34,
                    83, 249, 116,
                ],
                [
                    224, 23, 85, 57, 130, 67, 112, 81, 166, 239, 151, 170, 173, 65, 37, 98, 59, 44,
                    35, 164,
                ],
                [
                    255, 125, 185, 240, 70, 216, 108, 64, 101, 222, 220, 158, 150, 196, 215, 196,
                    60, 16, 148, 196,
                ],
                [
                    120, 100, 219, 181, 237, 39, 0, 84, 206, 123, 235, 30, 249, 98, 52, 91, 167,
                    171, 185, 63,
                ],
                [
                    35, 35, 55, 79, 26, 162, 36, 235, 109, 136, 43, 163, 5, 223, 18, 19, 245, 49,
                    51, 157,
                ],
                [
                    188, 120, 64, 134, 30, 243, 90, 168, 84, 152, 88, 109, 168, 38, 2, 213, 93,
                    159, 55, 202,
                ],
                [
                    233, 43, 176, 248, 43, 81, 67, 163, 147, 78, 8, 51, 216, 32, 108, 117, 29, 146,
                    62, 31,
                ],
                [
                    135, 171, 193, 55, 243, 235, 134, 43, 247, 59, 234, 207, 162, 194, 139, 180,
                    19, 49, 123, 216,
                ],
                [
                    167, 66, 104, 221, 190, 190, 140, 239, 129, 235, 136, 130, 21, 64, 16, 233,
                    210, 109, 153, 124,
                ],
                [
                    163, 152, 153, 239, 143, 52, 113, 36, 141, 120, 167, 176, 102, 0, 216, 196,
                    116, 120, 151, 225,
                ],
                [
                    141, 103, 197, 20, 188, 171, 189, 16, 206, 128, 153, 230, 144, 92, 187, 55,
                    192, 255, 192, 214,
                ],
                [
                    137, 209, 218, 139, 94, 212, 176, 201, 128, 221, 135, 216, 32, 180, 58, 187,
                    176, 73, 180, 20,
                ],
                [
                    203, 217, 73, 192, 139, 118, 160, 40, 107, 84, 91, 193, 104, 92, 253, 8, 94,
                    96, 6, 240,
                ],
                [
                    59, 223, 136, 137, 52, 234, 193, 50, 195, 136, 206, 23, 63, 150, 19, 193, 230,
                    139, 26, 184,
                ],
                [
                    139, 121, 24, 228, 203, 210, 35, 157, 218, 110, 221, 121, 240, 252, 149, 210,
                    107, 188, 98, 118,
                ],
                [
                    254, 95, 232, 186, 154, 78, 32, 137, 52, 45, 163, 159, 52, 56, 233, 9, 28, 230,
                    106, 137,
                ],
                [
                    226, 0, 18, 129, 100, 49, 72, 78, 116, 54, 9, 150, 230, 212, 118, 1, 149, 225,
                    235, 146,
                ],
                [
                    9, 176, 75, 162, 117, 107, 182, 224, 72, 249, 123, 173, 29, 3, 66, 120, 24, 24,
                    144, 103,
                ],
                [
                    150, 37, 188, 247, 209, 34, 91, 40, 166, 8, 27, 68, 194, 25, 153, 193, 253, 41,
                    4, 236,
                ],
                [
                    149, 87, 28, 219, 49, 45, 144, 254, 2, 180, 233, 247, 52, 234, 90, 54, 115, 89,
                    194, 127,
                ],
                [
                    201, 216, 230, 218, 7, 199, 9, 192, 191, 219, 29, 238, 123, 53, 35, 188, 175,
                    179, 84, 119,
                ],
                [
                    98, 33, 17, 39, 29, 198, 223, 41, 241, 99, 37, 81, 14, 19, 176, 0, 17, 37, 0,
                    230,
                ],
                [
                    30, 255, 147, 249, 111, 220, 114, 206, 161, 181, 221, 100, 70, 200, 67, 57,
                    140, 35, 187, 137,
                ],
                [
                    85, 174, 177, 196, 110, 200, 160, 73, 232, 112, 133, 232, 133, 18, 57, 85, 11,
                    139, 88, 57,
                ],
                [
                    39, 19, 220, 37, 27, 234, 81, 76, 22, 65, 253, 143, 60, 107, 43, 140, 7, 197,
                    56, 199,
                ],
                [
                    176, 216, 77, 184, 97, 79, 169, 101, 23, 138, 204, 117, 85, 103, 5, 168, 224,
                    239, 136, 116,
                ],
                [
                    68, 76, 87, 152, 149, 65, 237, 211, 122, 1, 52, 104, 134, 38, 213, 221, 9, 208,
                    160, 116,
                ],
                [
                    234, 80, 54, 21, 240, 102, 255, 12, 207, 187, 126, 4, 165, 193, 242, 255, 193,
                    177, 40, 35,
                ],
                [
                    132, 239, 46, 192, 69, 13, 202, 113, 252, 43, 172, 170, 179, 58, 197, 184, 173,
                    221, 243, 107,
                ],
                [
                    247, 179, 107, 217, 49, 157, 17, 161, 179, 40, 155, 118, 250, 253, 235, 80,
                    228, 180, 183, 92,
                ],
                [
                    150, 201, 217, 18, 164, 238, 139, 87, 15, 106, 211, 238, 188, 85, 52, 73, 252,
                    145, 200, 255,
                ],
                [
                    110, 64, 94, 200, 193, 4, 7, 183, 235, 213, 233, 138, 254, 193, 143, 110, 250,
                    6, 140, 132,
                ],
                [
                    59, 116, 55, 93, 249, 247, 236, 235, 51, 228, 144, 107, 9, 128, 151, 119, 233,
                    195, 225, 177,
                ],
                [
                    130, 218, 85, 115, 212, 14, 67, 101, 122, 57, 134, 206, 206, 99, 166, 165, 8,
                    102, 13, 80,
                ],
                [
                    145, 43, 137, 172, 128, 156, 44, 175, 201, 169, 145, 172, 242, 204, 194, 237,
                    101, 134, 135, 48,
                ],
                [
                    78, 198, 154, 53, 62, 144, 8, 91, 207, 161, 157, 63, 141, 172, 175, 85, 187,
                    112, 238, 153,
                ],
                [
                    192, 2, 253, 152, 11, 31, 166, 170, 189, 18, 136, 184, 187, 22, 163, 48, 62,
                    78, 212, 224,
                ],
                [
                    222, 85, 175, 169, 28, 201, 209, 22, 235, 22, 186, 7, 165, 245, 93, 53, 165,
                    79, 195, 166,
                ],
                [
                    237, 109, 88, 215, 2, 106, 20, 208, 165, 102, 201, 25, 84, 186, 184, 73, 37,
                    48, 110, 130,
                ],
                [
                    180, 112, 123, 26, 11, 47, 241, 182, 97, 212, 150, 52, 18, 238, 202, 245, 22,
                    93, 68, 234,
                ],
                [
                    222, 149, 93, 27, 125, 57, 51, 121, 246, 165, 67, 179, 98, 174, 85, 112, 34,
                    218, 58, 144,
                ],
                [
                    168, 54, 160, 241, 22, 67, 151, 106, 57, 239, 72, 32, 76, 184, 140, 90, 51, 40,
                    42, 118,
                ],
                [
                    178, 223, 254, 204, 49, 218, 80, 248, 102, 218, 11, 63, 51, 16, 239, 21, 154,
                    221, 221, 68,
                ],
                [
                    0, 80, 197, 189, 115, 33, 191, 191, 138, 139, 81, 201, 6, 206, 48, 201, 7, 237,
                    183, 33,
                ],
                [
                    232, 141, 7, 170, 230, 227, 166, 214, 71, 45, 106, 17, 12, 34, 18, 162, 139,
                    39, 176, 108,
                ],
                [
                    173, 143, 60, 164, 90, 137, 75, 17, 124, 242, 125, 44, 92, 198, 230, 25, 205,
                    178, 246, 114,
                ],
                [
                    211, 57, 172, 200, 170, 36, 96, 117, 103, 217, 65, 61, 51, 85, 223, 185, 188,
                    49, 212, 227,
                ],
                [
                    221, 231, 177, 83, 124, 70, 246, 217, 47, 253, 121, 109, 184, 148, 152, 43,
                    169, 116, 136, 94,
                ],
                [
                    53, 155, 147, 193, 178, 253, 60, 179, 113, 102, 254, 169, 84, 130, 247, 12, 21,
                    142, 124, 82,
                ],
                [
                    123, 21, 51, 218, 233, 181, 209, 181, 3, 72, 104, 160, 126, 216, 19, 250, 150,
                    69, 201, 17,
                ],
                [
                    77, 221, 69, 167, 185, 107, 245, 15, 219, 73, 104, 88, 205, 246, 224, 100, 39,
                    220, 252, 243,
                ],
                [
                    162, 230, 60, 140, 104, 54, 113, 211, 199, 131, 128, 133, 120, 222, 42, 78,
                    193, 97, 144, 80,
                ],
                [
                    13, 57, 26, 43, 28, 226, 157, 149, 177, 69, 214, 62, 12, 247, 20, 49, 48, 25,
                    233, 210,
                ],
                [
                    204, 98, 176, 168, 170, 193, 139, 39, 231, 167, 154, 231, 202, 193, 193, 158,
                    57, 51, 248, 198,
                ],
                [
                    155, 190, 198, 164, 218, 125, 184, 62, 163, 81, 219, 89, 101, 122, 82, 59, 121,
                    89, 57, 194,
                ],
                [
                    98, 230, 62, 238, 8, 6, 247, 111, 30, 138, 116, 68, 22, 223, 245, 124, 141,
                    174, 254, 199,
                ],
                [
                    4, 73, 208, 175, 233, 170, 239, 226, 152, 33, 18, 13, 145, 144, 238, 221, 134,
                    50, 22, 99,
                ],
                [
                    62, 51, 44, 95, 235, 227, 254, 34, 30, 216, 152, 135, 184, 25, 84, 70, 138,
                    104, 214, 174,
                ],
                [
                    43, 172, 71, 142, 150, 99, 188, 139, 139, 102, 45, 68, 195, 163, 205, 234, 230,
                    112, 124, 157,
                ],
                [
                    41, 54, 46, 149, 159, 192, 250, 165, 96, 188, 0, 12, 133, 101, 227, 169, 54,
                    173, 46, 239,
                ],
                [
                    26, 128, 246, 182, 7, 245, 120, 96, 212, 214, 194, 117, 164, 110, 146, 128, 52,
                    94, 143, 92,
                ],
                [
                    190, 227, 253, 116, 244, 51, 129, 238, 228, 165, 148, 251, 143, 195, 34, 136,
                    240, 52, 240, 133,
                ],
                [
                    180, 30, 58, 98, 99, 185, 52, 187, 150, 165, 246, 117, 14, 98, 184, 163, 83,
                    95, 245, 67,
                ],
                [
                    197, 192, 17, 204, 119, 132, 197, 243, 117, 173, 164, 10, 228, 26, 29, 190,
                    166, 21, 181, 252,
                ],
                [
                    92, 175, 169, 48, 223, 195, 134, 93, 132, 239, 38, 169, 44, 251, 42, 107, 174,
                    17, 24, 85,
                ],
                [
                    18, 198, 208, 225, 149, 61, 27, 88, 134, 81, 196, 202, 21, 138, 24, 27, 212,
                    39, 197, 191,
                ],
                [
                    93, 181, 248, 2, 188, 93, 224, 219, 206, 48, 82, 219, 137, 187, 158, 128, 41,
                    35, 125, 21,
                ],
                [
                    178, 83, 36, 122, 56, 245, 175, 232, 70, 167, 1, 24, 43, 195, 196, 56, 3, 49,
                    80, 52,
                ],
                [
                    8, 124, 177, 229, 187, 213, 17, 158, 169, 73, 159, 31, 77, 4, 108, 199, 34,
                    124, 81, 213,
                ],
                [
                    167, 194, 123, 247, 76, 52, 198, 110, 245, 145, 78, 227, 172, 194, 132, 140,
                    162, 242, 112, 57,
                ],
                [
                    179, 9, 29, 152, 162, 222, 56, 125, 217, 87, 175, 122, 138, 225, 124, 218, 215,
                    6, 239, 132,
                ],
                [
                    230, 118, 27, 213, 42, 13, 152, 42, 85, 50, 192, 21, 210, 10, 14, 210, 204, 62,
                    239, 112,
                ],
                [
                    173, 25, 69, 81, 150, 27, 80, 164, 153, 23, 5, 176, 240, 200, 168, 134, 240,
                    85, 47, 216,
                ],
                [
                    167, 67, 115, 248, 34, 111, 181, 151, 106, 194, 67, 148, 91, 174, 86, 6, 161,
                    21, 78, 173,
                ],
                [
                    196, 215, 176, 176, 90, 245, 233, 36, 185, 173, 246, 18, 214, 239, 101, 187,
                    228, 203, 65, 177,
                ],
                [
                    172, 116, 27, 44, 246, 240, 193, 181, 254, 87, 229, 18, 226, 25, 46, 35, 46,
                    87, 147, 168,
                ],
                [
                    139, 29, 222, 54, 169, 205, 108, 220, 224, 110, 230, 97, 34, 20, 222, 245, 77,
                    98, 44, 187,
                ],
                [
                    255, 117, 61, 242, 225, 183, 248, 224, 193, 244, 75, 186, 162, 147, 198, 70,
                    172, 198, 76, 254,
                ],
                [
                    217, 129, 128, 249, 129, 38, 80, 106, 204, 173, 195, 190, 150, 228, 114, 193,
                    93, 70, 181, 139,
                ],
                [
                    38, 238, 197, 123, 121, 47, 251, 13, 188, 230, 170, 43, 141, 119, 81, 225, 175,
                    219, 49, 48,
                ],
                [
                    42, 231, 249, 184, 117, 17, 77, 168, 8, 127, 130, 123, 19, 193, 199, 55, 70,
                    196, 245, 232,
                ],
                [
                    228, 226, 71, 187, 141, 114, 32, 12, 111, 20, 216, 13, 187, 119, 72, 170, 149,
                    123, 167, 136,
                ],
                [
                    251, 216, 135, 58, 249, 85, 96, 242, 131, 89, 241, 170, 170, 213, 137, 65, 211,
                    229, 138, 215,
                ],
                [
                    162, 64, 93, 178, 156, 113, 62, 121, 149, 40, 125, 192, 187, 200, 225, 241,
                    179, 191, 253, 167,
                ],
                [
                    103, 168, 35, 167, 147, 92, 149, 154, 99, 219, 223, 237, 86, 174, 21, 31, 170,
                    192, 218, 3,
                ],
                [
                    79, 250, 153, 180, 215, 134, 51, 45, 41, 234, 169, 67, 83, 229, 81, 41, 74,
                    113, 229, 97,
                ],
                [
                    199, 238, 181, 1, 78, 141, 210, 2, 66, 6, 255, 200, 182, 8, 98, 159, 171, 227,
                    65, 104,
                ],
                [
                    184, 36, 77, 7, 67, 61, 14, 203, 21, 229, 6, 7, 213, 216, 225, 229, 211, 17,
                    108, 240,
                ],
                [
                    245, 158, 118, 39, 210, 5, 166, 242, 28, 112, 170, 65, 159, 137, 7, 74, 197,
                    55, 134, 253,
                ],
                [
                    167, 50, 169, 68, 46, 93, 88, 93, 198, 20, 9, 43, 204, 127, 8, 192, 179, 223,
                    94, 72,
                ],
                [
                    197, 206, 193, 5, 77, 128, 7, 43, 90, 60, 197, 64, 173, 40, 21, 131, 65, 71,
                    70, 93,
                ],
                [
                    11, 159, 58, 44, 220, 219, 40, 229, 149, 159, 251, 156, 110, 28, 223, 81, 87,
                    90, 195, 4,
                ],
                [
                    106, 239, 182, 47, 220, 202, 54, 135, 249, 143, 216, 194, 113, 232, 98, 37, 29,
                    28, 255, 92,
                ],
                [
                    249, 125, 26, 198, 178, 128, 113, 229, 241, 11, 86, 111, 207, 73, 208, 134, 42,
                    167, 192, 16,
                ],
                [
                    125, 9, 10, 153, 194, 224, 232, 53, 113, 14, 188, 65, 159, 39, 63, 127, 118,
                    84, 140, 183,
                ],
                [
                    136, 174, 194, 91, 82, 125, 65, 203, 27, 165, 141, 182, 101, 147, 135, 103,
                    175, 40, 158, 88,
                ],
                [
                    2, 178, 38, 208, 137, 106, 117, 132, 60, 138, 7, 126, 35, 149, 82, 100, 228,
                    218, 51, 122,
                ],
                [
                    193, 162, 81, 16, 190, 218, 220, 18, 15, 169, 87, 247, 94, 118, 92, 250, 187,
                    70, 117, 192,
                ],
                [
                    39, 55, 97, 127, 84, 50, 127, 94, 140, 141, 233, 46, 130, 29, 200, 250, 122,
                    49, 128, 170,
                ],
                [
                    41, 132, 219, 235, 107, 36, 134, 184, 87, 206, 117, 247, 227, 193, 226, 33,
                    202, 171, 174, 137,
                ],
                [
                    204, 118, 199, 230, 129, 146, 80, 30, 30, 247, 118, 144, 166, 205, 19, 159,
                    196, 4, 138, 102,
                ],
                [
                    198, 192, 184, 129, 112, 174, 38, 40, 116, 3, 102, 2, 168, 206, 108, 71, 103,
                    167, 242, 99,
                ],
                [
                    238, 165, 249, 43, 97, 69, 37, 245, 102, 170, 58, 42, 127, 231, 255, 51, 148,
                    135, 213, 209,
                ],
                [
                    20, 21, 43, 12, 35, 32, 99, 231, 153, 168, 49, 47, 249, 166, 106, 98, 204, 172,
                    234, 255,
                ],
                [
                    237, 34, 231, 144, 28, 150, 138, 200, 122, 58, 68, 4, 74, 169, 252, 254, 109,
                    106, 57, 187,
                ],
                [
                    185, 19, 249, 126, 232, 164, 64, 113, 95, 120, 11, 162, 186, 60, 89, 141, 154,
                    80, 79, 169,
                ],
                [
                    153, 179, 12, 222, 189, 2, 246, 37, 225, 86, 252, 12, 207, 185, 237, 244, 209,
                    46, 30, 153,
                ],
                [
                    134, 42, 144, 3, 113, 157, 106, 94, 92, 81, 47, 93, 14, 129, 135, 87, 64, 238,
                    209, 180,
                ],
                [
                    189, 115, 243, 110, 146, 138, 114, 102, 49, 235, 191, 234, 71, 60, 32, 180,
                    237, 173, 159, 236,
                ],
                [
                    145, 24, 72, 129, 51, 133, 110, 198, 221, 32, 115, 57, 169, 189, 122, 116, 215,
                    244, 90, 81,
                ],
                [
                    81, 44, 197, 42, 172, 193, 164, 82, 211, 231, 7, 132, 166, 214, 233, 221, 212,
                    143, 51, 18,
                ],
                [
                    247, 216, 162, 207, 158, 89, 148, 32, 184, 51, 229, 235, 143, 186, 26, 248,
                    140, 89, 241, 55,
                ],
                [
                    45, 29, 82, 28, 151, 57, 241, 16, 132, 26, 1, 13, 20, 214, 214, 30, 83, 60,
                    243, 116,
                ],
                [
                    128, 138, 73, 68, 1, 1, 46, 13, 96, 66, 139, 46, 86, 230, 2, 64, 124, 255, 169,
                    185,
                ],
                [
                    91, 69, 207, 210, 110, 254, 80, 85, 245, 238, 45, 234, 139, 104, 135, 87, 116,
                    174, 27, 58,
                ],
                [
                    25, 107, 101, 58, 183, 237, 199, 42, 4, 83, 120, 44, 108, 123, 181, 222, 231,
                    226, 95, 20,
                ],
                [
                    229, 45, 182, 124, 93, 7, 103, 25, 59, 148, 120, 38, 92, 78, 82, 39, 36, 134,
                    91, 68,
                ],
                [
                    73, 79, 247, 174, 39, 31, 223, 150, 159, 202, 174, 116, 156, 242, 65, 185, 255,
                    142, 74, 70,
                ],
                [
                    195, 179, 131, 72, 121, 13, 226, 14, 68, 101, 218, 252, 97, 134, 91, 125, 237,
                    179, 87, 63,
                ],
                [
                    93, 38, 195, 168, 18, 111, 238, 83, 240, 48, 234, 232, 238, 136, 131, 31, 91,
                    47, 109, 204,
                ],
                [
                    98, 8, 103, 22, 137, 228, 97, 119, 84, 73, 191, 31, 130, 112, 55, 168, 91, 115,
                    159, 196,
                ],
                [
                    188, 155, 207, 121, 84, 224, 44, 200, 141, 35, 8, 213, 9, 56, 99, 235, 117, 31,
                    108, 40,
                ],
                [
                    139, 249, 25, 58, 215, 173, 118, 191, 221, 118, 240, 184, 172, 201, 152, 247,
                    243, 253, 80, 21,
                ],
                [
                    94, 147, 243, 113, 233, 80, 204, 102, 83, 93, 8, 218, 117, 106, 236, 148, 82,
                    160, 75, 54,
                ],
                [
                    186, 157, 182, 62, 16, 32, 152, 251, 7, 155, 168, 42, 210, 74, 89, 166, 95, 5,
                    210, 22,
                ],
                [
                    62, 146, 198, 9, 164, 92, 160, 130, 73, 68, 118, 6, 175, 120, 225, 78, 241, 95,
                    208, 251,
                ],
                [
                    135, 180, 193, 177, 134, 231, 21, 200, 150, 11, 83, 25, 220, 199, 132, 42, 46,
                    140, 90, 174,
                ],
                [
                    172, 92, 200, 0, 8, 66, 55, 145, 252, 48, 111, 12, 49, 70, 225, 132, 68, 67,
                    200, 139,
                ],
                [
                    60, 145, 15, 157, 129, 205, 87, 157, 179, 209, 128, 75, 86, 73, 125, 107, 39,
                    28, 117, 135,
                ],
                [
                    94, 250, 209, 215, 153, 147, 39, 27, 125, 235, 38, 123, 132, 126, 254, 241,
                    174, 97, 207, 94,
                ],
                [
                    135, 239, 192, 203, 218, 110, 132, 137, 3, 128, 152, 31, 209, 47, 150, 242,
                    246, 124, 198, 129,
                ],
                [
                    183, 131, 243, 104, 251, 23, 112, 196, 132, 215, 116, 227, 50, 253, 53, 137,
                    55, 13, 97, 5,
                ],
                [
                    234, 167, 82, 131, 202, 80, 202, 72, 102, 225, 171, 214, 246, 182, 87, 56, 169,
                    215, 115, 121,
                ],
                [
                    220, 145, 253, 161, 67, 249, 224, 43, 21, 81, 219, 97, 0, 214, 6, 126, 3, 119,
                    96, 2,
                ],
                [
                    247, 51, 52, 255, 130, 160, 143, 135, 117, 63, 198, 167, 49, 249, 214, 98, 146,
                    56, 117, 214,
                ],
                [
                    18, 184, 112, 155, 0, 13, 128, 205, 222, 187, 47, 192, 254, 251, 84, 123, 90,
                    201, 219, 138,
                ],
                [
                    41, 206, 114, 114, 49, 63, 178, 153, 210, 4, 90, 193, 244, 251, 169, 214, 246,
                    34, 251, 111,
                ],
                [
                    192, 220, 164, 203, 29, 3, 34, 34, 117, 150, 62, 211, 16, 117, 152, 79, 192,
                    237, 0, 245,
                ],
                [
                    153, 84, 125, 30, 254, 93, 214, 229, 80, 23, 115, 77, 67, 236, 149, 153, 174,
                    215, 177, 106,
                ],
                [
                    244, 20, 232, 68, 145, 132, 221, 17, 214, 206, 126, 62, 57, 143, 208, 15, 193,
                    15, 131, 98,
                ],
                [
                    223, 72, 231, 185, 177, 16, 185, 199, 248, 156, 205, 37, 9, 122, 76, 166, 115,
                    214, 172, 108,
                ],
                [
                    158, 24, 197, 97, 47, 251, 96, 114, 98, 129, 223, 69, 230, 155, 230, 171, 47,
                    223, 214, 64,
                ],
                [
                    114, 60, 60, 213, 70, 203, 227, 232, 246, 157, 73, 156, 83, 12, 159, 9, 216,
                    109, 83, 222,
                ],
                [
                    119, 149, 117, 22, 204, 205, 48, 183, 89, 146, 56, 22, 182, 108, 49, 71, 26,
                    114, 91, 164,
                ],
                [
                    7, 20, 110, 127, 156, 194, 97, 111, 165, 59, 136, 110, 69, 42, 21, 116, 217,
                    71, 116, 18,
                ],
                [
                    48, 6, 92, 46, 23, 41, 33, 125, 205, 215, 220, 255, 105, 166, 90, 82, 207, 248,
                    254, 94,
                ],
                [
                    40, 175, 174, 99, 225, 186, 166, 78, 43, 16, 18, 32, 148, 34, 220, 1, 227, 91,
                    102, 248,
                ],
                [
                    132, 138, 7, 224, 160, 144, 194, 30, 231, 70, 227, 83, 141, 133, 180, 12, 118,
                    95, 95, 188,
                ],
                [
                    152, 173, 240, 14, 174, 82, 117, 39, 132, 70, 59, 155, 178, 158, 124, 40, 61,
                    180, 207, 35,
                ],
                [
                    96, 177, 129, 158, 85, 40, 217, 6, 101, 201, 29, 204, 105, 253, 58, 0, 194, 98,
                    9, 239,
                ],
                [
                    146, 75, 191, 202, 193, 135, 97, 238, 123, 65, 149, 88, 153, 103, 148, 231,
                    218, 145, 101, 178,
                ],
                [
                    163, 251, 94, 233, 187, 0, 197, 235, 221, 93, 187, 159, 91, 138, 197, 130, 90,
                    235, 168, 170,
                ],
                [
                    119, 0, 142, 100, 195, 20, 198, 92, 46, 183, 105, 10, 70, 197, 64, 86, 127, 93,
                    220, 255,
                ],
                [
                    39, 42, 121, 173, 133, 213, 37, 23, 15, 74, 51, 161, 239, 186, 178, 172, 166,
                    83, 137, 139,
                ],
                [
                    250, 90, 46, 84, 183, 58, 50, 7, 216, 169, 240, 211, 223, 238, 229, 164, 152,
                    139, 19, 17,
                ],
                [
                    253, 79, 83, 36, 191, 233, 2, 159, 136, 155, 4, 222, 188, 127, 35, 205, 220,
                    107, 143, 54,
                ],
                [
                    2, 85, 47, 115, 42, 210, 35, 185, 54, 171, 129, 166, 38, 211, 107, 249, 174,
                    175, 45, 237,
                ],
                [
                    4, 187, 41, 74, 131, 239, 10, 178, 114, 143, 214, 169, 205, 7, 68, 204, 187,
                    206, 122, 118,
                ],
                [
                    160, 199, 212, 189, 252, 143, 5, 210, 177, 64, 2, 195, 91, 42, 120, 70, 167,
                    69, 71, 17,
                ],
                [
                    244, 168, 202, 246, 213, 83, 116, 222, 126, 233, 183, 174, 44, 208, 79, 108,
                    120, 255, 142, 198,
                ],
                [
                    75, 129, 244, 190, 43, 9, 115, 13, 206, 125, 198, 71, 70, 201, 137, 44, 103,
                    147, 29, 20,
                ],
                [
                    168, 142, 179, 102, 150, 159, 156, 161, 68, 214, 135, 239, 30, 117, 187, 47,
                    65, 238, 64, 21,
                ],
                [
                    194, 70, 132, 143, 108, 188, 100, 41, 235, 14, 37, 86, 148, 96, 149, 206, 248,
                    241, 184, 72,
                ],
                [
                    100, 87, 133, 208, 21, 44, 15, 93, 16, 174, 113, 113, 128, 88, 45, 51, 42, 172,
                    31, 129,
                ],
                [
                    21, 253, 66, 153, 210, 74, 74, 125, 10, 179, 38, 240, 147, 52, 236, 221, 236,
                    93, 223, 170,
                ],
                [
                    222, 79, 209, 201, 26, 114, 96, 69, 221, 86, 181, 55, 5, 195, 75, 210, 221,
                    191, 69, 213,
                ],
                [
                    48, 15, 170, 219, 26, 221, 69, 206, 93, 96, 105, 34, 210, 79, 41, 49, 62, 199,
                    18, 227,
                ],
                [
                    19, 160, 108, 194, 235, 105, 216, 217, 150, 2, 56, 231, 16, 134, 21, 137, 39,
                    155, 86, 22,
                ],
                [
                    176, 218, 216, 40, 79, 237, 228, 34, 140, 29, 56, 113, 96, 36, 76, 207, 172,
                    111, 168, 173,
                ],
                [
                    53, 206, 154, 45, 1, 92, 116, 54, 44, 199, 162, 231, 224, 205, 132, 159, 68,
                    225, 236, 41,
                ],
                [
                    214, 144, 111, 80, 154, 26, 167, 53, 20, 212, 28, 67, 99, 49, 85, 139, 173, 9,
                    110, 209,
                ],
                [
                    203, 194, 123, 191, 127, 159, 148, 108, 252, 126, 23, 214, 54, 69, 74, 126,
                    172, 187, 115, 43,
                ],
                [
                    33, 228, 83, 159, 37, 83, 148, 125, 70, 154, 136, 57, 240, 233, 198, 146, 75,
                    25, 204, 183,
                ],
                [
                    254, 201, 191, 0, 25, 85, 62, 217, 235, 190, 84, 253, 244, 142, 57, 180, 72,
                    86, 55, 138,
                ],
                [
                    134, 215, 156, 91, 137, 239, 87, 97, 169, 86, 242, 92, 205, 64, 118, 147, 85,
                    102, 167, 137,
                ],
                [
                    95, 188, 244, 180, 13, 177, 169, 176, 217, 237, 21, 8, 140, 107, 67, 85, 36,
                    210, 59, 225,
                ],
                [
                    51, 207, 12, 115, 243, 67, 82, 235, 124, 132, 83, 243, 17, 149, 223, 4, 198,
                    12, 240, 155,
                ],
                [
                    73, 108, 55, 32, 221, 84, 235, 163, 26, 193, 205, 19, 83, 192, 54, 220, 44,
                    250, 183, 166,
                ],
                [
                    159, 175, 70, 249, 104, 251, 98, 55, 162, 58, 64, 141, 186, 152, 126, 164, 144,
                    67, 179, 250,
                ],
                [
                    101, 51, 22, 99, 55, 164, 156, 100, 229, 81, 64, 251, 88, 55, 17, 79, 26, 221,
                    201, 114,
                ],
                [
                    51, 169, 104, 46, 79, 236, 48, 100, 220, 118, 98, 14, 221, 213, 229, 229, 62,
                    3, 14, 140,
                ],
                [
                    75, 35, 100, 235, 127, 141, 109, 91, 138, 60, 2, 100, 77, 145, 218, 2, 216, 81,
                    3, 139,
                ],
                [
                    127, 73, 144, 10, 17, 247, 118, 32, 34, 40, 150, 69, 146, 21, 93, 153, 190,
                    101, 217, 145,
                ],
                [
                    167, 183, 111, 150, 157, 173, 75, 31, 208, 125, 93, 179, 230, 54, 103, 227,
                    205, 76, 209, 240,
                ],
                [
                    255, 27, 23, 85, 215, 235, 94, 243, 206, 211, 161, 6, 18, 136, 74, 153, 34, 93,
                    133, 75,
                ],
                [
                    103, 88, 164, 155, 53, 38, 58, 126, 41, 142, 21, 138, 147, 5, 37, 115, 151,
                    109, 169, 174,
                ],
                [
                    77, 171, 245, 191, 213, 206, 89, 99, 236, 181, 77, 253, 229, 5, 194, 241, 224,
                    68, 102, 240,
                ],
                [
                    4, 67, 151, 105, 242, 250, 235, 215, 168, 88, 166, 65, 0, 8, 74, 135, 65, 131,
                    211, 48,
                ],
                [
                    150, 67, 200, 13, 95, 189, 196, 212, 73, 210, 168, 61, 186, 220, 149, 250, 28,
                    105, 170, 221,
                ],
                [
                    23, 165, 226, 184, 162, 93, 3, 248, 3, 222, 141, 17, 230, 118, 176, 161, 77,
                    245, 241, 138,
                ],
                [
                    117, 157, 69, 21, 213, 188, 213, 128, 142, 145, 35, 227, 88, 102, 4, 200, 115,
                    253, 170, 254,
                ],
                [
                    243, 75, 229, 85, 73, 173, 196, 13, 247, 149, 154, 225, 132, 222, 94, 176, 233,
                    155, 205, 128,
                ],
                [
                    7, 21, 111, 121, 76, 51, 235, 192, 68, 93, 46, 244, 30, 112, 164, 194, 60, 82,
                    27, 213,
                ],
                [
                    148, 78, 79, 54, 42, 83, 22, 125, 196, 186, 197, 178, 92, 232, 224, 25, 250,
                    45, 40, 66,
                ],
                [
                    99, 90, 215, 115, 230, 60, 68, 158, 170, 103, 88, 12, 223, 30, 63, 148, 166,
                    106, 201, 68,
                ],
                [
                    154, 44, 20, 20, 171, 4, 185, 218, 40, 22, 67, 76, 144, 16, 13, 93, 254, 64,
                    89, 253,
                ],
                [
                    220, 42, 129, 75, 87, 174, 179, 204, 165, 235, 34, 28, 8, 196, 200, 160, 95,
                    19, 142, 96,
                ],
                [
                    24, 95, 247, 205, 252, 142, 137, 141, 208, 2, 4, 112, 173, 247, 4, 250, 241,
                    240, 54, 32,
                ],
                [
                    147, 197, 168, 151, 9, 206, 139, 231, 80, 5, 249, 241, 199, 118, 111, 202, 205,
                    141, 84, 110,
                ],
                [
                    91, 111, 85, 114, 216, 7, 254, 242, 8, 200, 54, 74, 202, 39, 18, 23, 19, 179,
                    42, 20,
                ],
                [
                    168, 188, 82, 98, 90, 150, 74, 229, 246, 222, 38, 48, 39, 4, 24, 199, 115, 25,
                    205, 255,
                ],
                [
                    9, 165, 84, 208, 64, 95, 204, 250, 62, 178, 250, 110, 249, 167, 46, 85, 91,
                    221, 141, 13,
                ],
                [
                    75, 253, 175, 162, 228, 101, 25, 228, 238, 18, 86, 173, 247, 1, 206, 141, 83,
                    253, 121, 129,
                ],
                [
                    43, 64, 149, 33, 65, 112, 161, 95, 200, 134, 57, 8, 238, 243, 51, 71, 30, 240,
                    135, 55,
                ],
                [
                    37, 75, 217, 129, 130, 50, 201, 135, 223, 42, 45, 64, 100, 223, 211, 24, 45,
                    152, 69, 249,
                ],
                [
                    155, 152, 46, 62, 79, 10, 99, 164, 136, 150, 149, 168, 237, 219, 127, 116, 158,
                    189, 121, 140,
                ],
                [
                    67, 71, 49, 99, 156, 183, 185, 66, 217, 150, 252, 254, 189, 93, 215, 52, 22,
                    236, 198, 2,
                ],
                [
                    113, 24, 16, 215, 49, 169, 237, 78, 8, 160, 176, 196, 79, 35, 17, 165, 174,
                    130, 11, 252,
                ],
                [
                    248, 137, 74, 144, 211, 231, 132, 111, 117, 58, 73, 210, 196, 107, 183, 220,
                    146, 104, 95, 130,
                ],
                [
                    115, 161, 159, 115, 23, 185, 225, 138, 208, 212, 86, 6, 77, 100, 60, 132, 209,
                    236, 243, 238,
                ],
                [
                    103, 54, 198, 132, 20, 50, 89, 71, 249, 152, 17, 120, 192, 219, 25, 108, 226,
                    39, 3, 197,
                ],
                [
                    66, 202, 130, 252, 56, 43, 13, 103, 197, 71, 183, 113, 177, 17, 20, 123, 207,
                    243, 127, 162,
                ],
                [
                    22, 89, 138, 91, 232, 14, 52, 190, 200, 219, 88, 164, 76, 233, 167, 191, 213,
                    219, 10, 124,
                ],
                [
                    222, 152, 137, 134, 76, 79, 246, 208, 117, 253, 140, 42, 98, 150, 188, 45, 92,
                    135, 55, 241,
                ],
                [
                    26, 16, 125, 53, 92, 244, 29, 252, 235, 83, 145, 151, 174, 234, 57, 65, 184,
                    209, 0, 31,
                ],
                [
                    30, 100, 167, 122, 34, 153, 110, 67, 52, 83, 202, 73, 41, 183, 161, 130, 59,
                    49, 137, 92,
                ],
                [
                    252, 72, 68, 134, 35, 238, 39, 153, 175, 3, 120, 157, 117, 100, 118, 172, 76,
                    184, 146, 236,
                ],
                [
                    114, 249, 126, 6, 79, 135, 60, 144, 238, 58, 239, 169, 146, 201, 54, 40, 94,
                    135, 84, 109,
                ],
                [
                    177, 235, 229, 109, 75, 151, 38, 117, 218, 67, 50, 253, 242, 61, 83, 92, 208,
                    100, 219, 188,
                ],
                [
                    164, 90, 236, 50, 217, 172, 209, 179, 93, 133, 137, 196, 126, 158, 104, 127,
                    139, 245, 176, 47,
                ],
                [
                    116, 98, 154, 222, 179, 113, 245, 46, 92, 102, 122, 60, 245, 174, 244, 181, 99,
                    73, 67, 44,
                ],
                [
                    73, 232, 231, 100, 238, 81, 75, 57, 65, 134, 172, 161, 115, 7, 233, 239, 143,
                    249, 212, 125,
                ],
                [
                    45, 61, 244, 153, 204, 12, 93, 142, 112, 192, 42, 174, 10, 155, 246, 67, 248,
                    106, 187, 44,
                ],
                [
                    238, 22, 206, 158, 168, 4, 39, 32, 49, 131, 28, 241, 125, 184, 146, 38, 114,
                    166, 167, 83,
                ],
                [
                    2, 118, 114, 117, 69, 33, 247, 32, 32, 0, 212, 42, 167, 222, 27, 245, 100, 31,
                    101, 126,
                ],
                [
                    138, 21, 133, 91, 123, 161, 204, 66, 216, 23, 122, 242, 73, 136, 37, 66, 70,
                    61, 222, 18,
                ],
                [
                    220, 16, 218, 184, 137, 249, 143, 106, 105, 139, 81, 155, 202, 181, 209, 241,
                    128, 218, 87, 217,
                ],
                [
                    122, 88, 114, 241, 188, 231, 248, 179, 67, 232, 144, 24, 62, 2, 22, 97, 96,
                    152, 54, 147,
                ],
                [
                    126, 231, 202, 241, 98, 228, 75, 107, 40, 201, 110, 99, 16, 6, 45, 161, 129,
                    99, 96, 222,
                ],
                [
                    162, 25, 7, 68, 22, 169, 132, 180, 2, 87, 254, 167, 36, 207, 196, 96, 37, 177,
                    241, 91,
                ],
                [
                    65, 56, 177, 30, 102, 246, 37, 4, 157, 225, 125, 40, 13, 247, 94, 240, 183,
                    250, 117, 217,
                ],
                [
                    185, 77, 212, 149, 184, 78, 151, 56, 167, 188, 71, 2, 20, 20, 90, 177, 200,
                    147, 163, 75,
                ],
                [
                    91, 137, 131, 189, 117, 75, 134, 241, 230, 1, 120, 222, 144, 104, 183, 115,
                    115, 201, 129, 197,
                ],
                [
                    181, 151, 214, 64, 67, 115, 78, 225, 167, 16, 34, 28, 155, 18, 114, 22, 24,
                    204, 171, 135,
                ],
                [
                    148, 70, 139, 42, 167, 38, 52, 94, 40, 83, 46, 139, 226, 126, 143, 135, 211,
                    241, 247, 193,
                ],
                [
                    89, 82, 162, 229, 108, 191, 136, 232, 45, 0, 185, 85, 243, 154, 220, 75, 42,
                    29, 239, 172,
                ],
                [
                    191, 213, 221, 81, 67, 177, 255, 22, 246, 10, 18, 216, 198, 7, 57, 5, 119, 190,
                    12, 8,
                ],
                [
                    89, 125, 176, 23, 218, 240, 48, 216, 77, 65, 8, 222, 14, 47, 176, 115, 128,
                    212, 153, 167,
                ],
                [
                    164, 225, 147, 195, 148, 150, 35, 131, 70, 235, 253, 178, 238, 84, 119, 153,
                    20, 137, 28, 46,
                ],
                [
                    106, 130, 240, 186, 17, 148, 129, 193, 43, 155, 97, 31, 119, 26, 177, 100, 201,
                    94, 38, 197,
                ],
                [
                    66, 7, 206, 68, 186, 115, 118, 3, 40, 154, 250, 172, 241, 141, 50, 240, 24, 23,
                    89, 209,
                ],
                [
                    122, 185, 80, 76, 45, 193, 236, 141, 49, 199, 190, 116, 22, 132, 9, 209, 49,
                    227, 123, 87,
                ],
                [
                    155, 226, 36, 243, 124, 27, 130, 24, 198, 185, 154, 142, 225, 135, 91, 62, 101,
                    38, 240, 221,
                ],
                [
                    83, 57, 141, 139, 49, 108, 226, 186, 114, 173, 250, 107, 37, 181, 23, 126, 70,
                    106, 171, 103,
                ],
                [
                    44, 120, 122, 118, 158, 220, 138, 240, 105, 255, 128, 219, 23, 69, 98, 163,
                    180, 18, 68, 76,
                ],
                [
                    100, 198, 45, 154, 113, 167, 39, 176, 144, 252, 163, 72, 77, 62, 240, 204, 197,
                    53, 24, 49,
                ],
                [
                    136, 201, 75, 48, 115, 215, 20, 60, 227, 62, 46, 73, 133, 105, 63, 217, 4, 11,
                    18, 147,
                ],
                [
                    226, 113, 63, 18, 151, 177, 27, 16, 32, 58, 163, 122, 164, 134, 56, 11, 117,
                    96, 46, 126,
                ],
                [
                    222, 226, 5, 193, 5, 63, 89, 225, 143, 19, 156, 152, 183, 106, 138, 185, 78,
                    198, 209, 102,
                ],
                [
                    240, 134, 231, 255, 151, 81, 79, 151, 251, 195, 100, 73, 207, 75, 27, 178, 41,
                    36, 25, 17,
                ],
                [
                    11, 218, 243, 233, 65, 235, 154, 213, 113, 5, 194, 126, 157, 156, 252, 211,
                    213, 17, 104, 63,
                ],
                [
                    109, 216, 157, 197, 135, 1, 230, 143, 142, 30, 181, 214, 22, 177, 102, 82, 174,
                    18, 143, 190,
                ],
                [
                    155, 196, 231, 209, 19, 194, 45, 184, 158, 164, 106, 152, 248, 166, 189, 173,
                    5, 226, 231, 203,
                ],
                [
                    200, 39, 206, 127, 207, 11, 32, 152, 20, 226, 191, 98, 252, 14, 162, 162, 251,
                    148, 123, 189,
                ],
                [
                    82, 142, 1, 187, 22, 22, 193, 115, 245, 234, 125, 192, 145, 60, 95, 32, 243,
                    149, 57, 86,
                ],
                [
                    180, 214, 50, 147, 215, 165, 142, 171, 221, 88, 136, 242, 46, 214, 218, 51,
                    169, 144, 103, 243,
                ],
                [
                    231, 39, 3, 255, 24, 43, 211, 248, 94, 140, 34, 166, 95, 237, 146, 81, 111, 95,
                    114, 118,
                ],
                [
                    92, 41, 49, 67, 117, 128, 48, 253, 160, 186, 55, 39, 195, 130, 102, 131, 150,
                    235, 71, 39,
                ],
                [
                    91, 149, 0, 142, 211, 177, 58, 166, 69, 206, 117, 236, 16, 191, 167, 119, 89,
                    86, 0, 159,
                ],
                [
                    46, 97, 38, 73, 228, 148, 32, 96, 209, 2, 61, 14, 6, 215, 198, 140, 91, 64,
                    150, 129,
                ],
                [
                    91, 52, 214, 30, 132, 167, 105, 77, 212, 213, 238, 72, 55, 17, 18, 141, 218,
                    109, 9, 115,
                ],
                [
                    62, 146, 34, 84, 150, 76, 163, 202, 159, 186, 238, 28, 195, 197, 136, 11, 165,
                    174, 4, 12,
                ],
                [
                    83, 110, 191, 63, 238, 68, 250, 251, 154, 200, 238, 168, 102, 211, 207, 47, 63,
                    27, 227, 230,
                ],
                [
                    190, 11, 116, 235, 41, 157, 46, 227, 5, 77, 43, 71, 5, 51, 202, 231, 29, 91,
                    177, 68,
                ],
                [
                    191, 59, 90, 53, 48, 159, 135, 183, 190, 10, 189, 106, 57, 132, 25, 14, 36,
                    166, 199, 160,
                ],
                [
                    115, 53, 3, 127, 116, 231, 166, 52, 128, 196, 91, 171, 44, 197, 210, 85, 194,
                    74, 168, 74,
                ],
                [
                    74, 41, 71, 58, 74, 218, 121, 174, 125, 47, 173, 56, 19, 238, 119, 63, 165, 29,
                    19, 22,
                ],
                [
                    88, 23, 1, 20, 187, 10, 114, 182, 59, 134, 112, 173, 44, 187, 78, 88, 155, 78,
                    224, 123,
                ],
                [
                    180, 51, 233, 252, 2, 40, 230, 32, 72, 251, 189, 63, 90, 245, 90, 183, 84, 49,
                    141, 176,
                ],
                [
                    19, 139, 34, 238, 53, 92, 241, 243, 174, 19, 30, 94, 217, 107, 80, 236, 87,
                    135, 225, 81,
                ],
                [
                    59, 77, 118, 92, 24, 102, 107, 58, 172, 140, 252, 211, 131, 76, 107, 138, 2, 8,
                    204, 135,
                ],
                [
                    65, 82, 97, 183, 41, 49, 33, 160, 137, 61, 214, 125, 78, 158, 111, 47, 63, 8,
                    138, 254,
                ],
                [
                    29, 156, 76, 182, 151, 125, 53, 224, 66, 14, 153, 244, 172, 179, 56, 61, 5,
                    216, 253, 14,
                ],
                [
                    91, 132, 229, 216, 5, 109, 58, 187, 83, 27, 0, 1, 70, 113, 45, 86, 46, 3, 96,
                    135,
                ],
                [
                    116, 23, 74, 189, 213, 163, 133, 164, 123, 210, 171, 244, 109, 226, 160, 80,
                    72, 64, 50, 224,
                ],
                [
                    73, 205, 175, 28, 89, 139, 222, 251, 233, 55, 114, 109, 86, 26, 4, 131, 187,
                    47, 170, 158,
                ],
                [
                    94, 61, 255, 34, 64, 109, 175, 89, 19, 54, 94, 49, 206, 111, 237, 3, 149, 202,
                    78, 213,
                ],
                [
                    200, 231, 95, 254, 246, 37, 223, 255, 84, 174, 6, 78, 47, 160, 47, 138, 31,
                    232, 185, 120,
                ],
                [
                    242, 249, 203, 154, 124, 87, 184, 168, 186, 131, 57, 98, 73, 22, 101, 57, 131,
                    88, 103, 44,
                ],
                [
                    1, 6, 109, 109, 81, 64, 158, 4, 36, 26, 211, 7, 81, 232, 63, 61, 228, 89, 51,
                    126,
                ],
                [
                    139, 168, 24, 193, 189, 189, 145, 92, 88, 101, 52, 157, 76, 8, 71, 196, 97, 48,
                    28, 76,
                ],
                [
                    239, 94, 131, 89, 92, 199, 82, 194, 162, 52, 183, 164, 233, 155, 91, 237, 248,
                    77, 112, 97,
                ],
                [
                    211, 2, 197, 123, 155, 52, 192, 195, 134, 49, 255, 186, 249, 35, 62, 238, 95,
                    40, 43, 222,
                ],
                [
                    160, 198, 198, 31, 150, 75, 157, 250, 13, 229, 36, 181, 5, 71, 119, 115, 48,
                    79, 11, 178,
                ],
                [
                    216, 140, 77, 241, 3, 208, 111, 47, 252, 65, 176, 169, 17, 44, 26, 19, 182,
                    254, 41, 40,
                ],
                [
                    250, 52, 145, 216, 126, 189, 213, 28, 37, 137, 5, 252, 252, 69, 177, 77, 37,
                    27, 148, 83,
                ],
                [
                    235, 138, 86, 28, 224, 235, 125, 51, 197, 160, 160, 153, 71, 90, 150, 232, 164,
                    234, 253, 207,
                ],
                [
                    27, 32, 169, 217, 33, 173, 211, 140, 122, 114, 99, 210, 177, 75, 78, 37, 201,
                    120, 12, 44,
                ],
                [
                    98, 204, 13, 112, 221, 166, 57, 3, 46, 17, 216, 90, 166, 61, 14, 81, 186, 213,
                    232, 69,
                ],
                [
                    48, 219, 99, 139, 60, 121, 181, 166, 141, 112, 228, 186, 38, 226, 207, 113, 79,
                    124, 141, 173,
                ],
                [
                    39, 60, 126, 66, 214, 34, 159, 101, 218, 173, 109, 190, 203, 75, 47, 28, 118,
                    12, 74, 243,
                ],
                [
                    87, 164, 83, 115, 188, 74, 51, 200, 95, 104, 75, 90, 110, 153, 186, 163, 162,
                    52, 248, 86,
                ],
                [
                    223, 16, 79, 209, 203, 94, 3, 119, 106, 189, 53, 75, 65, 132, 110, 15, 114,
                    154, 83, 45,
                ],
                [
                    125, 119, 188, 146, 24, 33, 44, 45, 85, 100, 165, 143, 183, 233, 173, 25, 241,
                    23, 183, 23,
                ],
                [
                    242, 27, 246, 39, 27, 41, 226, 147, 193, 254, 76, 60, 95, 83, 63, 97, 13, 223,
                    25, 156,
                ],
                [
                    121, 81, 238, 128, 63, 176, 213, 63, 203, 233, 57, 248, 24, 154, 220, 250, 148,
                    182, 83, 94,
                ],
                [
                    250, 132, 230, 69, 78, 123, 143, 226, 181, 13, 168, 158, 36, 55, 161, 108, 95,
                    141, 193, 2,
                ],
                [
                    192, 164, 41, 168, 187, 137, 231, 125, 78, 194, 7, 100, 103, 148, 231, 57, 216,
                    123, 25, 137,
                ],
                [
                    153, 74, 232, 98, 229, 220, 175, 95, 99, 204, 79, 116, 81, 163, 138, 85, 229,
                    116, 144, 84,
                ],
                [
                    173, 188, 181, 221, 28, 52, 21, 81, 157, 112, 136, 214, 124, 90, 225, 67, 79,
                    35, 190, 34,
                ],
                [
                    237, 100, 12, 83, 201, 199, 170, 130, 213, 250, 219, 130, 95, 28, 111, 237,
                    195, 168, 229, 165,
                ],
                [
                    6, 88, 176, 96, 205, 16, 218, 119, 14, 216, 86, 66, 122, 207, 226, 0, 54, 35,
                    217, 151,
                ],
                [
                    111, 94, 100, 54, 108, 18, 74, 174, 215, 74, 132, 221, 18, 144, 87, 233, 86,
                    247, 217, 119,
                ],
                [
                    20, 111, 23, 2, 3, 74, 29, 24, 91, 128, 129, 23, 79, 61, 34, 206, 126, 176, 21,
                    55,
                ],
                [
                    67, 121, 209, 150, 140, 149, 121, 72, 236, 197, 73, 82, 3, 211, 76, 212, 203,
                    107, 170, 152,
                ],
                [
                    209, 19, 152, 91, 164, 69, 146, 84, 112, 148, 192, 12, 140, 96, 103, 160, 95,
                    54, 88, 171,
                ],
                [
                    125, 69, 169, 86, 18, 67, 235, 36, 216, 252, 24, 220, 243, 240, 110, 122, 185,
                    175, 119, 170,
                ],
                [
                    8, 135, 21, 205, 105, 228, 247, 210, 227, 7, 52, 15, 68, 90, 80, 214, 197, 206,
                    171, 60,
                ],
                [
                    155, 38, 93, 134, 51, 38, 124, 211, 149, 119, 215, 226, 208, 138, 216, 205, 45,
                    255, 119, 196,
                ],
                [
                    86, 157, 108, 112, 180, 142, 40, 66, 34, 96, 58, 137, 115, 123, 61, 35, 116,
                    186, 45, 245,
                ],
                [
                    186, 154, 182, 98, 174, 254, 182, 254, 49, 21, 103, 189, 190, 245, 170, 59,
                    111, 231, 101, 68,
                ],
                [
                    110, 113, 100, 192, 134, 19, 236, 23, 221, 198, 168, 165, 61, 239, 167, 130,
                    28, 14, 186, 13,
                ],
                [
                    204, 79, 196, 195, 82, 14, 38, 89, 239, 210, 11, 246, 161, 176, 193, 153, 103,
                    13, 217, 193,
                ],
                [
                    228, 21, 162, 217, 82, 77, 210, 28, 24, 183, 101, 178, 108, 188, 2, 116, 94,
                    163, 183, 229,
                ],
                [
                    15, 66, 23, 59, 25, 79, 120, 254, 204, 130, 180, 201, 19, 0, 161, 172, 247, 27,
                    103, 63,
                ],
                [
                    206, 135, 234, 159, 46, 116, 62, 164, 170, 81, 184, 133, 115, 58, 54, 212, 226,
                    50, 121, 67,
                ],
                [
                    241, 159, 133, 168, 87, 115, 96, 179, 226, 242, 225, 119, 10, 156, 114, 64, 61,
                    15, 112, 214,
                ],
                [
                    198, 170, 78, 52, 16, 74, 209, 197, 148, 66, 147, 134, 125, 82, 181, 113, 80,
                    204, 224, 54,
                ],
                [
                    2, 254, 44, 91, 175, 110, 143, 108, 197, 119, 173, 107, 130, 237, 16, 43, 41,
                    171, 84, 90,
                ],
                [
                    101, 150, 4, 209, 191, 71, 78, 91, 28, 62, 239, 167, 41, 68, 140, 235, 92, 164,
                    107, 170,
                ],
                [
                    12, 221, 6, 131, 123, 236, 230, 48, 5, 203, 105, 49, 65, 240, 135, 235, 171,
                    170, 187, 232,
                ],
                [
                    92, 66, 254, 177, 120, 144, 192, 43, 173, 0, 11, 17, 199, 173, 70, 211, 173,
                    46, 107, 26,
                ],
                [
                    174, 191, 81, 9, 70, 54, 81, 151, 190, 55, 226, 127, 156, 130, 240, 185, 15,
                    60, 216, 233,
                ],
                [
                    76, 172, 50, 173, 53, 186, 126, 27, 172, 251, 76, 236, 119, 184, 146, 254, 147,
                    223, 222, 170,
                ],
                [
                    18, 171, 81, 3, 220, 139, 3, 59, 174, 8, 151, 34, 161, 109, 251, 176, 104, 29,
                    214, 243,
                ],
                [
                    107, 203, 116, 138, 178, 12, 201, 47, 126, 115, 181, 186, 141, 243, 194, 160,
                    29, 144, 146, 111,
                ],
                [
                    157, 99, 167, 232, 15, 18, 49, 51, 35, 170, 215, 241, 178, 102, 228, 7, 211, 6,
                    55, 138,
                ],
                [
                    188, 197, 238, 108, 230, 249, 92, 117, 71, 0, 22, 153, 200, 187, 61, 4, 214, 0,
                    224, 155,
                ],
                [
                    169, 228, 9, 25, 115, 67, 221, 17, 221, 231, 166, 161, 29, 206, 145, 16, 216,
                    143, 51, 154,
                ],
                [
                    44, 193, 109, 248, 96, 74, 145, 251, 225, 207, 156, 67, 251, 12, 30, 31, 70,
                    108, 176, 212,
                ],
                [
                    126, 247, 11, 62, 167, 100, 6, 70, 193, 194, 136, 126, 105, 79, 124, 90, 238,
                    0, 91, 3,
                ],
                [
                    76, 17, 218, 145, 44, 108, 184, 203, 0, 87, 92, 194, 141, 112, 62, 19, 14, 173,
                    194, 162,
                ],
                [
                    8, 157, 103, 25, 136, 205, 213, 28, 120, 77, 1, 70, 178, 163, 25, 198, 77, 181,
                    168, 121,
                ],
                [
                    16, 228, 6, 91, 37, 20, 233, 96, 137, 171, 207, 249, 82, 201, 237, 199, 191,
                    233, 54, 128,
                ],
                [
                    199, 129, 24, 118, 188, 170, 203, 141, 74, 121, 220, 107, 79, 224, 119, 16, 18,
                    86, 101, 137,
                ],
                [
                    148, 246, 243, 230, 229, 102, 29, 26, 135, 23, 125, 221, 47, 202, 127, 83, 69,
                    140, 118, 61,
                ],
                [
                    47, 89, 239, 93, 238, 247, 251, 60, 113, 218, 41, 186, 217, 147, 118, 247, 147,
                    211, 110, 71,
                ],
                [
                    248, 170, 177, 117, 150, 128, 130, 123, 205, 84, 86, 171, 204, 206, 197, 72,
                    125, 213, 141, 33,
                ],
                [
                    164, 170, 4, 71, 125, 2, 65, 42, 34, 245, 139, 92, 182, 178, 201, 243, 95, 135,
                    55, 172,
                ],
                [
                    85, 141, 48, 84, 77, 89, 218, 228, 5, 46, 110, 44, 29, 225, 123, 233, 86, 121,
                    85, 164,
                ],
                [
                    43, 113, 63, 42, 169, 210, 138, 183, 16, 214, 38, 65, 17, 236, 100, 189, 40,
                    164, 131, 97,
                ],
                [
                    142, 95, 29, 19, 143, 57, 108, 108, 163, 127, 117, 125, 252, 239, 50, 232, 150,
                    16, 113, 83,
                ],
                [
                    186, 15, 234, 82, 63, 219, 212, 197, 196, 34, 118, 236, 98, 240, 196, 105, 168,
                    40, 105, 29,
                ],
                [
                    18, 224, 72, 56, 142, 122, 233, 41, 142, 37, 4, 1, 220, 65, 184, 138, 197, 8,
                    26, 47,
                ],
                [
                    129, 182, 106, 22, 119, 85, 17, 88, 80, 248, 17, 53, 147, 51, 154, 49, 141,
                    245, 152, 123,
                ],
                [
                    185, 81, 255, 218, 171, 105, 200, 106, 62, 123, 245, 55, 112, 54, 55, 170, 157,
                    177, 150, 227,
                ],
                [
                    147, 106, 143, 233, 122, 181, 142, 233, 164, 68, 169, 189, 54, 190, 122, 248,
                    2, 125, 21, 134,
                ],
                [
                    239, 185, 83, 230, 18, 42, 86, 114, 34, 245, 255, 221, 78, 186, 112, 111, 67,
                    22, 190, 171,
                ],
                [
                    209, 146, 18, 50, 187, 237, 175, 118, 73, 89, 224, 75, 92, 20, 146, 105, 25,
                    234, 206, 29,
                ],
                [
                    30, 33, 57, 133, 105, 49, 203, 101, 40, 243, 45, 138, 11, 177, 101, 41, 161,
                    195, 3, 124,
                ],
                [
                    122, 238, 28, 31, 60, 26, 102, 202, 11, 126, 46, 47, 199, 58, 106, 89, 99, 21,
                    94, 176,
                ],
                [
                    184, 167, 138, 35, 137, 208, 139, 232, 214, 101, 244, 86, 159, 191, 223, 67,
                    209, 240, 110, 131,
                ],
                [
                    82, 153, 26, 30, 64, 198, 66, 48, 126, 249, 81, 145, 95, 248, 125, 74, 21, 149,
                    169, 158,
                ],
                [
                    81, 173, 157, 193, 190, 169, 69, 64, 134, 135, 98, 116, 82, 74, 213, 240, 128,
                    135, 30, 162,
                ],
                [
                    41, 96, 163, 78, 226, 27, 34, 213, 50, 126, 78, 164, 231, 164, 224, 230, 218,
                    130, 110, 248,
                ],
                [
                    66, 182, 121, 191, 45, 51, 122, 52, 173, 17, 169, 253, 223, 21, 54, 100, 109,
                    216, 161, 167,
                ],
                [
                    133, 45, 4, 150, 216, 103, 61, 71, 144, 180, 94, 171, 187, 195, 244, 74, 251,
                    43, 9, 31,
                ],
                [
                    7, 133, 72, 168, 108, 67, 98, 23, 149, 104, 13, 15, 170, 70, 244, 127, 198,
                    181, 120, 166,
                ],
                [
                    210, 112, 157, 149, 196, 183, 9, 94, 40, 18, 75, 176, 188, 208, 52, 196, 8,
                    109, 63, 114,
                ],
                [
                    155, 138, 204, 73, 192, 237, 241, 124, 140, 43, 155, 139, 101, 103, 186, 40,
                    55, 191, 194, 115,
                ],
                [
                    35, 185, 12, 10, 44, 220, 81, 20, 54, 114, 94, 185, 147, 148, 138, 93, 138,
                    170, 55, 8,
                ],
                [
                    67, 78, 142, 103, 15, 5, 145, 145, 115, 22, 137, 16, 24, 160, 23, 194, 235,
                    110, 73, 248,
                ],
                [
                    224, 212, 156, 129, 16, 108, 254, 137, 47, 166, 196, 186, 223, 43, 59, 130,
                    113, 108, 193, 161,
                ],
                [
                    174, 103, 195, 16, 149, 116, 35, 165, 92, 123, 100, 220, 83, 91, 131, 45, 55,
                    106, 240, 233,
                ],
                [
                    4, 92, 105, 86, 142, 84, 213, 206, 5, 251, 4, 7, 4, 107, 240, 238, 202, 57, 71,
                    140,
                ],
                [
                    238, 38, 255, 185, 70, 22, 45, 117, 168, 32, 117, 184, 34, 48, 251, 93, 224,
                    240, 19, 144,
                ],
                [
                    156, 206, 14, 74, 209, 21, 218, 175, 253, 227, 250, 184, 26, 74, 236, 253, 19,
                    112, 212, 213,
                ],
                [
                    168, 217, 141, 111, 154, 56, 73, 166, 57, 51, 96, 132, 20, 178, 162, 0, 229,
                    211, 184, 221,
                ],
                [
                    10, 81, 129, 163, 154, 93, 189, 21, 72, 223, 88, 88, 140, 253, 31, 23, 179, 33,
                    68, 41,
                ],
                [
                    157, 45, 89, 245, 45, 194, 234, 59, 132, 10, 1, 30, 243, 137, 95, 92, 244, 39,
                    50, 221,
                ],
                [
                    52, 125, 15, 149, 177, 184, 204, 128, 45, 41, 204, 133, 92, 62, 107, 233, 85,
                    74, 163, 186,
                ],
                [
                    131, 166, 93, 252, 227, 42, 65, 210, 48, 151, 4, 153, 110, 234, 191, 195, 236,
                    157, 23, 100,
                ],
                [
                    177, 72, 95, 99, 40, 127, 101, 241, 120, 19, 138, 154, 200, 227, 142, 77, 10,
                    5, 226, 96,
                ],
                [
                    95, 123, 244, 16, 121, 232, 63, 28, 253, 155, 47, 252, 135, 54, 170, 245, 233,
                    144, 131, 27,
                ],
                [
                    225, 112, 207, 135, 136, 25, 241, 120, 23, 59, 174, 177, 110, 69, 170, 253,
                    205, 30, 113, 7,
                ],
                [
                    208, 89, 164, 196, 139, 3, 56, 178, 196, 113, 97, 28, 96, 43, 43, 202, 3, 221,
                    12, 114,
                ],
                [
                    144, 13, 62, 31, 131, 252, 165, 181, 223, 110, 84, 55, 142, 205, 146, 76, 108,
                    52, 223, 2,
                ],
                [
                    38, 103, 38, 183, 102, 30, 246, 91, 51, 79, 200, 9, 79, 204, 88, 222, 78, 87,
                    225, 254,
                ],
                [
                    43, 99, 6, 153, 6, 31, 193, 163, 10, 165, 141, 18, 64, 247, 103, 31, 25, 123,
                    117, 160,
                ],
                [
                    15, 120, 243, 118, 239, 35, 246, 79, 146, 186, 106, 38, 230, 246, 169, 60, 73,
                    106, 37, 30,
                ],
                [
                    6, 78, 87, 225, 197, 110, 224, 132, 24, 51, 19, 139, 125, 244, 229, 113, 127,
                    172, 2, 137,
                ],
                [
                    148, 146, 96, 244, 144, 177, 206, 247, 143, 74, 29, 229, 59, 235, 232, 67, 81,
                    252, 144, 58,
                ],
                [
                    29, 5, 222, 220, 41, 136, 219, 91, 134, 237, 73, 183, 97, 86, 128, 183, 208,
                    72, 184, 152,
                ],
                [
                    65, 138, 40, 201, 224, 240, 20, 172, 4, 216, 201, 172, 224, 240, 132, 98, 47,
                    146, 165, 24,
                ],
                [
                    4, 236, 211, 149, 15, 226, 187, 143, 39, 6, 173, 80, 128, 4, 182, 35, 16, 186,
                    96, 5,
                ],
                [
                    19, 225, 171, 215, 110, 89, 70, 218, 144, 87, 196, 87, 47, 14, 124, 175, 172,
                    170, 149, 148,
                ],
                [
                    185, 63, 43, 168, 249, 147, 181, 150, 103, 118, 142, 68, 76, 21, 117, 37, 41,
                    51, 179, 227,
                ],
            ],
        ),
    }
}
