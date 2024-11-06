use std::collections::HashSet;

use anyhow::bail;
use bitcoin::{
    hex::DisplayHex,
    sighash::{Prevouts, SighashCache},
    TapSighashType, Transaction, TxOut, Txid,
};
use musig2::{
    aggregate_partial_signatures, sign_partial, AggNonce, KeyAggContext, PartialSignature, PubNonce,
};
use rand::RngCore;
use secp256k1::schnorr::Signature;
use strata_bridge_btcio::traits::Broadcaster;
use strata_bridge_db::{
    connector_db::ConnectorDb,
    operator::{KickoffInfo, OperatorDb},
    public::PublicDb,
};
use strata_bridge_primitives::{
    build_context::{BuildContext, TxBuildContext, TxKind},
    deposit::DepositInfo,
    duties::BridgeDuty,
    params::prelude::{BRIDGE_DENOMINATION, MIN_RELAY_FEE, OPERATOR_STAKE},
    scripts::{
        taproot::{create_message_hash, finalize_input, TaprootWitness},
        wots::generate_wots_public_keys,
    },
    types::TxSigningData,
    withdrawal::WithdrawalInfo,
};
use strata_bridge_tx_graph::{
    peg_out_graph::{PegOutGraph, PegOutGraphConnectors, PegOutGraphInput},
    transactions::prelude::*,
};
use tokio::sync::broadcast;
use tracing::{error, info, trace, warn};

use crate::{
    base::Agent,
    signal::{AggNonces, CovenantSignal, DepositSignal, Request, RequestFulfilled},
};

pub type OperatorIdx = u32;

#[derive(Debug)]
pub struct Operator {
    pub agent: Agent,

    msk: String,

    build_context: TxBuildContext,

    db: OperatorDb,

    public_db: PublicDb,

    is_faulty: bool,

    deposit_signal_sender: broadcast::Sender<DepositSignal>,

    deposit_signal_receiver: broadcast::Receiver<DepositSignal>,

    covenant_signal_sender: broadcast::Sender<CovenantSignal>,

    covenant_signal_receiver: broadcast::Receiver<CovenantSignal>,
}

impl Operator {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        agent: Agent,
        build_context: TxBuildContext,
        is_faulty: bool,
        db: OperatorDb,
        public_db: PublicDb,
        deposit_signal_sender: broadcast::Sender<DepositSignal>,
        deposit_signal_receiver: broadcast::Receiver<DepositSignal>,
        covenant_signal_sender: broadcast::Sender<CovenantSignal>,
        covenant_signal_receiver: broadcast::Receiver<CovenantSignal>,
    ) -> Self {
        let mut msk_bytes: [u8; 32] = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut msk_bytes);

        let msk = msk_bytes.to_lower_hex_string();

        Self {
            agent,
            msk,
            build_context,
            db,
            public_db,
            is_faulty,
            deposit_signal_sender,
            deposit_signal_receiver,
            covenant_signal_sender,
            covenant_signal_receiver,
        }
    }

    pub fn am_i_faulty(&self) -> bool {
        self.is_faulty
    }

    pub async fn start(&mut self, duty_receiver: &mut broadcast::Receiver<BridgeDuty>) {
        info!(action = "starting operator", operator_idx=%self.build_context.own_index());

        while let Ok(bridge_duty) = duty_receiver.recv().await {
            self.process_duty(bridge_duty).await;
        }
    }

    pub async fn process_duty(&mut self, duty: BridgeDuty) {
        match duty {
            BridgeDuty::SignDeposit(deposit_info) => {
                let txid = deposit_info.deposit_request_outpoint().txid;
                info!(event = "received deposit", operator_idx = %self.build_context.own_index(), drt_txid = %txid);

                self.handle_deposit(deposit_info).await;
            }
            BridgeDuty::FulfillWithdrawal(cooperative_withdrawal_info) => {
                let txid = cooperative_withdrawal_info.deposit_outpoint().txid;
                let assignee_id = cooperative_withdrawal_info.assigned_operator_idx();
                info!(event = "received withdrawal", operator_idx = %self.build_context.own_index(), dt_txid = %txid, assignee = %assignee_id);

                if assignee_id != self.build_context.own_index() {
                    return;
                }

                self.handle_withdrawal(cooperative_withdrawal_info).await;
            }
        }
    }

    pub async fn handle_deposit(&mut self, deposit_info: DepositInfo) {
        let own_index = self.build_context.own_index();

        // 1. aggregate_tx_graph
        let mut deposit_tx = deposit_info
            .construct_signing_data(&self.build_context)
            .expect("should be able to create build context");
        let deposit_txid = deposit_tx.psbt.unsigned_tx.compute_txid();

        info!(action = "generating wots public keys", %deposit_txid, %own_index);
        let public_keys = generate_wots_public_keys(&self.msk, deposit_txid);
        self.public_db
            .set_wots_public_keys(self.build_context.own_index(), deposit_txid, &public_keys)
            .await;

        info!(action = "generating kickoff", %deposit_txid, %own_index);
        let reserved_outpoints = self.db.selected_outpoints().await;
        let (change_address, funding_input, total_amount, funding_utxo) = self
            .agent
            .select_utxo(OPERATOR_STAKE, reserved_outpoints)
            .await
            .expect("should be able to get outpoints");

        self.db.add_outpoint(funding_input).await;

        let funding_inputs = vec![funding_input];
        let funding_utxos = vec![funding_utxo];
        let change_amt = total_amount - OPERATOR_STAKE - MIN_RELAY_FEE;

        info!(action = "composing pegout graph input", %deposit_txid, %own_index);
        let peg_out_graph_input = PegOutGraphInput {
            network: self.build_context.network(),
            deposit_amount: BRIDGE_DENOMINATION,
            operator_pubkey: self.agent.public_key().x_only_public_key().0,
            kickoff_data: KickoffTxData {
                funding_inputs: funding_inputs.clone(),
                funding_utxos: funding_utxos.clone(),
                change_address: change_address.as_unchecked().clone(),
                change_amt,
                deposit_txid,
            },
        };

        info!(action = "adding kickoff info to db", %deposit_txid, %own_index);
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
        if let Err(e) = self
            .agent
            .client
            .send_raw_transaction(&signed_deposit_tx)
            .await
        {
            if e.is_missing_or_invalid_input() {
                warn!("somebody else has already spent the DRT UTXO");
            } else {
                error!(?e, "could not broadcast deposit tx");
            }
        } else {
            info!("deposit tx successfully broadcasted");
        }
    }

    pub async fn handle_withdrawal(&self, _withdrawal_info: WithdrawalInfo) {
        // for withdrawal duty (assigned),
        // 1. pay the user with PoW transaction
        // 2. create tx graph from public data
        // 3. publish kickoff -> claim
        // 4. compute superblock and proof
        // 5. publish assert chain
        // 6. settle reimbursement tx after wait time
    }

    pub async fn handle_withdrawal_faulty(&self) {
        // for withdrawal duty (assigned and self.am_i_faulty()),
        // 1. create tx graph from public data
        // 2. publish kickoff -> claim
        // 3. compute superblock and faulty proof
        // 4. publish assert chain
        // 5. try to settle reimbursement tx after wait time
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
        self.covenant_signal_sender
            .send(CovenantSignal::CovenantRequest {
                details: Request::Nonce(self_peg_out_graph_input),
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
    ) -> RequestFulfilled {
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

        RequestFulfilled::Nonce {
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

        while let Ok(msg) = self.covenant_signal_receiver.recv().await {
            if self_requests_fulfilled && requests_served.len() == num_signers {
                info!(event = "all nonce requests fulfilled and served", operator_idx = %own_index, %deposit_txid, requests_served = %requests_served.len());
                return;
            }

            match msg {
                CovenantSignal::CovenantRequest { details, sender_id } => {
                    if sender_id == self.build_context.own_index() {
                        info!(event = "self request ignored", %deposit_txid, %sender_id, %own_index);
                        // ignore own request
                        continue;
                    }

                    // fulfill request
                    if let Request::Nonce(peg_out_graph_input) = details {
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
                        self.covenant_signal_sender
                            .send(CovenantSignal::CovenantRequestFulfilled {
                                details: request_fulfilled,
                                sender_id: self.build_context.own_index(),
                                destination_id: sender_id,
                            })
                            .expect("should be able to send through the covenant signal sender");

                        requests_served.insert(sender_id);

                        if requests_served.len() == num_signers {
                            info!(event = "all nonces requests served", %deposit_txid, %own_index);
                        }
                    } else {
                        warn!(
                            %own_index, %sender_id,
                            "should not be receiving signature request in listener for signatures",
                        );
                    }
                }
                CovenantSignal::CovenantRequestFulfilled {
                    details,
                    sender_id,
                    destination_id,
                } => {
                    info!(event = "received covenant fulfillment data for nonce", %deposit_txid, %sender_id, %destination_id, %own_index);

                    if destination_id != own_index {
                        // ignore messages meant for others
                        continue;
                    }

                    if let RequestFulfilled::Nonce {
                        pre_assert,
                        post_assert,
                        disprove,
                        payout_0,
                        payout_1,
                    } = details
                    {
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

                            all_done = all_done
                                && self
                                    .db
                                    .collected_pubnonces(txid, input_index)
                                    .await
                                    .is_some_and(|v| v.len() == num_signers);
                        }

                        self_requests_fulfilled = all_done;
                        if self_requests_fulfilled {
                            info!(event = "nonce requests fulfilled", %own_index);
                        }
                    } else {
                        warn!(
                        %own_index, %sender_id,
                        "should not be receiving signature request fulfillment data in listener for signatures");
                    };
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
        self.covenant_signal_sender
            .send(CovenantSignal::CovenantRequest {
                details: Request::Signature {
                    agg_nonces: agg_nonces.clone(),
                    peg_out_graph_input: self_peg_out_graph_input,
                },
                sender_id: self.build_context.own_index(),
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

        let all_inputs = post_assert.witnesses().len();
        self.compute_agg_sig(
            &key_agg_ctx,
            all_inputs,
            post_assert,
            vec![agg_nonces.post_assert; all_inputs].as_ref(),
        )
        .await;

        self.compute_agg_sig(
            &key_agg_ctx,
            all_inputs,
            payout_tx,
            &[agg_nonces.payout_0, agg_nonces.payout_1],
        )
        .await;

        let all_inputs = disprove_tx.witnesses().len();
        self.compute_agg_sig(
            &key_agg_ctx,
            1,
            disprove_tx,
            vec![agg_nonces.disprove; all_inputs].as_ref(),
        )
        .await;
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
    ) -> RequestFulfilled {
        let own_index = self.build_context.own_index();

        let key_agg_ctx = KeyAggContext::new(self.build_context.pubkey_table().0.values().copied())
            .expect("should be able to create key agg ctx");

        let all_inputs = pre_assert.witnesses().len();
        trace!(action = "signing pre-assert tx partially", %operator_index);
        let pre_assert_partial_sigs = self
            .sign_partial(
                &key_agg_ctx,
                TapSighashType::All,
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
                TapSighashType::All,
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
                TapSighashType::All,
                all_inputs,
                own_index,
                operator_index,
                payout_tx,
                &[agg_nonces.payout_0, agg_nonces.payout_1],
            )
            .await;

        trace!(action = "signing disprove tx partially", %operator_index);
        let all_inputs = disprove_tx.witnesses().len();
        let disprove_partial_sigs = self
            .sign_partial(
                &key_agg_ctx,
                TapSighashType::Single,
                1,
                own_index,
                operator_index,
                disprove_tx,
                vec![agg_nonces.disprove; all_inputs].as_ref(),
            )
            .await;

        RequestFulfilled::Signature {
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

        while let Ok(msg) = self.covenant_signal_receiver.recv().await {
            if self_requests_fulfilled && requests_served.len() == num_signers {
                info!(event = "all signature requests fulfilled and served", %deposit_txid, requests_served = %requests_served.len(), %own_index);

                return;
            }

            match msg {
                CovenantSignal::CovenantRequest { details, sender_id } => {
                    if sender_id == own_index {
                        info!(event = "ignored self request for signatures", %deposit_txid, %own_index);
                        continue;
                    }

                    // fulfill request
                    if let Request::Signature {
                        agg_nonces,
                        peg_out_graph_input,
                    } = details
                    {
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
                        )
                        .await;
                        let AssertChain {
                            pre_assert,
                            assert_data: _,
                            post_assert,
                        } = assert_chain;

                        info!(action = "fulfilling covenant request for signatures", %deposit_txid, %sender_id, %own_index );
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
                        self.covenant_signal_sender
                            .send(CovenantSignal::CovenantRequestFulfilled {
                                details: request_fulfilled,
                                sender_id: own_index,
                                destination_id: sender_id,
                            })
                            .expect("should be able to send through the covenant signal sender");

                        requests_served.insert(sender_id);

                        if requests_served.len() == num_signers {
                            info!(event = "all nonces requests served", %deposit_txid, %own_index);
                        }
                    } else {
                        warn!(
                        %own_index, %sender_id,
                        "should not be receiving nonce request in listener for signatures");
                    }
                }
                CovenantSignal::CovenantRequestFulfilled {
                    details,
                    sender_id,
                    destination_id,
                } => {
                    if destination_id != own_index {
                        // ignore messages meant for others
                        continue;
                    }

                    if let RequestFulfilled::Signature {
                        pre_assert,
                        post_assert,
                        disprove,
                        payout,
                    } = details
                    {
                        info!(event = "received covenant fulfillment data for signature", %deposit_txid, %sender_id, %own_index );

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
                                        .is_some_and(|v| v.1.len() == num_signers);
                            }
                        }

                        self_requests_fulfilled = all_done;
                        if self_requests_fulfilled {
                            info!(event = "all signature requests fulfilled", %own_index);
                        }
                    } else {
                        warn!(
                        %own_index, %sender_id,
                        "should not be receiving nonce request fulfillment data in listener for signatures");
                    };
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

        let expected_nonce_count = self.build_context.pubkey_table().0.len();
        while let Ok(deposit_signal) = self.deposit_signal_receiver.recv().await {
            if let DepositSignal::Nonce {
                txid,
                pubnonce,
                sender_id,
            } = deposit_signal
            {
                if sender_id == own_index {
                    continue;
                }

                info!(event = "received nonce for deposit sweeping", deposit_txid=%txid, %own_index, %sender_id);
                self.db.add_pubnonce(txid, 0, sender_id, pubnonce).await;

                if let Some(collected_nonces) = self.db.collected_pubnonces(txid, 0).await {
                    if collected_nonces.len() != expected_nonce_count {
                        continue;
                    }

                    info!(event = "received nonce for deposit sweeping", deposit_txid=%txid, %own_index, %sender_id);
                    return Some(collected_nonces.values().sum());
                }
            } else {
                // ignore signatures in this function
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

        let mut tx = tx_signing_data.psbt.unsigned_tx.clone();
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
            .secnonce(txid, 0)
            .await
            .expect("secnonce should exist before adding signatures");

        info!(action = "generating one's own signature for deposit sweeping", deposit_txid=%txid, operator_idx=%own_index);

        let mut sighash_cache = SighashCache::new(&mut tx);
        let message = create_message_hash(
            &mut sighash_cache,
            prevouts,
            &tx_signing_data.spend_path,
            TapSighashType::All,
            0,
        )
        .expect("should be able to create message hash");
        let message = message.as_ref();

        let partial_signature = sign_partial(&key_agg_ctx, seckey, secnonce, &agg_nonce, message)
            .expect("should be able to sign deposit");
        self.db
            .add_partial_signature(txid, 0, own_index, partial_signature)
            .await;

        info!(action = "broadcasting one's own signature for deposit sweeping", deposit_txid=%txid, operator_idx=%own_index);
        self.deposit_signal_sender
            .send(DepositSignal::Signature {
                txid,
                signature: partial_signature,
                sender_id: own_index,
            })
            .expect("should be ableto send signature");

        info!(action = "listening for signatures for deposit sweeping", deposit_txid=%txid, operator_idx=%own_index);

        let expected_signature_count = self.build_context.pubkey_table().0.len();
        while let Ok(deposit_signal) = self.deposit_signal_receiver.recv().await {
            if let DepositSignal::Signature {
                txid,
                signature,
                sender_id,
            } = deposit_signal
            {
                if sender_id == own_index {
                    continue;
                }

                // TODO: add signature verification logic in prod
                // for now, this is fine because musig2 validates every signature during generation.
                self.db
                    .add_partial_signature(txid, 0, sender_id, signature)
                    .await;

                if let Some(collected_signatures) =
                    self.db.collected_signatures_per_msg(txid, 0).await
                {
                    if collected_signatures.1.len() != expected_signature_count {
                        continue;
                    }

                    let agg_signature: Signature = aggregate_partial_signatures(
                        &key_agg_ctx,
                        &agg_nonce,
                        collected_signatures.1.values().copied(),
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
                            agg_signature.serialize().to_vec(),
                            script_buf.to_bytes(),
                            control_block.serialize(),
                        ];
                        finalize_input(&mut tx_signing_data.psbt.inputs[0], witnesses);

                        let signed_tx = tx_signing_data
                            .psbt
                            .clone()
                            .extract_tx()
                            .expect("should be able to extract fully signed tx");
                        info!(event = "deposit transaction fully signed and ready for broadcasting", deposit_txid=%txid, operator_idx=%own_index);

                        return Some(signed_tx);
                    } else {
                        unreachable!("deposit request should have a script spend path");
                    };
                }
            } else {
                // ignore nonces in this function
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
    async fn sign_partial(
        &self,
        key_agg_ctx: &KeyAggContext,
        sighash_type: TapSighashType,
        inputs_to_sign: usize,
        own_index: OperatorIdx,
        operator_index: OperatorIdx,
        covenant_tx: impl CovenantTx,
        agg_nonces: &[AggNonce],
    ) -> Vec<PartialSignature> {
        let mut tx = covenant_tx.psbt().unsigned_tx.clone();
        let txid = tx.compute_txid();

        let prevouts = covenant_tx.prevouts();
        let witnesses = covenant_tx.witnesses();

        let mut sighash_cache = SighashCache::new(&mut tx);

        let mut partial_sigs: Vec<PartialSignature> = Vec::with_capacity(witnesses.len());
        for (input_index, (agg_nonce, witness)) in agg_nonces
            .iter()
            .zip(witnesses)
            .enumerate()
            .take(inputs_to_sign)
        {
            let message = create_message_hash(
                &mut sighash_cache,
                prevouts.clone(),
                witness,
                sighash_type,
                input_index,
            )
            .expect("should be able to create a message hash");
            let message = message.as_ref();

            let secnonce = if let Some(secnonce) = self.db.secnonce(txid, input_index as u32).await
            {
                secnonce
            } else {
                // use the first secnonce if the given input_index does not exist
                // this is the case for post_assert inputs (but not for payout)
                self.db
                    .secnonce(txid, 0)
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
                .put_signature(
                    self.build_context.own_index(),
                    txid,
                    input_index as u32,
                    agg_sig,
                )
                .await;
        }
    }
}
