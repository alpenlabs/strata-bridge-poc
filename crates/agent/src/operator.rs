use std::sync::Arc;

use musig2::PartialSignature;
use strata_bridge_db::{operator::OperatorDb, public::PublicDb};
use strata_bridge_primitives::{
    build_context::{BuildContext, TxBuildContext, TxKind},
    deposit::DepositInfo,
    duties::BridgeDuty,
    params::prelude::{BRIDGE_DENOMINATION, MIN_RELAY_FEE, OPERATOR_STAKE},
    signal::Signal,
    withdrawal::WithdrawalInfo,
};
use strata_bridge_tx_graph::{
    peg_out_graph::{PegOutGraph, PegOutGraphConnectors, PegOutGraphInput},
    transactions::prelude::KickoffTxData,
};
use tokio::sync::broadcast;
use tracing::info;

use crate::base::Agent;

pub type OperatorIdx = u32;

#[derive(Debug)]
pub struct Operator {
    pub agent: Agent,

    build_context: TxBuildContext,

    #[allow(dead_code)] // will use this during impl
    db: Arc<OperatorDb>,

    public_db: Arc<PublicDb>,

    is_faulty: bool,

    #[allow(dead_code)]
    signal_sender: broadcast::Sender<Signal>,

    #[allow(dead_code)]
    signal_receiver: broadcast::Receiver<Signal>,
}

impl Operator {
    pub async fn new(
        agent: Agent,
        build_context: TxBuildContext,
        is_faulty: bool,
        db: Arc<OperatorDb>,
        public_db: Arc<PublicDb>,
        signal_sender: broadcast::Sender<Signal>,
        signal_receiver: broadcast::Receiver<Signal>,
    ) -> Self {
        Self {
            agent,
            build_context,
            db,
            public_db,
            is_faulty,
            signal_sender,
            signal_receiver,
        }
    }

    pub fn am_i_faulty(&self) -> bool {
        self.is_faulty
    }

    pub async fn process_duty(&self, duty: BridgeDuty) {
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

    pub async fn handle_deposit(&self, deposit_info: DepositInfo) {
        // 1. aggregate_tx_graph
        let reserved_outpoints = self.db.selected_outpoints().await;
        let (change_address, funding_input, total_amount) = self
            .agent
            .select_utxo(OPERATOR_STAKE, reserved_outpoints)
            .await
            .expect("should be able to get outpoints");

        self.db.add_outpoint(funding_input).await;

        let deposit_tx = deposit_info
            .construct_signing_data(&self.build_context)
            .expect("should be able to create build context");
        let deposit_txid = deposit_tx.psbt.unsigned_tx.compute_txid();

        let peg_out_graph_input = PegOutGraphInput {
            network: self.build_context.network(),
            deposit_amount: BRIDGE_DENOMINATION,
            operator_pubkey: self.agent.public_key().x_only_public_key().0,
            kickoff_data: KickoffTxData {
                funding_inputs: vec![funding_input],
                change_address: change_address.as_unchecked().clone(),
                change_amt: total_amount - OPERATOR_STAKE - MIN_RELAY_FEE,
                deposit_txid,
            },
        };

        let connectors =
            PegOutGraphConnectors::new(self.public_db.clone(), &self.build_context, deposit_txid)
                .await;

        let _peg_out_graph =
            PegOutGraph::generate(peg_out_graph_input, deposit_txid, connectors).await;

        // 2. aggregate nonces and signatures for deposit
        todo!();
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

    pub async fn aggregate_tx_graph(&self) {
        // create connectors
        // create tx graph
        // update public data db with info required to create this operator's tx graph
        // signal others
        // wait for others to publish theirs
        // exchange nonces and signatures
        // end when all tx_graphs and signatures have been collected and published
        todo!()
    }

    pub async fn aggregate_nonces(&self) {
        todo!()
    }

    pub async fn aggregate_signatures(&self) {
        todo!()
    }

    pub async fn sign_partial(&self) -> PartialSignature {
        todo!()
    }
}
