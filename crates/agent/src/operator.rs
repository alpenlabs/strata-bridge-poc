use std::{collections::BTreeMap, sync::Arc};

use musig2::{KeyAggContext, PartialSignature};
use secp256k1::{PublicKey, XOnlyPublicKey};
use strata_bridge_db::operator::OperatorDb;
use strata_state::bridge_duties::BridgeDuty;

use crate::base::Agent;

pub type OperatorIdx = u32;

#[derive(Debug, Clone)]
pub struct Operator {
    pub agent: Agent,

    own_index: OperatorIdx,

    n_of_n_agg_pubkey: XOnlyPublicKey,

    #[allow(dead_code)] // will use this during impl
    db: Arc<OperatorDb>,

    is_faulty: bool,
    // add broadcast channels
}

impl Operator {
    pub fn new(
        agent: Agent,
        pubkey_table: BTreeMap<OperatorIdx, PublicKey>,
        is_faulty: bool,
        db: Arc<OperatorDb>,
    ) -> Self {
        let own_index = *pubkey_table
            .iter()
            .find(|(_, pk)| **pk == agent.public_key())
            .expect("should be part of the pubkey table")
            .0;

        let n_of_n_agg_pubkey: PublicKey = KeyAggContext::new(pubkey_table.values().copied())
            .expect("should be able to get agg key context")
            .aggregated_pubkey();
        let (n_of_n_agg_pubkey, _) = n_of_n_agg_pubkey.x_only_public_key();

        Self {
            agent,
            own_index,
            n_of_n_agg_pubkey,
            db,
            is_faulty,
        }
    }

    pub fn own_index(&self) -> &OperatorIdx {
        &self.own_index
    }

    pub fn n_of_n_agg_pubkey(&self) -> &XOnlyPublicKey {
        &self.n_of_n_agg_pubkey
    }

    pub fn am_i_faulty(&self) -> bool {
        self.is_faulty
    }

    pub async fn process_duty(&self, _duty: BridgeDuty) {
        todo!()
    }

    pub async fn handle_deposit(&self) {
        // 1. aggregate_tx_graph
        // 2. aggregate nonces and signatures for deposit
        todo!();
    }

    pub async fn handle_withdrawal(&self) {
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
