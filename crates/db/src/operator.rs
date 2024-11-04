use std::collections::{BTreeMap, HashMap, HashSet};

use bitcoin::{OutPoint, Txid};
use musig2::{PartialSignature, PubNonce, SecNonce};
use tokio::sync::RwLock;

pub(super) type OperatorIdx = u32;

#[derive(Debug, Default)]
pub struct OperatorDb {
    /// Txid -> OperatorIdx -> PubNonce
    collected_pubnonces: RwLock<HashMap<Txid, BTreeMap<OperatorIdx, PubNonce>>>,

    /// Txid -> PubNonce
    sec_nonces: RwLock<HashMap<Txid, SecNonce>>,

    /// Txid -> OperatorIdx -> PartialSignature
    collected_signatures: RwLock<HashMap<Txid, BTreeMap<OperatorIdx, PartialSignature>>>,

    /// OutPoints that have already been used to create KickoffTx.
    selected_outpoints: RwLock<HashSet<OutPoint>>,
}

impl OperatorDb {
    pub async fn add_pubnonce(&self, txid: Txid, operator_idx: OperatorIdx, pubnonce: PubNonce) {
        let mut collected_pubnonces = self.collected_pubnonces.write().await;

        if let Some(pubnonce_table) = collected_pubnonces.get_mut(&txid) {
            pubnonce_table.insert(operator_idx, pubnonce);
        } else {
            let mut new_entry = BTreeMap::new();
            new_entry.insert(operator_idx, pubnonce);

            collected_pubnonces.insert(txid, new_entry);
        }
    }
    pub async fn collected_pubnonces(&self, txid: Txid) -> Option<BTreeMap<OperatorIdx, PubNonce>> {
        self.collected_pubnonces.read().await.get(&txid).cloned()
    }

    pub async fn add_secnonce(&self, txid: Txid, secnonce: SecNonce) {
        let mut sec_nonces = self.sec_nonces.write().await;

        sec_nonces.insert(txid, secnonce);
    }

    pub async fn secnonce(&self, txid: Txid) -> Option<SecNonce> {
        self.sec_nonces.read().await.get(&txid).cloned()
    }

    pub async fn add_partial_signature(
        &self,
        txid: Txid,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    ) {
        let mut collected_sigs = self.collected_signatures.write().await;

        if let Some(sig_table) = collected_sigs.get_mut(&txid) {
            sig_table.insert(operator_idx, signature);
        } else {
            let mut new_entry = BTreeMap::new();
            new_entry.insert(operator_idx, signature);

            collected_sigs.insert(txid, new_entry);
        }
    }

    pub async fn collected_signatures(
        &self,
        txid: Txid,
    ) -> Option<BTreeMap<OperatorIdx, PartialSignature>> {
        self.collected_signatures.read().await.get(&txid).cloned()
    }

    pub async fn add_outpoint(&self, outpoint: OutPoint) -> bool {
        self.selected_outpoints.write().await.insert(outpoint)
    }

    pub async fn selected_outpoints(&self) -> HashSet<OutPoint> {
        self.selected_outpoints.read().await.clone()
    }
}
