use std::{array, collections::HashMap};

use bitcoin::Txid;
use bitcoin_script::Script;
use bitvm::groth16::g16;
use secp256k1::schnorr;
use tokio::sync::RwLock;

use super::operator::OperatorIdx;

// Assume that no node will update other nodes' data in this public db.
#[derive(Debug)]
pub struct PublicDb {
    verifier_scripts: RwLock<[Script; g16::N_TAPLEAVES]>,

    // operator_id -> deposit_txid -> WotsPublicKeys
    wots_public_keys: RwLock<HashMap<OperatorIdx, HashMap<Txid, g16::WotsPublicKeys>>>,

    // operator_id -> deposit_txid -> WotsSignatures
    wots_signatures: RwLock<HashMap<OperatorIdx, HashMap<Txid, g16::WotsSignatures>>>,

    // signature cache
    signatures: RwLock<HashMap<Txid, schnorr::Signature>>,
}

impl Default for PublicDb {
    fn default() -> Self {
        Self {
            verifier_scripts: RwLock::new(array::from_fn(|_| Script::new("init"))),
            wots_public_keys: Default::default(),
            wots_signatures: Default::default(),
            signatures: Default::default(),
        }
    }
}

impl PublicDb {
    pub async fn add_verifier_scripts(&self, verifier_scripts: &[Script; g16::N_TAPLEAVES]) {
        self.verifier_scripts
            .write()
            .await
            .clone_from(verifier_scripts);
    }

    pub async fn put_wots_public_keys(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        pubkeys: g16::WotsPublicKeys,
    ) {
        let mut wots_public_keys = self.wots_public_keys.write().await;

        if let Some(txid_to_pubkey_map) = wots_public_keys.get_mut(&operator_idx) {
            txid_to_pubkey_map.insert(txid, pubkeys);
        } else {
            let mut txid_to_pubkey_map = HashMap::new();
            txid_to_pubkey_map.insert(txid, pubkeys);

            wots_public_keys.insert(operator_idx, txid_to_pubkey_map);
        }
    }

    pub async fn get_wots_public_keys(
        &self,
        operator_idx: OperatorIdx,
    ) -> Option<HashMap<Txid, g16::WotsPublicKeys>> {
        self.wots_public_keys
            .read()
            .await
            .get(&operator_idx)
            .cloned()
    }

    pub async fn put_wots_signatures(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        signatures: g16::WotsSignatures,
    ) {
        let mut wots_signatures = self.wots_signatures.write().await;

        if let Some(txid_to_signatures_map) = wots_signatures.get_mut(&operator_idx) {
            txid_to_signatures_map.insert(txid, signatures);
        } else {
            let mut txid_to_signatures_map = HashMap::new();
            txid_to_signatures_map.insert(txid, signatures);

            wots_signatures.insert(operator_idx, txid_to_signatures_map);
        }
    }

    pub async fn get_wots_signatures(
        &self,
        operator_idx: OperatorIdx,
    ) -> Option<HashMap<Txid, g16::WotsSignatures>> {
        self.wots_signatures
            .read()
            .await
            .get(&operator_idx)
            .cloned()
    }

    pub async fn put_signature(self, txid: Txid, signature: schnorr::Signature) {
        self.signatures.write().await.insert(txid, signature);
    }

    pub async fn get_signature(self, txid: Txid) -> Option<schnorr::Signature> {
        self.signatures.read().await.get(&txid).copied()
    }
}
