use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use async_trait::async_trait;
use bitcoin::Txid;
use bitcoin_script::Script;
use bitvm::groth16::g16::{self};
use secp256k1::{schnorr::Signature, PublicKey};
use strata_bridge_primitives::scripts::wots::{self, bridge_poc_verification_key};
use tokio::sync::RwLock;

use super::operator::OperatorIdx;
use crate::connector_db::ConnectorDb;

pub type TxInputToSignatureMap = HashMap<(Txid, u32), Signature>;
pub type OperatorIdxToTxInputSigMap = HashMap<OperatorIdx, TxInputToSignatureMap>;

// Assume that no node will update other nodes' data in this public db.
#[derive(Debug, Clone)]
pub struct PublicDb {
    musig_pubkey_table: Arc<RwLock<BTreeMap<OperatorIdx, PublicKey>>>,

    verifier_scripts: Arc<RwLock<[Script; g16::N_TAPLEAVES]>>,

    // operator_id -> deposit_txid -> WotsPublicKeys
    wots_public_keys: Arc<RwLock<HashMap<OperatorIdx, HashMap<Txid, wots::PublicKeys>>>>,

    // operator_id -> deposit_txid -> WotsSignatures
    wots_signatures: Arc<RwLock<HashMap<OperatorIdx, HashMap<Txid, wots::Signatures>>>>,

    // signature cache per txid and input index per operator
    signatures: Arc<RwLock<OperatorIdxToTxInputSigMap>>,
}

impl Default for PublicDb {
    fn default() -> Self {
        Self {
            verifier_scripts: Arc::new(RwLock::new(g16::compile_verifier(
                bridge_poc_verification_key(),
            ))),
            musig_pubkey_table: Default::default(),
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
        public_keys: wots::PublicKeys,
    ) {
        let mut wots_public_keys = self.wots_public_keys.write().await;

        if let Some(txid_to_pubkey_map) = wots_public_keys.get_mut(&operator_idx) {
            txid_to_pubkey_map.insert(txid, public_keys);
        } else {
            let mut txid_to_pubkey_map = HashMap::new();
            txid_to_pubkey_map.insert(txid, public_keys);

            wots_public_keys.insert(operator_idx, txid_to_pubkey_map);
        }
    }

    pub async fn get_wots_public_keys(
        &self,
        operator_idx: OperatorIdx,
    ) -> Option<HashMap<Txid, wots::PublicKeys>> {
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
        signatures: wots::Signatures,
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
    ) -> Option<HashMap<Txid, wots::Signatures>> {
        self.wots_signatures
            .read()
            .await
            .get(&operator_idx)
            .cloned()
    }

    pub async fn put_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) {
        let mut signatures = self.signatures.write().await;

        if let Some(txid_and_input_index_to_signature) = signatures.get_mut(&operator_idx) {
            txid_and_input_index_to_signature.insert((txid, input_index), signature);
        } else {
            let mut txid_and_input_index_to_signature = HashMap::new();
            txid_and_input_index_to_signature.insert((txid, input_index), signature);

            signatures.insert(operator_idx, txid_and_input_index_to_signature);
        }
    }

    pub async fn set_musig_pubkey_table(&self, pubkey_table: &BTreeMap<OperatorIdx, PublicKey>) {
        self.musig_pubkey_table
            .write()
            .await
            .clone_from(pubkey_table);
    }

    pub async fn get_musig_pubkey_table(&self) -> BTreeMap<OperatorIdx, PublicKey> {
        self.musig_pubkey_table.read().await.clone()
    }
}

#[async_trait]
impl ConnectorDb for PublicDb {
    async fn get_partial_disprove_scripts(&self) -> [Script; g16::N_TAPLEAVES] {
        self.verifier_scripts.read().await.clone()
    }

    async fn get_wots_public_keys(&self, operator_id: u32, deposit_txid: Txid) -> wots::PublicKeys {
        *self
            .wots_public_keys
            .read()
            .await
            .get(&operator_id)
            .unwrap()
            .get(&deposit_txid)
            .unwrap()
    }

    async fn get_wots_signatures(&self, operator_id: u32, deposit_txid: Txid) -> wots::Signatures {
        *self
            .wots_signatures
            .read()
            .await
            .get(&operator_id)
            .unwrap()
            .get(&deposit_txid)
            .unwrap()
    }

    async fn set_wots_public_keys(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        public_keys: &wots::PublicKeys,
    ) {
        self.wots_public_keys
            .write()
            .await
            .get_mut(&operator_id)
            .unwrap()
            .insert(deposit_txid, *public_keys)
            .unwrap();
    }

    async fn set_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        signatures: &wots::Signatures,
    ) {
        self.wots_signatures
            .write()
            .await
            .get_mut(&operator_id)
            .unwrap()
            .insert(deposit_txid, *signatures)
            .unwrap();
    }

    async fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> Signature {
        self.signatures
            .read()
            .await
            .get(&operator_idx)
            .unwrap_or_else(|| {
                panic!("operato_idx: {operator_idx} must have a signature in the database")
            })
            .get(&(txid, input_index))
            .copied()
            .unwrap_or_else(|| {
                panic!("txid: {txid} must have a signature in the database");
            })
    }
}
