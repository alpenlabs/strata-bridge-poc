use std::{
    collections::{BTreeMap, HashMap},
    fs,
    sync::Arc,
};

use async_trait::async_trait;
use bitcoin::{ScriptBuf, Txid};
use bitvm::{
    groth16::g16::{self, N_TAPLEAVES},
    treepp::{script, Script},
};
use secp256k1::{schnorr::Signature, PublicKey};
use strata_bridge_primitives::scripts::wots::{self, bridge_poc_verification_key};
use tokio::sync::RwLock;
use tracing::{info, trace};

use super::operator::OperatorIdx;
use crate::{connector_db::ConnectorDb, constants::VK_SCRIPTS_FILE};

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
        let verifier_scripts: [Script; N_TAPLEAVES] = if fs::exists(VK_SCRIPTS_FILE)
            .expect("should be able to check for existence of verifier scripts file")
        {
            info!(
                action = "loading verifier script from file cache...this will take some time",
                estimated_time = "3 mins"
            );

            let contents: Vec<u8> = fs::read(VK_SCRIPTS_FILE)
                .expect("should be able to read verifier scripts from file");
            let deserialized: Vec<Vec<u8>> = bincode::deserialize(&contents)
                .expect("should be able to deserialize verifier scripts from file");

            let verifier_scripts = deserialized
                .iter()
                .map(|de| script!().push_script(ScriptBuf::from_bytes(de.to_vec())))
                .collect::<Vec<Script>>();

            let num_scripts = verifier_scripts.len();
            info!(event = "loaded verifier scripts", %num_scripts);

            verifier_scripts.try_into().unwrap_or_else(|_| {
                panic!("number of scripts should be: {N_TAPLEAVES} not {num_scripts}",)
            })
        } else {
            info!(
                action = "compiling verifier scripts, this will take time...",
                estimated_time = "3 mins"
            );

            let verifier_scripts = g16::compile_verifier(bridge_poc_verification_key());

            let serialized: Vec<Vec<u8>> = verifier_scripts
                .clone()
                .into_iter()
                .map(|s| s.compile().to_bytes())
                .collect();

            let serialized: Vec<u8> = bincode::serialize(&serialized)
                .expect("should be able to serialize verifier scripts");

            info!(action = "caching verifier scripts for later", cache_file=%VK_SCRIPTS_FILE);
            fs::write(VK_SCRIPTS_FILE, serialized)
                .expect("should be able to write verifier scripts to file");

            verifier_scripts
        };

        Self {
            verifier_scripts: Arc::new(RwLock::new(verifier_scripts)),
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

    pub async fn put_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) {
        trace!(action = "trying to acquire wlock on schnorr signatures", %operator_idx, %txid);
        let mut signatures = self.signatures.write().await;
        trace!(event = "acquired wlock on schnorr signatures", %operator_idx, %txid);

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
        trace!(action = "trying to acquire wlock on wots public keys", %operator_id, %deposit_txid);
        let mut map = self.wots_public_keys.write().await;
        trace!(event = "wlock acquired on wots public keys", %operator_id, %deposit_txid);

        if let Some(op_keys) = map.get_mut(&operator_id) {
            op_keys
                .insert(deposit_txid, *public_keys)
                .expect("must be able to add public keys");
        } else {
            let mut keys = HashMap::new();
            keys.insert(deposit_txid, *public_keys);

            map.insert(operator_id, keys);
        }
    }

    async fn set_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        signatures: &wots::Signatures,
    ) {
        trace!(action = "trying to acquire wlock on wots signatures", %operator_id, %deposit_txid);
        let mut map = self.wots_signatures.write().await;
        trace!(event = "wlock acquired on wots signatures", %operator_id, %deposit_txid);

        if let Some(op_keys) = map.get_mut(&operator_id) {
            op_keys
                .insert(deposit_txid, *signatures)
                .expect("must be able to add public keys");
        } else {
            let mut sigs_map = HashMap::new();
            sigs_map.insert(deposit_txid, *signatures);

            map.insert(operator_id, sigs_map);
        }
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
                panic!("operator_idx: {operator_idx} must have a signature in the database")
            })
            .get(&(txid, input_index))
            .copied()
            .unwrap_or_else(|| {
                panic!("txid: {txid} must have a signature in the database");
            })
    }
}
