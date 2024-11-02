use std::collections::HashMap;

use bitcoin::{secp256k1::schnorr, Txid};
use bitvm::{groth16::g16, treepp::*};
use strata_bridge_tx_graph::db::Database;

use super::generate_verifier_partial_scripts;

pub struct BridgeDb {
    verifier_scripts: [Script; g16::N_TAPLEAVES],

    // operator_id -> deposit_txid -> WotsPublicKeys
    wots_public_keys: HashMap<u32, HashMap<Txid, g16::WotsPublicKeys>>,

    // operator_id -> deposit_txid -> WotsSignatures
    wots_signatures: HashMap<u32, HashMap<Txid, g16::WotsSignatures>>,

    // signature cache
    signatures: HashMap<Txid, schnorr::Signature>,
}

impl Default for BridgeDb {
    fn default() -> Self {
        Self {
            verifier_scripts: generate_verifier_partial_scripts(),
            wots_public_keys: HashMap::new(),
            wots_signatures: HashMap::new(),
            signatures: HashMap::new(),
        }
    }
}

impl Database for BridgeDb {
    fn get_verifier_scripts(&self) -> Option<[Script; g16::N_TAPLEAVES]> {
        Some(self.verifier_scripts.clone())
    }

    fn get_wots_public_keys(&self, operator_id: u32, deposit_txid: Txid) -> g16::WotsPublicKeys {
        *self
            .wots_public_keys
            .get(&operator_id)
            .unwrap()
            .get(&deposit_txid)
            .unwrap()
    }

    fn get_wots_signatures(&self, operator_id: u32, deposit_txid: Txid) -> g16::WotsSignatures {
        *self
            .wots_signatures
            .get(&operator_id)
            .unwrap()
            .get(&deposit_txid)
            .unwrap()
    }

    fn set_wots_public_keys(
        &mut self,
        operator_id: u32,
        deposit_txid: Txid,
        public_keys: &g16::WotsPublicKeys,
    ) {
        self.wots_public_keys
            .get_mut(&operator_id)
            .unwrap()
            .insert(deposit_txid, *public_keys)
            .unwrap();
    }

    fn set_wots_signatures(
        &mut self,
        operator_id: u32,
        deposit_txid: Txid,
        signatures: &g16::WotsSignatures,
    ) {
        self.wots_signatures
            .get_mut(&operator_id)
            .unwrap()
            .insert(deposit_txid, *signatures)
            .unwrap();
    }

    fn get_signature(&self, txid: Txid) -> schnorr::Signature {
        *self.signatures.get(&txid).unwrap()
    }
}
