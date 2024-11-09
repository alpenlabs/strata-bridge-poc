// use std::collections::{BTreeMap, HashMap};
//
// use crate::{operator::OperatorIdx, public::{OperatorIdxToTxInputSigMap, PublicDb}};
// use bitcoin::Txid;
// use bitvm::groth16::g16;
// use secp256k1::PublicKey;
// use serde::{Serialize, Deserialize}
// use serde_json;
// use strata_bridge_primitives::scripts::wots;

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct PublicData {
//     musig_pubkey_table: BTreeMap<OperatorIdx, PublicKey>,
//
//     // operator_id -> deposit_txid -> WotsPublicKeys
//     wots_public_keys: HashMap<OperatorIdx, HashMap<Txid, wots::PublicKeys>>,
//
//     // operator_id -> deposit_txid -> WotsSignatures
//     wots_signatures: HashMap<OperatorIdx, HashMap<Txid, wots::Signatures>>,
//
//     // signature cache per txid and input index per operator
//     signatures: OperatorIdxToTxInputSigMap,
//
//     // reverse mapping
//     claim_txid_to_operator_index_and_deposit_txid: HashMap<Txid, (OperatorIdx, Txid)>,
//     post_assert_txid_to_operator_index_and_deposit_txid:
//         HashMap<Txid, (OperatorIdx, Txid)>,
// }

// pub fn dump_public_db(public_db: &PublicDb) {
//     let data_to_dump =
// }
//
// pub fn load_public_db(public_db: &PublicDb) {
//
// }
