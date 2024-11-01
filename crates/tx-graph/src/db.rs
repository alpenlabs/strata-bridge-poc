use bitcoin::Txid;
use bitvm::{
    signatures::wots::{wots160, wots256, wots32},
    treepp::*,
};
use secp256k1::schnorr::Signature;

use crate::connectors::constants::{NUM_PKS_A160, NUM_PKS_A256};

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct WotsPublicKeys {
    superblock_hash: wots256::PublicKey,
    superblock_period_start_ts: wots256::PublicKey,
    bridge_out_txid: wots256::PublicKey,
    proof_elements_160: [wots160::PublicKey; 598],
    proof_elements_256: [wots160::PublicKey; 49],
}

// struct Database {
//     invalidate_proof_scripts: Vec<Script>,

//     wots_public_keys: HashMap<u32, HashMap<TxId, WotsPublicKeys>>

// }

// impl Database {
//     fn get_groth16_validation_script(&self, index: usize) -> (Script, Vec<WotsPublicKeyData>) {
//         self.groth16_scripts[index]
//     }

// }

#[derive(Debug, Clone, Copy)]
pub enum WotsSignatureData {
    SuperblockHash([[u8; 20]; 67], [u8; 67]),
    SuperblockPeriodStartTs(wots32::PublicKey),
    BridgeOutTxid(wots256::PublicKey),
    ProofElement160(wots160::PublicKey),
    ProofElement256(wots256::PublicKey),
}

#[derive(Debug, Clone, Copy)]
pub enum WotsPublicKeyData {
    SuperblockHash(wots256::PublicKey),
    SuperblockPeriodStartTs(wots32::PublicKey),
    BridgeOutTxid(wots256::PublicKey),
    ProofElement160(wots160::PublicKey),
    ProofElement256(wots256::PublicKey),
}

pub trait Database {
    fn get_bridge_out_txid_public_key(&self) -> wots256::PublicKey;

    fn get_superblock_period_start_ts_public_key(&self) -> wots32::PublicKey;

    fn get_proof_elements_160(&self) -> [(u32, wots160::PublicKey); NUM_PKS_A160];

    fn get_proof_elements_256(&self) -> [(u32, wots256::PublicKey); NUM_PKS_A256];

    fn get_verifier_script_and_public_keys(
        &self,
        tapleaf_index: usize,
    ) -> (Script, Vec<WotsPublicKeyData>);

    fn get_verifier_disprove_signatures(&self, tapleaf_index: usize) -> Vec<WotsSignatureData>;

    fn get_signature(&self, txid: Txid) -> Signature;
}
