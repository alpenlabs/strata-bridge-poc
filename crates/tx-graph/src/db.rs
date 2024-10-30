use bitvm::{
    signatures::wots::{wots160, wots256, wots32},
    treepp::*,
};

pub struct WotsPublicKeys {
    superblock_hash: wots256::PublicKey,
    superblock_period_start_ts: wots256::PublicKey,
    bridge_out_txid: wots256::PublicKey,
    proof_elements_160: [wots160::PublicKey; 598],
    proof_elements_256: [wots160::PublicKey; 598],
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
    fn get_verifier_script_and_public_keys(
        &self,
        tapleaf_index: usize,
    ) -> (Script, Vec<WotsPublicKeyData>);

    fn get_verifier_disprove_signatures(&self, tapleaf_index: usize) -> Vec<WotsSignatureData>;
}
