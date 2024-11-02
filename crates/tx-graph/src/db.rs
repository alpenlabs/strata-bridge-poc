use bitcoin::Txid;
use bitvm::{
    groth16::g16::{self, N_TAPLEAVES},
    signatures::wots::{wots160, wots256, wots32},
    treepp::*,
};
use secp256k1::schnorr::Signature;

use crate::connectors::constants::{NUM_PKS_A160, NUM_PKS_A256};

pub trait Database {
    fn get_verifier_scripts(&self) -> Option<[Script; N_TAPLEAVES]>;

    fn get_wots_public_keys(&self, operator_id: u32, deposit_txid: Txid) -> g16::WotsPublicKeys;

    fn set_wots_public_keys(
        &mut self,
        operator_id: u32,
        deposit_txid: Txid,
        public_keys: &g16::WotsPublicKeys,
    );

    fn get_wots_signatures(&self, operator_id: u32, deposit_txid: Txid) -> g16::WotsSignatures;

    fn set_wots_signatures(
        &mut self,
        operator_id: u32,
        deposit_txid: Txid,
        signatures: &g16::WotsSignatures,
    );

    fn get_signature(&self, txid: Txid) -> Signature;
}
