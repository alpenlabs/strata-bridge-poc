use bitcoin::Txid;
use bitvm::{
    groth16::g16::{self, N_TAPLEAVES},
    treepp::*,
};
use secp256k1::schnorr::Signature;

pub trait Database {
    fn get_partial_disprove_scripts(&self) -> Option<[Script; N_TAPLEAVES]>;

    fn get_wots_public_keys(&self, operator_id: u32, deposit_txid: Txid) -> g16::PublicKeys;

    fn set_wots_public_keys(
        &mut self,
        operator_id: u32,
        deposit_txid: Txid,
        public_keys: &g16::PublicKeys,
    );

    fn get_wots_signatures(&self, operator_id: u32, deposit_txid: Txid) -> g16::Signatures;

    fn set_wots_signatures(
        &mut self,
        operator_id: u32,
        deposit_txid: Txid,
        signatures: &g16::Signatures,
    );

    fn get_signature(&self, txid: Txid) -> Signature;
}
