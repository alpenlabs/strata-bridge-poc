use std::fmt::Debug;

use async_trait::async_trait;
use bitcoin::Txid;
use bitvm::{
    signatures::wots::{wots160, wots256, wots32},
    treepp::*,
};
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::wots::{WotsPublicKeyData, WotsSignatureData};
use strata_bridge_primitives::params::prelude::{NUM_PKS_A160, NUM_PKS_A256};

#[async_trait]
pub trait ConnectorDb: Debug + Send + Sync {
    async fn get_bridge_out_txid_public_key(&self) -> wots256::PublicKey;

    async fn get_superblock_period_start_ts_public_key(&self) -> wots32::PublicKey;

    async fn get_proof_elements_160(&self) -> [(u32, wots160::PublicKey); NUM_PKS_A160];

    async fn get_proof_elements_256(&self) -> [(u32, wots256::PublicKey); NUM_PKS_A256];

    async fn get_verifier_script_and_public_keys(
        &self,
        tapleaf_index: usize,
    ) -> (Script, Vec<WotsPublicKeyData>);

    async fn get_verifier_disprove_signatures(
        &self,
        tapleaf_index: usize,
    ) -> Vec<WotsSignatureData>;

    async fn get_signature(&self, txid: Txid) -> Signature;
}
