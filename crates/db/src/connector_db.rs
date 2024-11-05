use std::fmt::Debug;

use async_trait::async_trait;
use bitcoin::Txid;
use bitvm::{groth16::g16, treepp::*};
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::{scripts::wots, types::OperatorIdx};

#[async_trait]
pub trait ConnectorDb: Clone + Debug + Send + Sync {
    async fn get_verifier_scripts(&self) -> [Script; g16::N_TAPLEAVES];

    async fn get_wots_public_keys(&self, operator_id: u32, deposit_txid: Txid) -> wots::PublicKeys;

    async fn set_wots_public_keys(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        public_keys: &wots::PublicKeys,
    );

    async fn get_wots_signatures(&self, operator_id: u32, deposit_txid: Txid) -> wots::Signatures;

    async fn set_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        signatures: &wots::Signatures,
    );

    async fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> Signature;
}
