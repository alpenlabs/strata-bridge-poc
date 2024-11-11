use std::collections::{BTreeMap, HashSet};

use async_trait::async_trait;
use bitcoin::{Amount, OutPoint, TxOut, Txid};
use musig2::{PartialSignature, PubNonce, SecNonce};
use strata_bridge_primitives::{bitcoin::BitcoinAddress, types::OperatorIdx};

pub type MsgHashAndOpIdToSigMap = (Vec<u8>, BTreeMap<OperatorIdx, PartialSignature>);

#[derive(Debug, Clone)]
pub struct KickoffInfo {
    pub funding_inputs: Vec<OutPoint>,
    pub funding_utxos: Vec<TxOut>,
    pub change_address: BitcoinAddress,
    pub change_amt: Amount,
}

#[async_trait]
pub trait OperatorDb {
    async fn add_pubnonce(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        pubnonce: PubNonce,
    );

    async fn collected_pubnonces(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> Option<BTreeMap<OperatorIdx, PubNonce>>;

    async fn add_secnonce(&self, txid: Txid, input_index: u32, secnonce: SecNonce);

    async fn get_secnonce(&self, txid: Txid, input_index: u32) -> Option<SecNonce>;

    async fn add_message_hash_and_signature(
        &self,
        txid: Txid,
        input_index: u32,
        message_sighash: Vec<u8>,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    );

    /// Adds a partial signature to the map if already present.
    async fn add_partial_signature(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    );

    async fn collected_signatures_per_msg(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> Option<MsgHashAndOpIdToSigMap>;

    async fn add_outpoint(&self, outpoint: OutPoint) -> bool;

    async fn selected_outpoints(&self) -> HashSet<OutPoint>;

    async fn add_kickoff_info(&self, deposit_txid: Txid, kickoff_info: KickoffInfo);

    async fn get_kickoff_info(&self, deposit_txid: Txid) -> Option<KickoffInfo>;
}
