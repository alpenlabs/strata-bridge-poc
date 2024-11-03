use std::sync::Arc;

use bitcoin::{
    psbt::Input,
    taproot::{ControlBlock, LeafVersion},
    Address, Network, ScriptBuf, Txid,
};
use bitvm::{signatures::wots::wots256, treepp::*};
use secp256k1::XOnlyPublicKey;
use strata_bridge_db::connector_db::ConnectorDb;
use strata_bridge_primitives::scripts::prelude::*;

use crate::commitments::{
    secret_key_for_bridge_out_txid, secret_key_for_superblock_period_start_ts,
};

#[derive(Debug, Clone)]
pub struct ConnectorK<Db: ConnectorDb> {
    pub n_of_n_agg_pubkey: XOnlyPublicKey,

    pub network: Network,

    pub db: Arc<Db>,
}

impl<Db: ConnectorDb> ConnectorK<Db> {
    pub fn new(n_of_n_agg_pubkey: XOnlyPublicKey, network: Network, db: Arc<Db>) -> Self {
        Self {
            n_of_n_agg_pubkey,
            network,
            db,
        }
    }

    async fn create_locking_script(&self, deposit_txid: Txid) -> ScriptBuf {
        let ((superblock_period_start_ts_public_key, bridge_out_txid_public_key, _), _, _) =
            self.db.get_wots_public_keys(0, deposit_txid).await;

        script! {
            // superblock_period_start_timestamp
            { wots256::checksig_verify(superblock_period_start_ts_public_key) }
            for _ in 0..4 { OP_2DROP } // drop ts nibbles

            // bridge_out_tx_id
            { wots256::checksig_verify(bridge_out_txid_public_key) }
            OP_DUP OP_NOT OP_VERIFY // assert the most significant nibble is zero
            for _ in 0..32 { OP_2DROP }
        }
        .compile()
    }

    pub async fn create_taproot_address(&self, deposit_txid: Txid) -> Address {
        let scripts = &[self.create_locking_script(deposit_txid).await];

        let (taproot_address, _) =
            create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
                .expect("should be able to add scripts");

        taproot_address
    }

    pub async fn generate_spend_info(&self, deposit_txid: Txid) -> (ScriptBuf, ControlBlock) {
        let script = self.create_locking_script(deposit_txid).await;

        let (_, spend_info) = create_taproot_addr(
            &self.network,
            SpendPath::ScriptSpend {
                scripts: &[script.clone()],
            },
        )
        .expect("should be able to create taproot address");

        let control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script must be part of the address");

        (script, control_block)
    }

    pub async fn create_tx_input(
        &self,
        input: &mut Input,
        deposit_txid: Txid,
        msk: &str,
        bridge_out_txid: Txid, // starts with 0x0..
        superblock_period_start_ts: u32,
    ) {
        // 1. Create an array of witness data (`[Vec<u8>]`) `n_of_n_sig` and bitcommitments.
        // 2. Call taproot::finalize_input() to create the signed psbt input.
        // unimplemented!("call the bitvm impl to generate witness data for bitcommitments");
        let witness = script! {
            { wots256::sign(&secret_key_for_bridge_out_txid(msk), bridge_out_txid.as_ref()) }
            // pad ts bytes
            { wots256::sign(&secret_key_for_superblock_period_start_ts(msk), &superblock_period_start_ts.to_le_bytes()) }
        }.compile();

        let (script, control_block) = self.generate_spend_info(deposit_txid).await;

        finalize_input(
            input,
            [
                witness.to_bytes(),
                script.to_bytes(),
                control_block.serialize(),
            ],
        );
    }
}
