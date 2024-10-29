use bitcoin::{
    opcodes::all::OP_VERIFY,
    psbt::Input,
    taproot::{ControlBlock, LeafVersion, Signature},
    Address, Network, ScriptBuf, Transaction, Txid, Witness,
};
use bitvm::{
    bridge::transactions::base::Input,
    signatures::wots::{wots256, wots32},
    treepp::*,
};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

use crate::{
    commitments::{secret_key_for_bridge_out_txid, secret_key_for_superblock_period_start_ts},
    scripts::{prelude::*, transform::ts_from_nibbles},
};

#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub struct ConnectorK {
    pub n_of_n_agg_key: XOnlyPublicKey,

    pub network: Network,

    // this needs WOTS data
    pub bridge_out_txid_public_key: wots256::PublicKey,
    pub superblock_period_start_ts_public_key: wots32::PublicKey,
}

impl ConnectorK {
    fn create_locking_script(&self) -> ScriptBuf {
        script! {
            // superblock_period_start_timestamp
            { wots32::checksig_verify(self.superblock_period_start_ts_public_key) }
            for _ in 0..4 { OP_2DROP } // drop ts nibbles

            // bridge_out_tx_id
            { wots256::checksig_verify(self.bridge_out_txid_public_key) }
            OP_DUP OP_NOT OP_VERIFY // assert the most significant nibble is zero
            for _ in 0..32 { OP_2DROP }
        }
    }

    pub fn create_taproot_address(&self) -> Address {
        let scripts = &[self.create_locking_script()];

        let (taproot_address, _) =
            create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
                .expect("should be able to add scripts");

        taproot_address
    }

    pub fn generate_spend_info(&self) -> (ScriptBuf, ControlBlock) {
        let script = self.create_locking_script();

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

    pub fn create_tx_input<'input>(
        &self,
        input: &'input mut Input,
        msk: &str,
        bridge_out_txid: Txid, // starts with 0x0..
        superblock_period_start_ts: u32,
    ) -> &'input Input {
        // 1. Create an array of witness data (`[Vec<u8>]`) `n_of_n_sig` and bitcommitments.
        // 2. Call taproot::finalize_input() to create the signed psbt input.
        // unimplemented!("call the bitvm impl to generate witness data for bitcommitments");
        let witness = script! {
            { wots256::sign(&secret_key_for_bridge_out_txid(msk), bridge_out_txid.as_ref()) }

            { wots32::sign(&secret_key_for_superblock_period_start_ts(msk), &superblock_period_start_ts.to_le_bytes()) }
        }.compile();

        let (script, control_block) = self.generate_spend_info();

        finalize_input(
            input,
            [
                witness.to_bytes(),
                script.to_bytes(),
                control_block.serialize(),
            ],
        );

        input
    }
}
