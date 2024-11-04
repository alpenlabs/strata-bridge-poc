use bitcoin::{
    psbt::Input,
    taproot::{ControlBlock, LeafVersion, TaprootSpendInfo},
    Address, Network, ScriptBuf,
};
use bitvm::{
    bn254::chunk_superblock::H256,
    hash::sha256::sha256,
    pseudo::NMUL,
    signatures::wots::{wots160, wots256, wots32},
    treepp::*,
};
use strata_bridge_db::connector_db::ConnectorDb;
use strata_bridge_primitives::{
    params::prelude::{NUM_PKS_A160, NUM_PKS_A256},
    scripts::prelude::*,
};

use crate::transactions::constants::SUPERBLOCK_PERIOD;

#[derive(Debug, Clone, Copy)]
pub struct ConnectorA31<DB: ConnectorDb> {
    network: Network,

    pub superblock_hash_public_key: wots256::PublicKey,
    pub superblock_period_start_ts_public_key: wots32::PublicKey,
    pub proof_elements_public_key: ([wots256::PublicKey; 49], [wots160::PublicKey; 598]),

    #[allow(dead_code)]
    db: DB,
}

#[derive(Debug, Clone, Copy)]
pub enum ConnectorA31Leaf {
    DisproveChain,
    InvalidateProof(usize),
}

impl<DB: ConnectorDb> ConnectorA31<DB> {
    fn extract_superblock_ts_from_header(&self) -> Script {
        script! {
            for i in 0..4 {
                { 80 - 12 + 2 * i } OP_PICK
            }
            for _ in 1..4 {
                { NMUL(1 << 8) } OP_ADD
            }
        }
    }

    pub async fn generate_tapleaf(&self, tapleaf: ConnectorA31Leaf) -> ScriptBuf {
        match tapleaf {
            ConnectorA31Leaf::DisproveChain => {
                script! {
                // committed superblock hash
                { wots256::compact::checksig_verify(self.superblock_hash_public_key) }
                { sb_hash_from_nibbles() } { H256::toaltstack() }

                // committed superblock period start timestamp
                { wots32::compact::checksig_verify(self.superblock_period_start_ts_public_key) }
                { ts_from_nibbles() } OP_TOALTSTACK

                // extract superblock timestamp from header
                { self.extract_superblock_ts_from_header() }

                // assert: 0 < sbv.ts - sb_start_ts < superblock_period
                OP_FROMALTSTACK
                OP_SUB
                OP_DUP
                0 OP_GREATERTHAN OP_VERIFY
                { SUPERBLOCK_PERIOD } OP_LESSTHAN OP_VERIFY

                // sbv.hash()
                { sha256(80) }
                { sha256(32) }
                { sb_hash_from_bytes() }

                { H256::fromaltstack() }

                // assert sb.hash < committed_sb_hash
                { H256::lessthan(1, 0) } OP_VERIFY

                OP_TRUE
                }
            }
            ConnectorA31Leaf::InvalidateProof(_tapleaf_index) => {
                // let (invalidate_proof_script, public_keys) = self
                //     .db
                //     .get_verifier_script_and_public_keys(tapleaf_index)
                //     .await;

                // let wots_script_pub_keys = public_keys.iter().map(|&public_key| match public_key
                // {     WotsPublicKeyData::SuperblockHash(public_key) => {
                //         wots256::compact::checksig_verify(public_key)
                //     }
                //     WotsPublicKeyData::SuperblockPeriodStartTs(public_key) => {
                //         wots32::compact::checksig_verify(public_key)
                //     }
                //     WotsPublicKeyData::BridgeOutTxid(public_key) => {
                //         wots256::compact::checksig_verify(public_key)
                //     }
                //     WotsPublicKeyData::ProofElement160(public_key) => {
                //         wots160::compact::checksig_verify(public_key)
                //     }
                //     WotsPublicKeyData::ProofElement256(public_key) => {
                //         wots256::compact::checksig_verify(public_key)
                //     }
                // });

                script! {
                    // for script in wots_script_pub_keys {
                    //     { script }
                    // }
                    // { invalidate_proof_script }
                }
            }
        }
        .compile()
    }

    pub async fn generate_locking_script(&self) -> ScriptBuf {
        let (address, _) = self.generate_taproot_address().await;

        address.script_pubkey()
    }

    pub async fn generate_spend_info(
        &self,
        tapleaf: ConnectorA31Leaf,
    ) -> (ScriptBuf, ControlBlock) {
        let (_, taproot_spend_info) = self.generate_taproot_address().await;

        let script = self.generate_tapleaf(tapleaf).await;
        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script is always present in the address");

        (script, control_block)
    }

    async fn generate_taproot_address(&self) -> (Address, TaprootSpendInfo) {
        let mut scripts = vec![self.generate_tapleaf(ConnectorA31Leaf::DisproveChain).await];

        const TOTAL_SCRIPTS: usize = NUM_PKS_A160 + NUM_PKS_A256;
        let mut invalidate_proof_tapleaves = Vec::with_capacity(TOTAL_SCRIPTS);
        for i in 0..TOTAL_SCRIPTS {
            invalidate_proof_tapleaves.push(
                self.generate_tapleaf(ConnectorA31Leaf::InvalidateProof(i))
                    .await,
            );
        }

        scripts.extend(invalidate_proof_tapleaves.into_iter());

        create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts: &scripts })
            .expect("should be able to create taproot address")
    }

    pub async fn finalize_input(&self, input: &mut Input, tapleaf: ConnectorA31Leaf) {
        let (script, control_block) = self.generate_spend_info(tapleaf).await;

        let witness_script = match tapleaf {
            ConnectorA31Leaf::DisproveChain => {
                script! {}
            }
            ConnectorA31Leaf::InvalidateProof(_tapleaf_index) => {
                // let _signatures = self.db.get_verifier_disprove_signatures(tapleaf_index);

                script! {
                    // add signatures script
                    // add aux input (quotients)
                }
            }
        };

        finalize_input(
            input,
            [
                witness_script.compile().to_bytes(),
                script.to_bytes(),
                control_block.serialize(),
            ],
        );
    }
}
