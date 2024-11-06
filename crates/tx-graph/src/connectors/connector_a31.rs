use bitcoin::{
    psbt::Input,
    taproot::{ControlBlock, LeafVersion, TaprootSpendInfo},
    Address, Network, ScriptBuf, Txid,
};
use bitvm::{
    bn254::chunk_superblock::H256,
    groth16::g16,
    hash::sha256::sha256,
    pseudo::NMUL,
    signatures::wots::{wots256, wots32, SignatureImpl},
    treepp::*,
};
use strata_bridge_db::connector_db::ConnectorDb;
use strata_bridge_primitives::{
    params::prelude::{NUM_PKS_A160, NUM_PKS_A256},
    scripts::{prelude::*, wots},
};
use tracing::trace;

use crate::transactions::constants::SUPERBLOCK_PERIOD;

#[derive(Debug, Clone)]
pub struct ConnectorA31<DB: ConnectorDb> {
    network: Network,

    db: DB,
}

#[derive(Debug, Clone)]
#[expect(clippy::large_enum_variant)]
pub enum ConnectorA31Leaf {
    InvalidateProof((usize, Option<Script>)),
    DisproveChain(Option<(wots256::Signature, wots32::Signature, [u8; 80])>),
    InvalidatePublicDataHash(
        Option<(
            wots256::Signature,
            wots256::Signature,
            wots32::Signature,
            wots256::Signature,
        )>,
    ),
}

impl<DB: ConnectorDb> ConnectorA31<DB> {
    pub fn new(network: Network, db: DB) -> Self {
        Self { network, db }
    }

    pub async fn generate_tapleaf(
        &self,
        tapleaf: ConnectorA31Leaf,
        deposit_txid: Txid,
    ) -> ScriptBuf {
        let wots::PublicKeys {
            bridge_out_txid: bridge_out_txid_public_key,
            superblock_hash: superblock_hash_public_key,
            superblock_period_start_ts: superblock_period_start_ts_public_key,
            groth16: ([public_inputs_hash_public_key], _, _),
        } = self.db.get_wots_public_keys(0, deposit_txid).await;

        fn extract_superblock_ts_from_header() -> Script {
            script! {
                for i in 0..4 { { 80 - 12 + 2 * i } OP_PICK }
                for _ in 1..4 {  { NMUL(1 << 8) } OP_ADD }
            }
        }

        fn add_bincode_padding_bytes32() -> Script {
            script! {
                for b in [0; 7] { {b} } 32
            }
        }

        fn hash_to_bn254_fq() -> Script {
            script! {
                for i in 1..=3 {
                    { 1 << (8 - i) }
                    OP_2DUP
                    OP_GREATERTHAN
                    OP_IF OP_SUB
                    OP_ELSE OP_DROP
                    OP_ENDIF
                }
            }
        }

        match tapleaf {
            ConnectorA31Leaf::DisproveChain(_) => {
                script! {
                // committed superblock hash
                { wots256::compact::checksig_verify(superblock_hash_public_key) }
                { sb_hash_from_nibbles() } { H256::toaltstack() }

                // committed superblock period start timestamp
                { wots32::compact::checksig_verify(superblock_period_start_ts_public_key) }
                { ts_from_nibbles() } OP_TOALTSTACK

                // extract superblock timestamp from header
                extract_superblock_ts_from_header

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
            ConnectorA31Leaf::InvalidatePublicDataHash(_) => {
                script! {
                    { wots256::checksig_verify(superblock_hash_public_key) }
                    for _ in 0..32 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }

                    { wots256::checksig_verify(bridge_out_txid_public_key) }
                    for _ in 0..32 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }

                    { wots32::checksig_verify(superblock_period_start_ts_public_key) }
                    for _ in 0..4 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }

                    { wots256::checksig_verify(public_inputs_hash_public_key) }
                    for _ in 0..32 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }

                    for _ in 0..32 { OP_FROMALTSTACK }
                    for _ in 0..4 { OP_FROMALTSTACK }
                    for _ in 0..32 { OP_FROMALTSTACK } add_bincode_padding_bytes32
                    for _ in 0..32 { OP_FROMALTSTACK } add_bincode_padding_bytes32

                    { sha256(84) }
                    hash_to_bn254_fq

                    // verify that hashes don't match
                    for i in (1..32).rev() {
                        {i + 1} OP_ROLL OP_EQUAL OP_TOALTSTACK
                    }
                    OP_EQUAL
                    for _ in 1..32 { OP_FROMALTSTACK OP_BOOLAND }
                    OP_NOT
                }
            }
            ConnectorA31Leaf::InvalidateProof((disprove_script_index, _)) => {
                let partial_disprove_scripts = &self.db.get_partial_disprove_scripts().await;
                let public_keys = self.db.get_wots_public_keys(0, deposit_txid).await.groth16;
                let disprove_scripts =
                    g16::generate_disprove_scripts(public_keys, partial_disprove_scripts);
                disprove_scripts[disprove_script_index].clone()
            }
        }
        .compile()
    }

    pub async fn generate_locking_script(&self, deposit_txid: Txid) -> ScriptBuf {
        let (address, _) = self.generate_taproot_address(deposit_txid).await;

        address.script_pubkey()
    }

    pub async fn generate_spend_info(
        &self,
        tapleaf: ConnectorA31Leaf,
        deposit_txid: Txid,
    ) -> (ScriptBuf, ControlBlock) {
        let (_, taproot_spend_info) = self.generate_taproot_address(deposit_txid).await;

        let script = self.generate_tapleaf(tapleaf, deposit_txid).await;
        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script is always present in the address");

        (script, control_block)
    }

    async fn generate_taproot_address(&self, deposit_txid: Txid) -> (Address, TaprootSpendInfo) {
        trace!(action = "generating disprove chain and invalidate public data leaves");
        let mut scripts = vec![
            self.generate_tapleaf(ConnectorA31Leaf::DisproveChain(None), deposit_txid)
                .await,
            self.generate_tapleaf(
                ConnectorA31Leaf::InvalidatePublicDataHash(None),
                deposit_txid,
            )
            .await,
        ];
        trace!(event = "generated disprove chain and invalidate public data leaves");

        const TOTAL_SCRIPTS: usize = NUM_PKS_A160 + NUM_PKS_A256;
        trace!(action = "generating invalidate proof leaves", %TOTAL_SCRIPTS);
        let mut invalidate_proof_tapleaves = Vec::with_capacity(TOTAL_SCRIPTS);
        for i in 0..TOTAL_SCRIPTS {
            invalidate_proof_tapleaves.push(
                self.generate_tapleaf(ConnectorA31Leaf::InvalidateProof((i, None)), deposit_txid)
                    .await,
            );
        }
        trace!(event = "generated invalidate proof leaves");

        scripts.extend(invalidate_proof_tapleaves.into_iter());

        trace!(action = "create taproot address");
        create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts: &scripts })
            .expect("should be able to create taproot address")
    }

    pub async fn finalize_input(
        &self,
        input: &mut Input,
        tapleaf: ConnectorA31Leaf,
        deposit_txid: Txid,
    ) {
        let (script, control_block) = self
            .generate_spend_info(tapleaf.clone(), deposit_txid)
            .await;

        let witness_script = match tapleaf {
            ConnectorA31Leaf::DisproveChain(Some((
                sig_superblock_hash,
                sig_superblock_period_start_ts,
                raw_superblock_header_bytes,
            ))) => {
                script! {
                    { raw_superblock_header_bytes.to_vec() }
                    { sig_superblock_period_start_ts.to_compact_script() }
                    { sig_superblock_hash.to_compact_script() }
                }
            }
            ConnectorA31Leaf::InvalidatePublicDataHash(Some((
                sig_superblock_hash,
                sig_bridge_out_txid,
                sig_superblock_period_start_ts,
                sig_public_inputs_hash,
            ))) => {
                script! {
                    { sig_public_inputs_hash.to_compact_script() }
                    { sig_superblock_period_start_ts.to_compact_script() }
                    { sig_bridge_out_txid.to_compact_script() }
                    { sig_superblock_hash.to_compact_script() }
                }
            }
            ConnectorA31Leaf::InvalidateProof((_, Some(witness_script))) => witness_script,
            _ => panic!("no data provided to finalize input"),
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
