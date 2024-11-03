//! Builders related to building deposit-related transactions.
//!
//! Contains types, traits and implementations related to creating various transactions used in the
//! bridge-in dataflow.

use anyhow::{bail, Context};
use bitcoin::{
    key::TapTweak,
    secp256k1::SECP256K1,
    taproot::{self, ControlBlock},
    Address, Amount, OutPoint, Psbt, TapNodeHash, Transaction, TxOut,
};
use serde::{Deserialize, Serialize};

use crate::{
    bitcoin::BitcoinAddress,
    build_context::{BuildContext, TxKind},
    params::prelude::{BRIDGE_DENOMINATION, UNSPENDABLE_INTERNAL_KEY},
    scripts::{
        general::{create_tx, create_tx_ins, create_tx_outs},
        prelude::*,
        taproot::{create_taproot_addr, SpendPath, TaprootWitness},
    },
    types::TxSigningData,
};

/// The deposit information  required to create the Deposit Transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositInfo {
    /// The deposit request transaction outpoints from the users.
    deposit_request_outpoint: OutPoint,

    /// The execution layer address to mint the equivalent tokens to.
    /// As of now, this is just the 20-byte EVM address.
    el_address: Vec<u8>,

    /// The amount in bitcoins that the user is sending.
    ///
    /// This amount should be greater than the [`BRIDGE_DENOMINATION`] for the deposit to be
    /// confirmed on bitcoin. The excess amount is used as miner fees for the Deposit Transaction.
    total_amount: Amount,

    /// The hash of the take back leaf in the Deposit Request Transaction (DRT) as provided by the
    /// user in their `OP_RETURN` output.
    take_back_leaf_hash: TapNodeHash,

    /// The original taproot address in the Deposit Request Transaction (DRT) output used to
    /// sanity check computation internally i.e., whether the known information (n/n script spend
    /// path, [`static@UNSPENDABLE_INTERNAL_KEY`]) + the [`Self::take_back_leaf_hash`] yields the
    /// same P2TR address.
    original_taproot_addr: BitcoinAddress,
}

impl TxKind for DepositInfo {
    fn construct_signing_data<C: BuildContext>(
        &self,
        build_context: &C,
    ) -> anyhow::Result<TxSigningData> {
        let prevouts = self.compute_prevouts();
        let spend_info = self.compute_spend_infos(build_context)?;
        let unsigned_tx = self.create_unsigned_tx(build_context)?;

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

        for (i, input) in psbt.inputs.iter_mut().enumerate() {
            input.witness_utxo = Some(prevouts[i].clone());
        }

        Ok(TxSigningData {
            psbt,
            spend_path: spend_info,
        })
    }
}

impl DepositInfo {
    /// Create a new deposit info with all the necessary data required to create a deposit
    /// transaction.
    pub fn new(
        deposit_request_outpoint: OutPoint,
        el_address: Vec<u8>,
        total_amount: Amount,
        take_back_leaf_hash: TapNodeHash,
        original_taproot_addr: BitcoinAddress,
    ) -> Self {
        Self {
            deposit_request_outpoint,
            el_address,
            total_amount,
            take_back_leaf_hash,
            original_taproot_addr,
        }
    }

    /// Get the total deposit amount that needs to be bridged-in.
    pub fn total_amount(&self) -> &Amount {
        &self.total_amount
    }

    /// Get the address in EL to mint tokens to.
    pub fn el_address(&self) -> &[u8] {
        &self.el_address
    }

    /// Get the outpoint of the Deposit Request Transaction (DRT) that is to spent in the Deposit
    /// Transaction (DT).
    pub fn deposit_request_outpoint(&self) -> &OutPoint {
        &self.deposit_request_outpoint
    }

    /// Get the hash of the user-takes-back leaf in the taproot of the Deposit Request Transaction
    /// (DRT).
    pub fn take_back_leaf_hash(&self) -> &TapNodeHash {
        &self.take_back_leaf_hash
    }

    fn compute_spend_infos(
        &self,
        build_context: &impl BuildContext,
    ) -> anyhow::Result<TaprootWitness> {
        // The Deposit Request (DT) spends the n-of-n multisig leaf
        let spend_script = n_of_n_script(&build_context.aggregated_pubkey());
        let spend_script_hash =
            TapNodeHash::from_script(&spend_script, taproot::LeafVersion::TapScript);

        let takeback_script_hash = self.take_back_leaf_hash();

        let merkle_root = TapNodeHash::from_node_hashes(spend_script_hash, *takeback_script_hash);

        let address = Address::p2tr(
            SECP256K1,
            *UNSPENDABLE_INTERNAL_KEY,
            Some(merkle_root),
            build_context.network(),
        );

        let expected_addr = self.original_taproot_addr.address();

        if address != *expected_addr {
            bail!("address mismatch");
        }

        let (output_key, parity) = UNSPENDABLE_INTERNAL_KEY.tap_tweak(SECP256K1, Some(merkle_root));

        let control_block = ControlBlock {
            leaf_version: taproot::LeafVersion::TapScript,
            internal_key: *UNSPENDABLE_INTERNAL_KEY,
            merkle_branch: vec![*takeback_script_hash]
                .try_into()
                .context("invalid script hash")?,
            output_key_parity: parity,
        };

        if !control_block.verify_taproot_commitment(SECP256K1, output_key.into(), &spend_script) {
            bail!("control block verification");
        }

        let spend_info = TaprootWitness::Script {
            script_buf: spend_script,
            control_block,
        };

        Ok(spend_info)
    }

    fn compute_prevouts(&self) -> Vec<TxOut> {
        let deposit_address = self.original_taproot_addr.address();

        vec![TxOut {
            script_pubkey: deposit_address.script_pubkey(),
            value: self.total_amount,
        }]
    }

    fn create_unsigned_tx(&self, build_context: &impl BuildContext) -> anyhow::Result<Transaction> {
        // First, create the inputs
        let outpoint = self.deposit_request_outpoint();
        let tx_ins = create_tx_ins([*outpoint]);

        // Then, create the outputs:

        // First, create the `OP_RETURN <el_address>` output
        let el_addr = self.el_address();
        let el_addr: &[u8; 20] = el_addr.try_into().context("invalid el address")?;

        let metadata_script = metadata_script(el_addr);
        let metadata_amount = Amount::from_int_btc(0);

        // Then create the taproot script pubkey with keypath spend for the actual deposit
        let spend_path = SpendPath::KeySpend {
            internal_key: build_context.aggregated_pubkey(),
        };

        let (bridge_addr, _) = create_taproot_addr(&build_context.network(), spend_path)?;

        let bridge_in_script_pubkey = bridge_addr.script_pubkey();

        let tx_outs = create_tx_outs([
            (bridge_in_script_pubkey, BRIDGE_DENOMINATION),
            (metadata_script, metadata_amount),
        ]);

        let unsigned_tx = create_tx(tx_ins, tx_outs);

        Ok(unsigned_tx)
    }
}
