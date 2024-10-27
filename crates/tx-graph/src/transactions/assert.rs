use std::collections::HashMap;

use bitcoin::{
    absolute, consensus, Amount, Network, PublicKey, ScriptBuf, TapSighashType, Transaction, TxOut,
    XOnlyPublicKey,
};
use musig2::{secp256k1::schnorr::Signature, PartialSignature, PubNonce, SecNonce};
use serde::{Deserialize, Serialize};
use strata_bridge_contexts::{
    base::BaseContext, operator::OperatorContext, verifier::VerifierContext,
};

use super::{
    super::{
        connectors::{connector::*, connector_a1::ConnectorA1, connector_c0::ConnectorC0},
        graphs::base::{DUST_AMOUNT, FEE_AMOUNT},
    },
    base::*,
    pre_signed::*,
    pre_signed_musig2::*,
};
use crate::connectors::{connector_a0::ConnectorA0, connector_cpfp::ConnectorCpfp};

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx_with_locking_chunks: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    txs_with_redeem_chunks: Vec<Transaction>,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
    connector_c0: ConnectorC0,

    musig2_nonces: HashMap<usize, HashMap<PublicKey, PubNonce>>,
    musig2_nonce_signatures: HashMap<usize, HashMap<PublicKey, Signature>>,
    musig2_signatures: HashMap<usize, HashMap<PublicKey, PartialSignature>>,
}

impl PreSignedTransaction for AssertTransaction {
    fn tx(&self) -> &Transaction {
        &self.tx
    }

    fn tx_mut(&mut self) -> &mut Transaction {
        &mut self.tx
    }

    fn prev_outs(&self) -> &Vec<TxOut> {
        &self.prev_outs
    }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> {
        &self.prev_scripts
    }
}

impl PreSignedMusig2Transaction for AssertTransaction {
    fn musig2_nonces(&self) -> &HashMap<usize, HashMap<PublicKey, PubNonce>> {
        &self.musig2_nonces
    }
    fn musig2_nonces_mut(&mut self) -> &mut HashMap<usize, HashMap<PublicKey, PubNonce>> {
        &mut self.musig2_nonces
    }
    fn musig2_nonce_signatures(&self) -> &HashMap<usize, HashMap<PublicKey, Signature>> {
        &self.musig2_nonce_signatures
    }
    fn musig2_nonce_signatures_mut(
        &mut self,
    ) -> &mut HashMap<usize, HashMap<PublicKey, Signature>> {
        &mut self.musig2_nonce_signatures
    }
    fn musig2_signatures(&self) -> &HashMap<usize, HashMap<PublicKey, PartialSignature>> {
        &self.musig2_signatures
    }
    fn musig2_signatures_mut(
        &mut self,
    ) -> &mut HashMap<usize, HashMap<PublicKey, PartialSignature>> {
        &mut self.musig2_signatures
    }
}

impl AssertTransaction {
    pub fn new(context: &OperatorContext, claim_input: Input) -> Self {
        Self::new_for_validation(
            context.network,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
            claim_input,
        )
    }

    pub fn new_for_validation(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        claim_input: Input,
    ) -> Self {
        let connector_a0 = ConnectorA0::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
        );
        let connector_a1 = ConnectorA1::new(network, n_of_n_taproot_public_key);
        let connector_c0 = ConnectorC0::new(network, n_of_n_taproot_public_key);

        let claim_leaf = 2;
        let claim = connector_c0.generate_taproot_leaf_tx_in(claim_leaf, &claim_input);

        let total_output_amount = claim_input.amount - Amount::from_sat(FEE_AMOUNT);

        let presigned_output = TxOut {
            value: total_output_amount - Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_a0.generate_taproot_address().script_pubkey(),
        };

        let assert_output = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_a1.generate_taproot_address().script_pubkey(),
        };

        let connector_cpfp = ConnectorCpfp::new(network);
        let cpfp_output = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_cpfp.generate_address().script_pubkey(),
        };

        AssertTransaction {
            tx_with_locking_chunks: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![claim],
                // FIXME: add script to commit assertion inputs
                // there should be 56 of these
                output: vec![],
            },
            // FIXME: replace `Vec` with a function that computes the number of transactions
            // required to stay within the standardness limit.
            txs_with_redeem_chunks: vec![Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                // FIXME: add inputs from `txs_with_locking_chunks` in groups of 4
                // only 4 of these can fit because of the size of the data to be committed.
                input: vec![],
                // FIXME: add a single output that spends to N/N
                output: vec![],
            }],
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                // FIXME: add inputs from `tx_with_redeem_chunks` to be presigned by all
                input: vec![],
                output: vec![presigned_output, assert_output, cpfp_output],
            },
            prev_outs: vec![TxOut {
                value: claim_input.amount,
                script_pubkey: connector_c0.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_c0.generate_taproot_leaf_script(claim_leaf)],
            connector_c0,
            musig2_nonces: HashMap::new(),
            musig2_nonce_signatures: HashMap::new(),
            musig2_signatures: HashMap::new(),
        }
    }

    pub fn num_blocks_timelock_0(&self) -> u32 {
        self.connector_c0.num_blocks_timelock_1
    }

    fn sign_input_0(&mut self, context: &VerifierContext, secret_nonce: &SecNonce) {
        let input_index = 0;
        pre_sign_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            secret_nonce,
        );

        // TODO: Consider verifying the final signature against the n-of-n public key and the tx.
        if self.musig2_signatures[&input_index].len() == context.n_of_n_public_keys.len() {
            self.finalize_input_0(context);
        }
    }

    fn finalize_input_0(&mut self, context: &dyn BaseContext) {
        let input_index = 0;
        finalize_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            self.connector_c0.generate_taproot_spend_info(),
        );
    }

    pub fn push_nonces(&mut self, context: &VerifierContext) -> HashMap<usize, SecNonce> {
        let mut secret_nonces = HashMap::new();

        let input_index = 0;
        let secret_nonce = push_nonce(self, context, input_index);
        secret_nonces.insert(input_index, secret_nonce);

        secret_nonces
    }

    pub fn pre_sign(
        &mut self,
        context: &VerifierContext,
        secret_nonces: &HashMap<usize, SecNonce>,
    ) {
        let input_index = 0;
        self.sign_input_0(context, &secret_nonces[&input_index]);
    }

    pub fn merge(&mut self, assert: &AssertTransaction) {
        merge_transactions(&mut self.tx, &assert.tx);
        merge_musig2_nonces_and_signatures(self, assert);
    }
}

impl BaseTransaction for AssertTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
}
