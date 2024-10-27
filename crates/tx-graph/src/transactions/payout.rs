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
        connectors::{connector::*, connector_b::ConnectorB},
        graphs::base::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
    pre_signed_musig2::*,
};
use crate::connectors::connector_a0::ConnectorA0;

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PayoutTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
    connector_0: ConnectorB,
    connector_a: ConnectorA0,

    musig2_nonces: HashMap<usize, HashMap<PublicKey, PubNonce>>,
    musig2_nonce_signatures: HashMap<usize, HashMap<PublicKey, Signature>>,
    musig2_signatures: HashMap<usize, HashMap<PublicKey, PartialSignature>>,
}

impl PreSignedTransaction for PayoutTransaction {
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

impl PreSignedMusig2Transaction for PayoutTransaction {
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

impl PayoutTransaction {
    pub fn new(
        context: &OperatorContext,
        output_from_peg_in: Input,
        output_0_from_assert: Input,
    ) -> Self {
        Self::new_for_validation(
            context.network,
            &context.operator_public_key,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
            output_from_peg_in,
            output_0_from_assert,
        )
    }

    #[allow(clippy::too_many_arguments)] // HACK:
    pub fn new_for_validation(
        network: Network,
        operator_public_key: &PublicKey,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        output_from_peg_in: Input,
        output_0_from_assert: Input,
    ) -> Self {
        let connector_b = ConnectorB::new(network, n_of_n_taproot_public_key);
        let connector_a = ConnectorA0::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
        );

        let peg_in_leaf = 0;
        let peg_in = connector_b.generate_taproot_leaf_tx_in(peg_in_leaf, &output_from_peg_in);

        let operator_payout_leaf = 0;
        let _input_1 =
            connector_a.generate_taproot_leaf_tx_in(operator_payout_leaf, &output_0_from_assert);

        let total_output_amount =
            output_from_peg_in.amount + output_0_from_assert.amount - Amount::from_sat(FEE_AMOUNT);

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(network, operator_public_key)
                .script_pubkey(),
        };

        PayoutTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![peg_in, _input_1],
                output: vec![_output_0],
            },
            prev_outs: vec![
                TxOut {
                    value: output_from_peg_in.amount,
                    script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: output_0_from_assert.amount,
                    script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                connector_b.generate_taproot_leaf_script(peg_in_leaf),
                connector_a.generate_taproot_leaf_script(operator_payout_leaf),
            ],
            connector_0: connector_b,
            connector_a,
            musig2_nonces: HashMap::new(),
            musig2_nonce_signatures: HashMap::new(),
            musig2_signatures: HashMap::new(),
        }
    }

    pub fn num_blocks_timelock_0(&self) -> u32 {
        self.connector_a.num_blocks_timelock_0
    }

    fn sign_input(
        &mut self,
        context: &VerifierContext,
        secret_nonce: &SecNonce,
        input_index: usize,
    ) {
        pre_sign_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            secret_nonce,
        );

        // TODO: Consider verifying the final signature against the n-of-n public key and the tx.
        if self.musig2_signatures[&input_index].len() == context.n_of_n_public_keys.len() {
            self.finalize_input(context, input_index);
        }
    }

    fn finalize_input(&mut self, context: &dyn BaseContext, input_index: usize) {
        finalize_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            self.connector_0.generate_taproot_spend_info(),
        );
    }

    pub fn push_nonces(&mut self, context: &VerifierContext) -> HashMap<usize, SecNonce> {
        let mut secret_nonces = HashMap::new();

        let input_index = 0;
        let secret_nonce = push_nonce(self, context, input_index);
        secret_nonces.insert(input_index, secret_nonce);

        let input_index = 2;
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
        self.sign_input(context, &secret_nonces[&input_index], input_index);

        let input_index = 1;
        self.sign_input(context, &secret_nonces[&input_index], input_index);
    }

    pub fn merge(&mut self, take_2: &PayoutTransaction) {
        merge_transactions(&mut self.tx, &take_2.tx);
        merge_musig2_nonces_and_signatures(self, take_2);
    }
}

impl BaseTransaction for PayoutTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
}
