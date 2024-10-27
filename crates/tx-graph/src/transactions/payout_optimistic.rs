use std::collections::HashMap;

use bitcoin::{
    absolute, consensus, Amount, EcdsaSighashType, Network, PublicKey, ScriptBuf, TapSighashType,
    Transaction, TxOut, XOnlyPublicKey,
};
use musig2::{secp256k1::schnorr::Signature, PartialSignature, PubNonce, SecNonce};
use serde::{Deserialize, Serialize};
use strata_bridge_contexts::{
    base::BaseContext, operator::OperatorContext, verifier::VerifierContext,
};

use super::{
    super::{
        connectors::{
            connector::*, connector_a0::ConnectorA0, connector_b::ConnectorB,
            connector_c0::ConnectorC0, connector_c1::ConnectorC1,
        },
        graphs::base::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
    pre_signed_musig2::*,
};

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PayoutOptimisticTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
    connector_0: ConnectorB,
    connector_c1: ConnectorC1,
    connector_a: ConnectorA0,
    connector_c0: ConnectorC0,

    musig2_nonces: HashMap<usize, HashMap<PublicKey, PubNonce>>,
    musig2_nonce_signatures: HashMap<usize, HashMap<PublicKey, Signature>>,
    musig2_signatures: HashMap<usize, HashMap<PublicKey, PartialSignature>>,
}

impl PreSignedTransaction for PayoutOptimisticTransaction {
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

impl PreSignedMusig2Transaction for PayoutOptimisticTransaction {
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

impl PayoutOptimisticTransaction {
    pub fn new(
        context: &OperatorContext,
        input_from_peg_in: Input,
        input_from_c0: Input,
        input_from_c1: Input,
    ) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.operator_public_key,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
            input_from_peg_in,
            input_from_c0,
            input_from_c1,
        );

        this.sign_kick_off_input(context);
        this.sign_claim_lc_input_0(context);

        this
    }

    #[allow(clippy::too_many_arguments)] // HACK:
    pub fn new_for_validation(
        network: Network,
        operator_public_key: &PublicKey,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        peg_in_input: Input,
        input_from_c0: Input,
        input_from_c1: Input,
    ) -> Self {
        let connector_0 = ConnectorB::new(network, n_of_n_taproot_public_key);
        let connector_c1 = ConnectorC1::new(network, operator_public_key);
        let connector_a = ConnectorA0::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
        );
        let connector_c0 = ConnectorC0::new(network, n_of_n_taproot_public_key);

        let peg_in_leaf = 0;
        let peg_in = connector_0.generate_taproot_leaf_tx_in(peg_in_leaf, &peg_in_input);

        let claim_lc_0 = connector_c1.generate_tx_in(&input_from_c0);

        let claim_lc_1_leaf = 0;
        let claim_lc_1 = connector_c0.generate_taproot_leaf_tx_in(claim_lc_1_leaf, &input_from_c1);

        let total_output_amount = peg_in_input.amount + input_from_c0.amount + input_from_c1.amount
            - Amount::from_sat(FEE_AMOUNT);

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(network, operator_public_key)
                .script_pubkey(),
        };

        PayoutOptimisticTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![peg_in, claim_lc_0, claim_lc_1],
                output: vec![_output_0],
            },
            prev_outs: vec![
                TxOut {
                    value: peg_in_input.amount,
                    script_pubkey: connector_0.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_from_c0.amount,
                    script_pubkey: connector_c1.generate_address().script_pubkey(),
                },
                TxOut {
                    value: input_from_c1.amount,
                    script_pubkey: connector_c0.generate_taproot_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                connector_0.generate_taproot_leaf_script(peg_in_leaf),
                connector_c1.generate_script(),
                connector_c0.generate_taproot_leaf_script(claim_lc_1_leaf),
            ],
            connector_0,
            connector_c1,
            connector_a,
            connector_c0,
            musig2_nonces: HashMap::new(),
            musig2_nonce_signatures: HashMap::new(),
            musig2_signatures: HashMap::new(),
        }
    }

    pub fn num_blocks_timelock_2(&self) -> u32 {
        self.connector_c1.num_blocks_timelock
    }

    fn sign_peg_in_input(&mut self, context: &VerifierContext, secret_nonce: &SecNonce) {
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
            self.finalize_peg_in_input(context);
        }
    }

    fn finalize_peg_in_input(&mut self, context: &dyn BaseContext) {
        let input_index = 0;
        finalize_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            self.connector_0.generate_taproot_spend_info(),
        );
    }

    fn sign_kick_off_input(&mut self, context: &OperatorContext) {
        let input_index = 1;
        pre_sign_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            self.connector_a.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    fn sign_claim_lc_input_0(&mut self, context: &OperatorContext) {
        let input_index = 2;
        pre_sign_p2wsh_input(
            self,
            context,
            input_index,
            EcdsaSighashType::All,
            &vec![&context.operator_keypair],
        );
    }

    fn sign_claim_lc_input_1(&mut self, context: &VerifierContext, secret_nonce: &SecNonce) {
        let input_index = 3;
        pre_sign_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            secret_nonce,
        );

        // TODO: Consider verifying the final signature against the n-of-n public key and the tx.
        if self.musig2_signatures[&input_index].len() == context.n_of_n_public_keys.len() {
            self.finalize_claim_lc_input_1(context);
        }
    }

    fn finalize_claim_lc_input_1(&mut self, context: &dyn BaseContext) {
        let input_index = 3;
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

        let input_index = 3;
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
        self.sign_peg_in_input(context, &secret_nonces[&input_index]);

        let input_index = 3;
        self.sign_claim_lc_input_1(context, &secret_nonces[&input_index]);
    }

    pub fn merge(&mut self, take_1: &PayoutOptimisticTransaction) {
        merge_transactions(&mut self.tx, &take_1.tx);
        merge_musig2_nonces_and_signatures(self, take_1);
    }
}

impl BaseTransaction for PayoutOptimisticTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
}
