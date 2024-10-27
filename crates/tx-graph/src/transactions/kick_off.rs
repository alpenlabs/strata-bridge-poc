use bitcoin::{
    absolute, consensus, key::TapTweak, Address, Amount, EcdsaSighashType, Network, PublicKey,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};
use strata_bridge_contexts::operator::OperatorContext;

use super::{
    super::{
        connectors::{connector::*, connector_k::ConnectorK},
        graphs::base::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
};
use crate::constants::OPERATOR_STAKE;

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct KickOffTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for KickOffTransaction {
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

impl KickOffTransaction {
    pub fn new(context: &OperatorContext, operator_input: Input) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.operator_public_key,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
            operator_input,
        );

        this.sign_input_0(context);

        this
    }

    pub fn new_for_validation(
        network: Network,
        operator_public_key: &PublicKey,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        operator_input: Input,
    ) -> Self {
        let connector_k = ConnectorK::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
        );

        let _input_0 = TxIn {
            previous_output: operator_input.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let _output_0 = TxOut {
            value: OPERATOR_STAKE,
            script_pubkey: connector_k.generate_taproot_address().script_pubkey(),
        };

        let change_amount = operator_input.amount - OPERATOR_STAKE - Amount::from_sat(FEE_AMOUNT);
        let change_address = Address::p2tr_tweaked(
            operator_taproot_public_key.dangerous_assume_tweaked(),
            network,
        );

        let _output_1 = TxOut {
            value: change_amount,
            script_pubkey: change_address.script_pubkey(),
        };

        KickOffTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0, _output_1],
            },
            prev_outs: vec![TxOut {
                value: operator_input.amount,
                script_pubkey: generate_pay_to_pubkey_script_address(network, operator_public_key)
                    .script_pubkey(), // TODO: Add address of Commit y
            }],
            prev_scripts: vec![generate_pay_to_pubkey_script(operator_public_key)],
        }
    }

    fn sign_input_0(&mut self, context: &OperatorContext) {
        let input_index = 0;
        pre_sign_p2wsh_input(
            self,
            context,
            input_index,
            EcdsaSighashType::All,
            &vec![&context.operator_keypair],
        );
    }
}

impl BaseTransaction for KickOffTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
}
