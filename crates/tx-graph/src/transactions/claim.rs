use bitcoin::{
    absolute, consensus, Amount, Network, PublicKey, ScriptBuf, TapSighashType, Transaction, TxOut,
    XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};
use strata_bridge_contexts::operator::OperatorContext;

use super::{
    super::{
        connectors::{
            connector::*, connector_c0::ConnectorC0, connector_c1::ConnectorC1,
            connector_k::ConnectorK,
        },
        graphs::base::{DUST_AMOUNT, FEE_AMOUNT},
    },
    base::*,
    pre_signed::*,
};

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ClaimTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
    connector_k: ConnectorK,
}

impl PreSignedTransaction for ClaimTransaction {
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

impl ClaimTransaction {
    pub fn new(context: &OperatorContext, input_0: Input) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.operator_public_key,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
            input_0,
        );

        this.sign_input_0(context);

        this
    }

    pub fn new_for_validation(
        network: Network,
        operator_public_key: &PublicKey,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        input_from_kickoff: Input,
    ) -> Self {
        let kickoff_connector = ConnectorK::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
        );

        let connector_c0 = ConnectorC0::new(network, n_of_n_taproot_public_key);
        let connector_c1 = ConnectorC1::new(network, operator_public_key);

        let input_0_leaf = 0;
        let input_0 =
            kickoff_connector.generate_taproot_leaf_tx_in(input_0_leaf, &input_from_kickoff);

        let total_output_amount = input_from_kickoff.amount - Amount::from_sat(FEE_AMOUNT);

        let output_for_assert = TxOut {
            value: total_output_amount - Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_c0.generate_taproot_address().script_pubkey(),
        };

        let output_for_challenge = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_c1.generate_address().script_pubkey(),
        };

        ClaimTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![input_0],
                output: vec![output_for_challenge, output_for_assert],
            },
            prev_outs: vec![TxOut {
                value: input_from_kickoff.amount,
                script_pubkey: kickoff_connector.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![kickoff_connector.generate_taproot_leaf_script(input_0_leaf)],
            connector_k: kickoff_connector,
        }
    }

    pub fn num_blocks_timelock_0(&self) -> u32 {
        self.connector_k.num_blocks_timelock_0
    }

    fn sign_input_0(&mut self, context: &OperatorContext) {
        let input_index = 0;
        pre_sign_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            self.connector_k.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }
}

impl BaseTransaction for ClaimTransaction {
    fn finalize(&self) -> Transaction {
        self.tx.clone()
    }
}
