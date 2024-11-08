use bitcoin::{sighash::Prevouts, Amount, OutPoint, Psbt, Transaction, TxOut, Txid};
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{params::prelude::*, scripts::prelude::*};
use tracing::trace;

use super::{
    constants::{NUM_ASSERT_DATA_TX1_A256_PK7, NUM_ASSERT_DATA_TX2_A160_PK11},
    covenant_tx::CovenantTx,
};
use crate::connectors::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAssertData {
    pub claim_txid: Txid,
    pub input_stake: Amount,
}

#[derive(Debug, Clone)]
pub struct PreAssertTx {
    psbt: Psbt,

    remaining_stake: Amount,

    prevouts: Vec<TxOut>,

    /// The ordering of these is pretty complicated.
    ///
    /// This field is so that we don't have to recompute this order in other places.
    tx_outs: Vec<TxOut>,

    witnesses: Vec<TaprootWitness>,
}

impl PreAssertTx {
    pub fn new(
        data: PreAssertData,
        connector_c0: ConnectorC0,
        connector_s: ConnectorS,
        connector_a256: ConnectorA256Factory<NUM_PKS_A256_PER_CONNECTOR, NUM_PKS_A256>,
        connector_a160: ConnectorA160Factory<NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A160>,
    ) -> Self {
        let (connector160_batch, connector160_remainder): (
            Vec<ConnectorA160<NUM_PKS_A160_PER_CONNECTOR>>,
            ConnectorA160<NUM_PKS_A160_RESIDUAL>,
        ) = connector_a160.create_connectors();

        let (connector256_batch, _connector256_remainder): (
            Vec<ConnectorA256<NUM_PKS_A256_PER_CONNECTOR>>,
            ConnectorA256<NUM_PKS_A256_RESIDUAL>,
        ) = connector_a256.create_connectors();

        let outpoints = [OutPoint {
            txid: data.claim_txid,
            vout: 0,
        }];
        let tx_ins = create_tx_ins(outpoints);

        /* arrange locking scripts to make it easier to construct minimal number of spending
         * transactions. As of this writing, the following configuration yields the lowest
         * number of transactions:
         *
         * 5 * `AssertDataTx` take 10 A160 connectors and 1 A256 connector each.
         * Second `AssertDataTx` takes 4 A160<11> connector, 2 A256 connectors, and 1 A160<4>
         * connector.
         */
        let mut scripts_and_amounts = vec![];

        let connector_s_script = connector_s.create_taproot_address().script_pubkey();
        let connector_s_amt = Amount::from_int_btc(0); // this is set after all the output
                                                       // amounts have been calculated for the assertion

        scripts_and_amounts.push((connector_s_script, connector_s_amt));

        // add connector 6_7x_256
        scripts_and_amounts.extend(
            connector256_batch
                .iter()
                .by_ref()
                .take(NUM_ASSERT_DATA_TX1_A256_PK7)
                .map(|conn| {
                    let script = conn.create_taproot_address().script_pubkey();
                    let amount = script.minimal_non_dust();

                    (script, amount)
                }),
        );

        // add connector 9_11x_160, 7_11x_160
        scripts_and_amounts.extend(
            connector160_batch
                .iter()
                .by_ref()
                .take(NUM_ASSERT_DATA_TX2_A160_PK11)
                .map(|conn| {
                    let script = conn.create_taproot_address().script_pubkey();
                    let amount = script.minimal_non_dust();

                    (script, amount)
                }),
        );

        // add connector 1_2x_160
        let connector160_remainder_script = connector160_remainder
            .create_taproot_address()
            .script_pubkey();
        let connector160_remainder_amt = connector160_remainder_script.minimal_non_dust();
        scripts_and_amounts.push((connector160_remainder_script, connector160_remainder_amt));

        let total_assertion_amount = scripts_and_amounts.iter().map(|(_, amt)| *amt).sum();
        let net_stake = data.input_stake - total_assertion_amount - MIN_RELAY_FEE;

        trace!(event = "calculated net remaining stake", %net_stake);

        scripts_and_amounts[0].1 = net_stake;

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let tx = create_tx(tx_ins, tx_outs.clone());

        let mut psbt =
            Psbt::from_unsigned_tx(tx).expect("input should have an empty witness field");

        let prevouts = vec![TxOut {
            value: data.input_stake,
            script_pubkey: connector_c0.generate_locking_script(),
        }];

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo);
        }

        let (script_buf, control_block) = connector_c0.generate_spend_info(ConnectorC0Leaf::Assert);
        let witness = vec![TaprootWitness::Script {
            script_buf,
            control_block,
        }];

        Self {
            psbt,
            remaining_stake: net_stake,

            prevouts,
            tx_outs,
            witnesses: witness,
        }
    }

    pub fn remaining_stake(&self) -> Amount {
        self.remaining_stake
    }

    pub fn tx_outs(&self) -> &[TxOut] {
        &self.tx_outs
    }

    pub fn finalize(mut self, n_of_n_sig: Signature, connector_c0: ConnectorC0) -> Transaction {
        connector_c0.finalize_input_with_n_of_n(
            &mut self.psbt_mut().inputs[0],
            n_of_n_sig,
            ConnectorC0Leaf::Assert,
        );

        self.psbt
            .extract_tx()
            .expect("should be able to extract tx")
    }
}

impl CovenantTx for PreAssertTx {
    fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    fn prevouts(&self) -> Prevouts<'_, TxOut> {
        Prevouts::All(&self.prevouts)
    }

    fn witnesses(&self) -> &[TaprootWitness] {
        &self.witnesses
    }

    fn compute_txid(&self) -> Txid {
        self.psbt.unsigned_tx.compute_txid()
    }
}
