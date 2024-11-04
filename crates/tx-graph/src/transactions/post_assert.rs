use bitcoin::{sighash::Prevouts, Amount, OutPoint, Psbt, Transaction, TxOut, Txid};
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use strata_bridge_db::connector_db::ConnectorDb;
use strata_bridge_primitives::scripts::prelude::*;

use super::{
    constants::{NUM_ASSERT_DATA_TX1, NUM_ASSERT_DATA_TX2},
    covenant_tx::CovenantTx,
};
use crate::connectors::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostAssertTxData {
    pub assert_data_txids: Vec<Txid>,

    pub input_amount: Amount,

    pub deposit_txid: Txid,
}

#[derive(Debug, Clone)]
pub struct PostAssertTx {
    psbt: Psbt,

    remaining_stake: Amount,

    prevouts: Vec<TxOut>,

    witnesses: Vec<TaprootWitness>,
}

impl PostAssertTx {
    pub async fn new<Db: ConnectorDb>(
        data: PostAssertTxData,
        connector_a2: ConnectorS,
        connector_a30: ConnectorA30<Db>,
        connector_a31: ConnectorA31<Db>,
    ) -> Self {
        let utxos = data.assert_data_txids.iter().map(|txid| OutPoint {
            txid: *txid,
            vout: 0,
        });
        let tx_ins = create_tx_ins(utxos);

        let connector_a31_script = connector_a31
            .generate_locking_script(data.deposit_txid)
            .await;
        let mut scripts_and_amounts = [
            (
                connector_a30.generate_locking_script(),
                Amount::from_int_btc(0), // set net amount later
            ),
            (
                connector_a31_script.clone(),
                connector_a31_script.minimal_non_dust(),
            ),
        ];

        let net_stake = data.input_amount - scripts_and_amounts.iter().map(|(_, amt)| *amt).sum();
        scripts_and_amounts[0].1 = net_stake;

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let tx = create_tx(tx_ins, tx_outs);

        let psbt = Psbt::from_unsigned_tx(tx).expect("witness should be empty");

        const NUM_ASSERT_DATA: usize = NUM_ASSERT_DATA_TX1 + NUM_ASSERT_DATA_TX2;
        let assert_data_output_script = connector_a2.create_taproot_address().script_pubkey();
        let prevouts = (0..NUM_ASSERT_DATA)
            .map(|_| TxOut {
                script_pubkey: assert_data_output_script.clone(),
                value: assert_data_output_script.minimal_non_dust(),
            })
            .collect();

        let witnesses = vec![TaprootWitness::Key; NUM_ASSERT_DATA];

        Self {
            psbt,
            remaining_stake: net_stake,

            prevouts,
            witnesses,
        }
    }

    pub fn remaining_stake(&self) -> Amount {
        self.remaining_stake
    }

    pub fn compute_txid(&self) -> Txid {
        self.psbt.unsigned_tx.compute_txid()
    }

    pub fn finalize(mut self, signatures: &[Signature]) -> Transaction {
        for (index, input) in self.psbt.inputs.iter_mut().enumerate() {
            finalize_input(input, [signatures[index].as_ref()]);
        }

        self.psbt
            .extract_tx()
            .expect("should be able to extract signed tx")
    }
}

impl CovenantTx for PostAssertTx {
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
}
