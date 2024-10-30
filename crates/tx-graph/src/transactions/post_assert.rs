use bitcoin::{Amount, OutPoint, Psbt, Transaction, Txid};
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};

use crate::{connectors::prelude::*, scripts::prelude::*};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostAssertTxData {
    pub assert_data_txids: Vec<Txid>,

    pub input_amount: Amount,
}

#[derive(Debug, Clone)]
pub struct PostAssertTx {
    psbt: Psbt,

    remaining_stake: Amount,
}

impl PostAssertTx {
    pub fn new(data: PostAssertTxData, connector_a30: ConnectorA30) -> Self {
        let utxos = data.assert_data_txids.iter().map(|txid| OutPoint {
            txid: *txid,
            vout: 0,
        });
        let tx_ins = create_tx_ins(utxos);

        let mut scripts_and_amounts = [(
            connector_a30.generate_locking_script(),
            Amount::from_int_btc(0), // set net amount later
        )];

        let net_stake = scripts_and_amounts.iter().map(|(_, amt)| *amt).sum();
        scripts_and_amounts[0].1 = net_stake;

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let tx = create_tx(tx_ins, tx_outs);

        let psbt = Psbt::from_unsigned_tx(tx).expect("witness should be empty");

        Self {
            psbt,
            remaining_stake: net_stake,
        }
    }

    pub fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    pub fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
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
