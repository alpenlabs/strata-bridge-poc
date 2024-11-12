use bitcoin::{Amount, OutPoint, Psbt, Transaction, TxOut, Txid};
use serde::{Deserialize, Serialize};
use strata_bridge_db::public::PublicDb;
use strata_bridge_primitives::{bitcoin::BitcoinAddress, params::prelude::*, scripts::prelude::*};

use crate::connectors::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KickoffTxData {
    pub funding_inputs: Vec<OutPoint>,
    pub funding_utxos: Vec<TxOut>,
    pub change_address: BitcoinAddress,
    pub change_amt: Amount,
    pub deposit_txid: Txid,
}

/// KickOff is just a wrapper around a Psbt.
///
/// One output of this Psbt is fixed but the other inputs and outputs can be variable so long as the
/// transaction itself is a SegWit transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KickOffTx(Psbt);

impl KickOffTx {
    pub async fn new<Db: PublicDb + Clone>(
        data: KickoffTxData,
        connector_k: ConnectorK<Db>,
    ) -> Self {
        let tx_ins = create_tx_ins(data.funding_inputs);

        let commitment_script = connector_k
            .create_taproot_address(data.deposit_txid)
            .await
            .script_pubkey();

        let change_address = data.change_address.address();
        let scripts_and_amounts = [
            (commitment_script, OPERATOR_STAKE),
            (change_address.script_pubkey(), data.change_amt),
        ];

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let tx = create_tx(tx_ins, tx_outs);

        let mut psbt = Psbt::from_unsigned_tx(tx).expect("witness should be empty");

        for (input, utxo) in psbt.inputs.iter_mut().zip(data.funding_utxos) {
            input.witness_utxo = Some(utxo);
        }

        Self(psbt)
    }

    pub fn psbt(&self) -> &Psbt {
        &self.0
    }

    pub fn mut_psbt(&mut self) -> &mut Psbt {
        &mut self.0
    }

    pub fn compute_txid(&self) -> Txid {
        self.0.unsigned_tx.compute_txid()
    }

    pub fn finalize(&self /* , signer: Signer */) -> Transaction {
        unimplemented!("implement signing with bitcoin wallet");
    }
}
