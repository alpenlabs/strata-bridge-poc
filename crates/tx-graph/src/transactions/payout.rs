use bitcoin::{sighash::Prevouts, Amount, Network, OutPoint, Psbt, Transaction, TxOut, Txid};
use secp256k1::{schnorr::Signature, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use strata_bridge_db::connector_db::ConnectorDb;
use strata_bridge_primitives::{
    params::{prelude::MIN_RELAY_FEE, tx::BRIDGE_DENOMINATION},
    scripts::prelude::*,
};

use super::covenant_tx::CovenantTx;
use crate::connectors::prelude::{ConnectorA30, ConnectorS};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutData {
    pub post_assert_txid: Txid,

    pub deposit_txid: Txid,

    pub input_stake: Amount,

    pub deposit_amount: Amount,

    pub operator_key: XOnlyPublicKey,

    pub network: Network,
}

#[derive(Debug, Clone)]
pub struct PayoutTx {
    psbt: Psbt,

    prevouts: Vec<TxOut>,

    witnesses: Vec<TaprootWitness>,
}

impl PayoutTx {
    pub fn new<Db: ConnectorDb>(
        data: PayoutData,
        connector_a30: ConnectorA30<Db>,
        connector_b: ConnectorS,
    ) -> Self {
        let utxos = [
            OutPoint {
                txid: data.deposit_txid,
                vout: 0,
            },
            OutPoint {
                txid: data.post_assert_txid,
                vout: 0,
            },
        ];

        let tx_ins = create_tx_ins(utxos);

        let payout_amount = data.input_stake + data.deposit_amount - MIN_RELAY_FEE;

        let (operator_address, _) = create_taproot_addr(
            &data.network,
            SpendPath::KeySpend {
                internal_key: data.operator_key,
            },
        )
        .expect("should be able to create taproot address");

        let tx_outs = create_tx_outs([(operator_address.script_pubkey(), payout_amount)]);

        let tx = create_tx(tx_ins, tx_outs);

        let mut psbt = Psbt::from_unsigned_tx(tx).expect("the witness must be empty");

        let prevouts = vec![
            TxOut {
                value: BRIDGE_DENOMINATION,
                script_pubkey: connector_b.create_taproot_address().script_pubkey(),
            },
            TxOut {
                value: data.input_stake,
                script_pubkey: connector_a30.generate_locking_script(),
            },
        ];

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo);
        }

        let witnesses = vec![TaprootWitness::Key; 2];

        Self {
            psbt,

            prevouts,
            witnesses,
        }
    }

    pub fn finalize(mut self, n_of_n_signature: Signature) -> Transaction {
        finalize_input(&mut self.psbt.inputs[0], [n_of_n_signature.serialize()]);
        finalize_input(&mut self.psbt.inputs[1], [n_of_n_signature.serialize()]);

        self.psbt
            .extract_tx()
            .expect("should be able to extract tx")
    }
}

impl CovenantTx for PayoutTx {
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
