use bitcoin::{
    sighash::Prevouts, Amount, Network, OutPoint, Psbt, ScriptBuf, Transaction, TxOut, Txid,
};
use strata_bridge_db::connector_db::ConnectorDb;
use strata_bridge_primitives::{
    params::prelude::UNSPENDABLE_INTERNAL_KEY, scripts::prelude::*, types::OperatorIdx,
};

use super::covenant_tx::CovenantTx;
use crate::connectors::prelude::*;

#[derive(Debug, Clone)]
pub struct DisproveData {
    pub post_assert_txid: Txid,

    pub deposit_txid: Txid,

    pub input_stake: Amount,

    pub network: Network,
}

#[derive(Debug, Clone)]
pub struct DisproveTx {
    psbt: Psbt,

    prevouts: Vec<TxOut>,

    witnesses: Vec<TaprootWitness>,
}

impl DisproveTx {
    pub async fn new<Db: ConnectorDb>(
        data: DisproveData,
        connector_a30: ConnectorA30<Db>,
        connector_a31: ConnectorA31<Db>,
    ) -> Self {
        let utxos = [
            OutPoint {
                txid: data.post_assert_txid,
                vout: 0,
            },
            OutPoint {
                txid: data.post_assert_txid,
                vout: 1,
            },
        ];

        let tx_ins = create_tx_ins(utxos);

        let (burn_address, _) = create_taproot_addr(
            &data.network,
            SpendPath::KeySpend {
                internal_key: *UNSPENDABLE_INTERNAL_KEY,
            },
        )
        .expect("should be able to create taproot address");
        let burn_script = burn_address.script_pubkey();
        let burn_amount = burn_script.minimal_non_dust();

        let tx_outs = create_tx_outs([
            (burn_script, burn_amount),
            (ScriptBuf::new(), Amount::from_int_btc(0)),
        ]);

        let tx = create_tx(tx_ins, tx_outs);

        let mut psbt = Psbt::from_unsigned_tx(tx).expect("should be able to create psbt");

        let connector_a31_script = connector_a31
            .generate_locking_script(data.deposit_txid)
            .await;
        let connector_a31_value = connector_a31_script.minimal_non_dust();

        let prevouts = vec![
            TxOut {
                value: data.input_stake,
                script_pubkey: connector_a30.generate_locking_script(),
            },
            TxOut {
                value: connector_a31_value,
                script_pubkey: connector_a31_script,
            },
        ];

        let witnesses = vec![TaprootWitness::Key; 2];

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo)
        }

        Self {
            psbt,

            prevouts,
            witnesses,
        }
    }

    pub async fn finalize<Db>(
        mut self,
        connector_a30: ConnectorA30<Db>,
        _connector_a31: ConnectorA31<Db>,
        reward: TxOut,
        _deposit_txid: Txid,
        operator_idx: OperatorIdx,
    ) -> Transaction
    where
        Db: ConnectorDb + Clone,
    {
        let original_txid = self.compute_txid();
        let psbt = self.psbt_mut();

        psbt.unsigned_tx.output[1] = reward;

        connector_a30
            .finalize_input(
                &mut self.psbt.inputs[0],
                0,
                operator_idx,
                original_txid,
                ConnectorA30Leaf::Disprove,
            )
            .await;

        // // // TODO: Compute which `ConnectorA31Leaf` is spendable
        // connector_a31
        //     .finalize_input(
        //         &mut self.psbt.inputs[1],
        //         ConnectorA31Leaf::InvalidateProof(0),
        //         deposit_txid,
        //     )
        //     .await;

        self.psbt
            .extract_tx()
            .expect("should be able to extract tx")
    }
}

impl CovenantTx for DisproveTx {
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
