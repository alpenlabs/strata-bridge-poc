use bitcoin::{Amount, Network, OutPoint, Psbt, ScriptBuf, Transaction, TxOut, Txid};
use strata_bridge_db::connector_db::ConnectorDb;
use strata_bridge_primitives::{params::prelude::UNSPENDABLE_INTERNAL_KEY, scripts::prelude::*};

use crate::connectors::prelude::*;

#[derive(Debug, Clone)]
pub struct DisproveData {
    pub post_assert_txid: Txid,

    pub input_stake: Amount,

    pub network: Network,
}

#[derive(Debug, Clone)]
pub struct DisproveTx(Psbt);

impl DisproveTx {
    pub fn new(data: DisproveData) -> Self {
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

        let psbt = Psbt::from_unsigned_tx(tx).expect("should be able to create psbt");

        Self(psbt)
    }

    pub fn psbt(&self) -> &Psbt {
        &self.0
    }

    pub fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.0
    }

    pub fn compute_txid(&self) -> Txid {
        self.0.unsigned_tx.compute_txid()
    }

    pub async fn finalize<Db>(
        mut self,
        connector_a30: ConnectorA30<Db>,
        connector_a31: ConnectorA31<Db>,
        reward: TxOut,
    ) -> Transaction
    where
        Db: ConnectorDb + Clone,
    {
        let original_txid = self.compute_txid();
        let psbt = self.psbt_mut();

        psbt.unsigned_tx.output[1] = reward;

        connector_a30
            .finalize_input(
                &mut self.0.inputs[0],
                original_txid,
                ConnectorA30Leaf::Disprove,
            )
            .await;

        // TODO: Compute which `ConnectorA31Leaf` is spendable
        connector_a31
            .finalize_input(&mut self.0.inputs[1], ConnectorA31Leaf::InvalidateProof(0))
            .await;

        self.0.extract_tx().expect("should be able to extract tx")
    }
}
