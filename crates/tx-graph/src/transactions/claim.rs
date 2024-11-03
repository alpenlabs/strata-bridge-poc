use bitcoin::{Amount, OutPoint, Psbt, Transaction, Txid};
use strata_bridge_db::connector_db::ConnectorDb;
use strata_bridge_primitives::{
    params::prelude::{MIN_RELAY_FEE, OPERATOR_STAKE},
    scripts::prelude::*,
};

use crate::connectors::prelude::*;

#[derive(Debug, Clone)]
pub struct ClaimData {
    pub kickoff_txid: Txid,
}

#[derive(Debug, Clone)]
pub struct ClaimTx {
    psbt: Psbt,

    remaining_stake: Amount,
}

impl ClaimTx {
    pub fn new(data: ClaimData, connector_c0: ConnectorC0, connector_c1: ConnectorC1) -> Self {
        let tx_ins = create_tx_ins([OutPoint {
            txid: data.kickoff_txid,
            vout: 0,
        }]);

        let c1_out = connector_c1.generate_locking_script();
        let c1_amt = c1_out.minimal_non_dust();

        let c0_amt = OPERATOR_STAKE - c1_amt - MIN_RELAY_FEE; // use stake for intermediate fees

        let scripts_and_amounts = [
            (connector_c0.generate_locking_script(), c0_amt),
            (connector_c1.generate_locking_script(), c1_amt),
        ];

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let tx = create_tx(tx_ins, tx_outs);

        let psbt = Psbt::from_unsigned_tx(tx).expect("tx should have an empty witness");

        Self {
            psbt,
            remaining_stake: c0_amt,
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

    pub async fn finalize<Db: ConnectorDb>(
        mut self,
        connector_k: ConnectorK<Db>,
        msk: &str,
        bridge_out_txid: Txid,
        superblock_period_start_ts: u32,
    ) -> Transaction {
        connector_k
            .create_tx_input(
                &mut self.psbt.inputs[0],
                msk,
                bridge_out_txid,
                superblock_period_start_ts,
            )
            .await;

        self.psbt
            .extract_tx()
            .expect("should be able to extract signed tx")
    }
}
