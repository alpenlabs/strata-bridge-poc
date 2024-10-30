use bitcoin::{taproot::Signature, Amount, OutPoint, Psbt, Transaction, Txid};

use crate::{
    connectors::prelude::*,
    constants::{MIN_RELAY_FEE, OPERATOR_STAKE},
    scripts::general::{create_tx, create_tx_ins, create_tx_outs},
};

#[derive(Debug, Clone)]
pub struct ClaimData {
    pub kickoff_txid: Txid,

    pub n_of_n_sig: Signature,
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

    pub fn finalize(
        mut self,
        connector_k: ConnectorK,
        msk: &str,
        bridge_out_txid: Txid,
        superblock_period_start_ts: u32,
    ) -> Transaction {
        connector_k.create_tx_input(
            &mut self.psbt.inputs[0],
            msk,
            bridge_out_txid,
            superblock_period_start_ts,
        );

        self.psbt
            .extract_tx()
            .expect("should be able to extract signed tx")
    }
}
