use bitcoin::{taproot::Signature, OutPoint, Psbt, Transaction, Txid};

use crate::{
    connectors::prelude::*,
    constants::{MIN_RELAY_FEE, OPERATOR_STAKE},
    scripts::general::{create_tx, create_tx_ins, create_tx_outs},
};

#[derive(Debug, Clone)]
pub struct ClaimData {
    pub kickoff_txid: Txid,

    pub n_of_n_sig: Signature,
    // WOTS data
}

#[derive(Debug, Clone)]
pub struct ClaimTx {
    psbt: Psbt,

    data: ClaimData,
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

        Self { psbt, data }
    }

    pub fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    pub fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    pub fn txid(&self) -> Txid {
        self.psbt.unsigned_tx.compute_txid()
    }

    pub fn finalize(mut self, connector_k: ConnectorK) -> Transaction {
        self.psbt.inputs[0] = connector_k.create_tx_input(self.data.n_of_n_sig);

        self.psbt
            .extract_tx()
            .expect("should be able to extract signed tx")
    }
}
