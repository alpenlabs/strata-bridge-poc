use bitcoin::{
    address::NetworkUnchecked, Address, Amount, Network, OutPoint, Psbt, Transaction, Txid,
};
use serde::{Deserialize, Serialize};
use strata_bridge_db::connector_db::ConnectorDb;
use strata_bridge_primitives::{params::prelude::*, scripts::prelude::*};

use crate::connectors::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KickoffTxData {
    pub funding_inputs: Vec<OutPoint>,
    pub change_address: Address<NetworkUnchecked>,
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
    pub async fn new<Db: ConnectorDb>(
        data: KickoffTxData,
        connector_k: ConnectorK<Db>,
        network: Network,
    ) -> Self {
        let tx_ins = create_tx_ins(data.funding_inputs);

        let commitment_script = connector_k
            .create_taproot_address(data.deposit_txid)
            .await
            .script_pubkey();

        let change_address = data
            .change_address
            .require_network(network)
            .expect("address should be valid for network");
        let scripts_and_amounts = [
            (commitment_script, OPERATOR_STAKE),
            (change_address.script_pubkey(), data.change_amt),
        ];

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let tx = create_tx(tx_ins, tx_outs);

        let psbt = Psbt::from_unsigned_tx(tx).expect("witness should be empty");

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
