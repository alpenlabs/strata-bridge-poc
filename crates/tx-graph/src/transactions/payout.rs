use bitcoin::{Amount, Network, OutPoint, Psbt, Transaction, Txid};
use secp256k1::{schnorr::Signature, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{params::prelude::MIN_RELAY_FEE, scripts::prelude::*};

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
pub struct PayoutTx(Psbt);

impl PayoutTx {
    pub fn new(data: PayoutData) -> Self {
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

        let psbt = Psbt::from_unsigned_tx(tx).expect("the witness must be empty");

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

    pub fn finalize(mut self, n_of_n_signature: Signature) -> Transaction {
        finalize_input(&mut self.0.inputs[0], [n_of_n_signature.serialize()]);

        self.0.extract_tx().expect("should be able to extract tx")
    }
}
