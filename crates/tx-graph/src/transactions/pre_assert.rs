use bitcoin::{OutPoint, Psbt, Transaction, Txid};
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};

use super::constants::{
    ASSERT_DATA_TX1_A160_PK11_COUNT, ASSERT_DATA_TX1_A256_PK7_COUNT, ASSERT_DATA_TX1_COUNT,
    ASSERT_DATA_TX2_A160_PK11_COUNT, ASSERT_DATA_TX2_A256_PK7_COUNT, ASSERT_DATA_TX2_COUNT,
};
use crate::{connectors::prelude::*, scripts::prelude::*};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAssertData {
    claim_txid: Txid,
}

#[derive(Debug, Clone)]
pub struct PreAssertTx(Psbt);

impl PreAssertTx {
    pub fn new(
        data: PreAssertData,
        connector_s: ConnectorS,
        connector_a256: ConnectorA256Factory<7, 49>,
        connector_a160: ConnectorA160Factory<11, 598>,
    ) -> Self {
        let (connector160_batch, connector160_remainder): (
            Vec<ConnectorA160<11>>,
            ConnectorA160<4>,
        ) = connector_a160.create_connectors();

        let (connector256_batch, _connector256_remainder): (
            Vec<ConnectorA256<7>>,
            ConnectorA256<0>,
        ) = connector_a256.create_connectors();

        let outpoints = [OutPoint {
            txid: data.claim_txid,
            vout: 0,
        }];
        let tx_ins = create_tx_ins(outpoints);

        /* arrange locking scripts to make it easier to construct minimal number of spending
         * transactions. As of this writing, the following configuration yields the lowest
         * number of transactions:
         *
         * 5 * `AssertDataTx` take 10 A160 connectors and 1 A256 connector each.
         * Second `AssertDataTx` takes 4 A160<11> connector, 2 A256 connectors, and 1 A160<4>
         * connector.
         */
        let mut scripts_and_amounts = vec![];

        let connector_s_script = connector_s.create_taproot_address().script_pubkey();
        let connector_s_amt = connector_s_script.minimal_non_dust();

        scripts_and_amounts.push((connector_s_script, connector_s_amt));

        for _ in 0..ASSERT_DATA_TX1_COUNT {
            scripts_and_amounts.extend(
                connector160_batch
                    .iter()
                    .by_ref()
                    .take(ASSERT_DATA_TX1_A160_PK11_COUNT)
                    .map(|conn| {
                        let script = conn.create_locking_script();
                        let amount = script.minimal_non_dust();

                        (script, amount)
                    }),
            );

            scripts_and_amounts.extend(
                connector256_batch
                    .iter()
                    .by_ref()
                    .take(ASSERT_DATA_TX1_A256_PK7_COUNT)
                    .map(|conn| {
                        let script = conn.create_locking_script();
                        let amount = script.minimal_non_dust();

                        (script, amount)
                    }),
            );
        }

        for _ in 0..ASSERT_DATA_TX2_COUNT {
            scripts_and_amounts.extend(
                connector160_batch
                    .iter()
                    .by_ref()
                    .take(ASSERT_DATA_TX2_A160_PK11_COUNT)
                    .map(|conn| {
                        let script = conn.create_locking_script();
                        let amount = script.minimal_non_dust();

                        (script, amount)
                    }),
            );

            scripts_and_amounts.extend(
                connector256_batch
                    .iter()
                    .by_ref()
                    .take(ASSERT_DATA_TX2_A256_PK7_COUNT)
                    .map(|conn| {
                        let script = conn.create_locking_script();
                        let amount = script.minimal_non_dust();

                        (script, amount)
                    }),
            );
        }

        let connector160_remainder_script = connector160_remainder.create_locking_script();
        let connector160_remainder_amt = connector160_remainder_script.minimal_non_dust();

        scripts_and_amounts.push((connector160_remainder_script, connector160_remainder_amt));

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let tx = create_tx(tx_ins, tx_outs);

        let psbt = Psbt::from_unsigned_tx(tx).expect("input should have an empty witness field");

        Self(psbt)
    }

    pub fn psbt(&self) -> &Psbt {
        &self.0
    }

    pub fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.0
    }

    pub fn finalize(mut self, n_of_n_sig: Signature, connector_c0: ConnectorC0) -> Transaction {
        connector_c0.finalize_input_with_n_of_n(
            &mut self.psbt_mut().inputs[0],
            n_of_n_sig,
            ConnectorC0Leaf::Assert,
        );

        self.0.extract_tx().expect("should be able to extract tx")
    }
}
