use bitcoin::{OutPoint, Psbt, Transaction, Txid};
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{
    params::connectors::{
        NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A160_RESIDUAL, NUM_PKS_A256_PER_CONNECTOR,
    },
    scripts::prelude::*,
};

use super::constants::{
    NUM_ASSERT_DATA_TX1, NUM_ASSERT_DATA_TX1_A160_PK11, NUM_ASSERT_DATA_TX1_A256_PK7,
    NUM_ASSERT_DATA_TX2, NUM_ASSERT_DATA_TX2_A160_PK11, NUM_ASSERT_DATA_TX2_A256_PK7, TOTAL_VALUES,
};
use crate::connectors::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertDataTxInput {
    pub pre_assert_txid: Txid,
}

#[derive(Debug, Clone)]
pub struct AssertDataTxBatch<const N: usize, const N_INPUTS_PER_TX1: usize>([Psbt; N]);

impl<const N: usize, const N_INPUTS_PER_TX: usize> AssertDataTxBatch<N, N_INPUTS_PER_TX> {
    pub fn new(input: AssertDataTxInput, connector_a2: ConnectorS) -> Self {
        let mut psbts: Vec<Psbt> = Vec::with_capacity(N);

        for i in 0..N {
            let starting_index = i * N_INPUTS_PER_TX + 1; // +1 to account for the stake output from
                                                          // `pre-assert` tx

            // in the last iteration, there will be less than `N_INPUTS_PER_TX` utxos.
            let mut utxos: Vec<OutPoint> = Vec::with_capacity(N_INPUTS_PER_TX);
            for vout in starting_index..(starting_index + N_INPUTS_PER_TX) {
                utxos.push(OutPoint {
                    txid: input.pre_assert_txid,
                    vout: vout as u32,
                });
            }

            let tx_ins = create_tx_ins(utxos);

            let output_script = connector_a2.create_taproot_address().script_pubkey();
            let output_amt = output_script.minimal_non_dust();

            let tx_outs = create_tx_outs([(output_script, output_amt)]);

            let tx = create_tx(tx_ins, tx_outs);

            let psbt = Psbt::from_unsigned_tx(tx).expect("must have an empty witness");

            psbts.push(psbt);
        }

        Self(psbts.try_into().expect("should have exactly N elements"))
    }

    pub fn psbts(&self) -> &[Psbt; N] {
        &self.0
    }

    pub fn psbt_at_index(&self, index: usize) -> Option<&Psbt> {
        self.0.get(index)
    }

    pub fn psbt_at_index_mut(&mut self, index: usize) -> Option<&mut Psbt> {
        self.0.get_mut(index)
    }

    pub fn compute_txids(&self) -> [Txid; N] {
        self.0
            .iter()
            .map(|psbt| psbt.unsigned_tx.compute_txid())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    pub fn finalize(
        mut self,
        connector_a160_factory: ConnectorA160Factory<11, 598>,
        connector_a256_factory: ConnectorA256Factory<7, 49>,
        msk: &str,
        values: [&[u8]; TOTAL_VALUES],
    ) -> [Transaction; N] {
        let (connector160_batch, connector160_remainder): (
            Vec<ConnectorA160<11>>,
            ConnectorA160<4>,
        ) = connector_a160_factory.create_connectors();

        let (connector256_batch, _connector256_remainder): (
            Vec<ConnectorA256<7>>,
            ConnectorA256<0>,
        ) = connector_a256_factory.create_connectors();

        let mut value_offset = 0;
        for psbt_index in 0..NUM_ASSERT_DATA_TX1 {
            connector160_batch
                .iter()
                .by_ref()
                .take(NUM_ASSERT_DATA_TX1_A160_PK11)
                .enumerate()
                .for_each(|(input_index, conn)| {
                    conn.create_tx_input(
                        &mut self.0[psbt_index].inputs[input_index],
                        msk,
                        values[value_offset..value_offset + NUM_PKS_A160_PER_CONNECTOR]
                            .try_into()
                            .unwrap(),
                    );

                    value_offset += NUM_PKS_A160_PER_CONNECTOR;
                });

            let input_offset = NUM_ASSERT_DATA_TX1_A160_PK11;
            connector256_batch
                .iter()
                .by_ref()
                .take(NUM_ASSERT_DATA_TX1_A256_PK7)
                .enumerate()
                .for_each(|(input_index, conn)| {
                    conn.create_tx_input(
                        &mut self.0[psbt_index].inputs[input_index + input_offset],
                        msk,
                        values[value_offset..value_offset + NUM_PKS_A256_PER_CONNECTOR]
                            .try_into()
                            .unwrap(),
                    );

                    value_offset += NUM_PKS_A256_PER_CONNECTOR;
                });
        }

        for psbt_index in NUM_ASSERT_DATA_TX1..NUM_ASSERT_DATA_TX1 + NUM_ASSERT_DATA_TX2 {
            connector160_batch
                .iter()
                .by_ref()
                .take(NUM_ASSERT_DATA_TX2_A160_PK11)
                .enumerate()
                .for_each(|(input_index, conn)| {
                    conn.create_tx_input(
                        &mut self.0[psbt_index].inputs[input_index],
                        msk,
                        values[value_offset..value_offset + NUM_PKS_A160_PER_CONNECTOR]
                            .try_into()
                            .unwrap(),
                    );

                    value_offset += NUM_PKS_A160_PER_CONNECTOR;
                });

            let input_offset = NUM_ASSERT_DATA_TX2_A160_PK11;
            connector256_batch
                .iter()
                .by_ref()
                .take(NUM_ASSERT_DATA_TX2_A256_PK7)
                .enumerate()
                .for_each(|(input_index, conn)| {
                    conn.create_tx_input(
                        &mut self.0[psbt_index].inputs[input_index + input_offset],
                        msk,
                        values[value_offset..value_offset + NUM_PKS_A256_PER_CONNECTOR]
                            .try_into()
                            .unwrap(),
                    );

                    value_offset += NUM_PKS_A256_PER_CONNECTOR;
                });

            let final_input = &mut self.0[psbt_index].inputs
                [NUM_ASSERT_DATA_TX2_A160_PK11 + NUM_ASSERT_DATA_TX2_A256_PK7];

            connector160_remainder.create_tx_input(
                final_input,
                msk,
                values[value_offset..value_offset + NUM_PKS_A160_RESIDUAL]
                    .try_into()
                    .unwrap(),
            );
        }

        self.0
            .into_iter()
            .map(|psbt| {
                psbt.extract_tx()
                    .expect("should be able to extract signed tx")
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}
