use bitcoin::{TxOut, Txid};
use strata_bridge_db::connector_db::ConnectorDb;
use strata_bridge_primitives::params::connectors::{
    NUM_PKS_A160, NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A256, NUM_PKS_A256_PER_CONNECTOR,
};
use tracing::trace;

use super::{
    constants::{
        NUM_ASSERT_DATA_TX1, NUM_ASSERT_DATA_TX1_A160_PK11, NUM_ASSERT_DATA_TX1_A256_PK7,
        NUM_ASSERT_DATA_TX2,
    },
    prelude::*,
};
use crate::connectors::prelude::*;

#[derive(Debug, Clone)]
pub struct AssertChainData {
    pub pre_assert_data: PreAssertData,
    pub deposit_txid: Txid,
}

#[derive(Debug, Clone)]
pub struct AssertChain {
    pub pre_assert: PreAssertTx,
    pub assert_data: AssertDataTxBatch<
        { NUM_ASSERT_DATA_TX1 + NUM_ASSERT_DATA_TX2 },
        { NUM_ASSERT_DATA_TX1_A160_PK11 + NUM_ASSERT_DATA_TX1_A256_PK7 },
    >,
    pub post_assert: PostAssertTx,
}

impl AssertChain {
    pub async fn new<Db: ConnectorDb>(
        data: AssertChainData,
        connector_c0: ConnectorC0,
        connector_s: ConnectorS,
        connector_a30: ConnectorA30<Db>,
        connector_a31: ConnectorA31<Db>,
        connector_a160_factory: ConnectorA160Factory<NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A160>,
        connector_a256_factory: ConnectorA256Factory<NUM_PKS_A256_PER_CONNECTOR, NUM_PKS_A256>,
    ) -> Self {
        let pre_assert = PreAssertTx::new(
            data.pre_assert_data,
            connector_c0,
            connector_s,
            connector_a256_factory,
            connector_a160_factory,
        );
        let pre_assert_txid = pre_assert.compute_txid();
        trace!(event = "created pre-assert tx", %pre_assert_txid);

        let pre_assert_net_output_stake = pre_assert.remaining_stake();

        let assert_data_input = AssertDataTxInput {
            pre_assert_txid,
            pre_assert_txouts: pre_assert
                .tx_outs()
                .iter()
                .skip(1) // skip stake output
                .cloned()
                .collect::<Vec<TxOut>>(),
        };

        let assert_data: AssertDataTxBatch<
            { NUM_ASSERT_DATA_TX1 + NUM_ASSERT_DATA_TX2 },
            { NUM_ASSERT_DATA_TX1_A160_PK11 + NUM_ASSERT_DATA_TX1_A256_PK7 },
        > = AssertDataTxBatch::new(assert_data_input, connector_s);

        let assert_data_txids = assert_data.compute_txids().to_vec();
        trace!(event = "created assert_data tx batch", ?assert_data_txids);

        let post_assert_data = PostAssertTxData {
            assert_data_txids,
            input_amount: pre_assert_net_output_stake,
            deposit_txid: data.deposit_txid,
        };

        let post_assert =
            PostAssertTx::new(post_assert_data, connector_s, connector_a30, connector_a31).await;

        trace!(event = "created post_assert tx", post_assert_txid = ?post_assert.compute_txid());

        Self {
            pre_assert,
            assert_data,
            post_assert,
        }
    }
}
