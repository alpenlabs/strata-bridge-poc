use std::{sync::Arc, time::Duration};

use bitcoin::{Transaction, Txid};
use strata_bridge_btcio::{
    traits::{Reader, Wallet},
    BitcoinClient,
};
use strata_bridge_db::{connector_db::ConnectorDb, public::PublicDb};
use strata_bridge_tx_graph::transactions::constants::NUM_ASSERT_DATA_TX;
use tokio::sync::broadcast;
use tracing::{debug, info};

use crate::{operator::OperatorIdx, verifier::VerifierDuty};

#[derive(Debug, Clone)]
pub struct BitcoinWatcher {
    db: PublicDb,

    poll_interval: Duration,

    client: Arc<BitcoinClient>,

    genesis_height: u32,
}

impl BitcoinWatcher {
    pub fn new(db: PublicDb, client: Arc<BitcoinClient>, poll_interval: Duration) -> Self {
        Self {
            db,
            client,
            poll_interval,
            genesis_height: 0,
        }
    }

    pub async fn start(&self, notifier: broadcast::Sender<VerifierDuty>) {
        info!(action = "starting bitcoin watcher", %self.genesis_height);

        let mut height = self.genesis_height;
        loop {
            let block = self
                .client
                .get_block_at(height)
                .await
                .expect("should be able to get block at height");

            for tx in block.txdata {
                let txid = tx.compute_txid();

                if let Some((_, _)) = self.db.get_operator_and_deposit_for_claim(&txid).await {
                    let duty = self.handle_claim().await;

                    debug!(action = "dispatching challenge duty for verifier", claim_txid=%txid);
                    notifier
                        .send(duty)
                        .expect("should be able to send challenge duty to the verifier");
                } else if let Some((operator_idx, deposit_txid)) = self
                    .db
                    .get_operator_and_deposit_for_post_assert(&txid)
                    .await
                {
                    let duty = self.handle_assertion(tx, operator_idx, deposit_txid).await;

                    debug!(action = "dispatching disprove duty for verifier", post_assert_txid=%txid);
                    notifier
                        .send(duty)
                        .expect("should be ablet o send disprove duty to the verifier");
                }
            }

            tokio::time::sleep(self.poll_interval).await;
            height += 1;

            info!(event = "block scanned", cur_height=%height);
        }
    }

    pub async fn handle_claim(&self) -> VerifierDuty {
        unimplemented!("challenge not supported yet");
    }

    pub async fn handle_assertion(
        &self,
        post_assert_tx: Transaction,
        operator_id: OperatorIdx,
        deposit_txid: Txid,
    ) -> VerifierDuty {
        let mut assert_data_txs = Vec::new();
        for txin in post_assert_tx.input {
            let txid = txin.previous_output.txid;

            let tx = self
                .client
                .get_transaction(&txid)
                .await
                .expect("should be able to fetch post_assert tx");

            let tx = tx.hex;

            assert_data_txs.push(tx);
        }

        let assert_data_txs: [Transaction; NUM_ASSERT_DATA_TX] = assert_data_txs
            .try_into()
            .expect("the number of assert-data txs must match");

        let pre_assert_tx = self
            .client
            .get_transaction(&assert_data_txs[0].compute_txid())
            .await
            .expect("should be able to get pre-assert tx")
            .hex;
        let claim_tx = self
            .client
            .get_transaction(&pre_assert_tx.compute_txid())
            .await
            .expect("should be able to get claim tx")
            .hex;

        VerifierDuty::VerifyAssertions {
            operator_id,
            deposit_txid,
            claim_tx,
            assert_data_txs,
        }
    }
}