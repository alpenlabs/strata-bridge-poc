use async_trait::async_trait;
use bitcoin::{Transaction, Txid};
use strata_bridge_primitives::duties::BridgeDutyStatus;

#[async_trait]
pub trait DutyTrackerDb {
    async fn get_last_fetched_duty_index(&self) -> u64;

    async fn set_last_fetched_duty_index(&self, duty_index: u64);

    async fn fetch_duty_status(&self, duty_id: Txid) -> Option<BridgeDutyStatus>;

    async fn update_duty_status(&self, duty_id: Txid, status: BridgeDutyStatus);
}

#[async_trait]
pub trait BitcoinBlockTrackerDb {
    async fn get_last_scanned_block_height(&self) -> u64;

    async fn set_last_scanned_block_height(&self, block_height: u64);

    async fn get_relevant_tx(&self, txid: &Txid) -> Option<Transaction>;

    async fn add_relevant_tx(&self, tx: Transaction);
}
