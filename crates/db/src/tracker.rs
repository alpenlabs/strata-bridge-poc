use async_trait::async_trait;
use strata_bridge_primitives::duties::BridgeDutyStatus;

#[async_trait]
pub trait DutyTracker {
    async fn get_last_fetched_duty_index(&self) -> u64;

    async fn set_last_fetched_duty_index(&self, duty_index: u64);

    async fn fetch_status(&self, duty_id: String) -> Option<BridgeDutyStatus>;

    async fn update_duty_status(&self, duty_id: String, status: BridgeDutyStatus);
}

#[async_trait]
pub trait BitcoinBlockTracker {
    async fn get_last_scanned_block_height(&self) -> u64;

    async fn set_last_scanned_block_height(&self, block_height: u64);
}
