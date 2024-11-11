use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bitcoin::{consensus, Txid};
use strata_bridge_primitives::duties::BridgeDutyStatus;
use tokio::sync::{Mutex, RwLock};

use crate::tracker::{BitcoinBlockTracker, DutyTracker};

#[derive(Debug, Clone)]
pub struct DutyTrackerInMemory {
    last_fetched_duty_index: Arc<RwLock<u64>>,

    duty_status: Arc<RwLock<HashMap<Txid, BridgeDutyStatus>>>,
}

#[async_trait]
impl DutyTracker for DutyTrackerInMemory {
    async fn get_last_fetched_duty_index(&self) -> u64 {
        *self.last_fetched_duty_index.read().await
    }

    async fn set_last_fetched_duty_index(&self, duty_index: u64) {
        let mut new_duty_index = self.last_fetched_duty_index.write().await;

        *new_duty_index = duty_index;
    }

    async fn fetch_status(&self, duty_id: String) -> Option<BridgeDutyStatus> {
        let txid: Txid =
            consensus::encode::deserialize_hex(&duty_id).expect("duty id must be hex-encoded txid");

        self.duty_status.read().await.get(&txid).cloned()
    }

    async fn update_duty_status(&self, duty_id: String, status: BridgeDutyStatus) {
        let duty_id: Txid =
            consensus::encode::deserialize_hex(&duty_id).expect("duty id must be hex-encoded txid");

        let mut duty_status = self.duty_status.write().await;

        if let Some(duty_status) = duty_status.get_mut(&duty_id) {
            *duty_status = status;
        } else {
            duty_status.insert(duty_id, status);
        }
    }
}

#[derive(Debug, Clone)]
pub struct BitcoinBlockTrackerInMemory {
    last_scanned_block_height: Arc<RwLock<u64>>,
}

#[async_trait]
impl BitcoinBlockTracker for BitcoinBlockTrackerInMemory {
    async fn get_last_scanned_block_height(&self) -> u64 {
        *self.last_scanned_block_height.read().await
    }

    async fn set_last_scanned_block_height(&self, block_height: u64) {
        let mut height = self.last_scanned_block_height.write().await;

        *height = block_height;
    }
}
