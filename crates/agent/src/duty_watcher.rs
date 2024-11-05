use std::{sync::Arc, time::Duration};

use strata_bridge_primitives::duties::{BridgeDuties, BridgeDuty};
use strata_rpc::StrataApiClient;
use tokio::sync::broadcast;
use tracing::{error, info};

#[derive(Debug, Clone)]
pub struct DutyWatcherConfig {
    pub poll_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct DutyWatcher<StrataClient: StrataApiClient> {
    config: DutyWatcherConfig,

    strata_rpc_client: Arc<StrataClient>,

    last_fetched_duty_index: u64,
}

impl<StrataClient: StrataApiClient + Send + Sync> DutyWatcher<StrataClient> {
    pub fn new(config: DutyWatcherConfig, strata_rpc_client: Arc<StrataClient>) -> Self {
        Self {
            config,
            strata_rpc_client,
            last_fetched_duty_index: 0,
        }
    }

    pub async fn start(&mut self, duty_sender: broadcast::Sender<BridgeDuty>) {
        loop {
            let operator_idx = u32::MAX; // doesn't really matter in the current impl

            match self
                .strata_rpc_client
                .get_bridge_duties(operator_idx, self.last_fetched_duty_index)
                .await
            {
                Ok(BridgeDuties {
                    duties,
                    start_index,
                    stop_index,
                }) => {
                    let num_duties = duties.len();
                    info!(event = "fetched duties", %start_index, %stop_index, %num_duties);

                    for duty in duties {
                        duty_sender.send(duty).expect("should be able to send duty");
                    }

                    self.last_fetched_duty_index = stop_index;
                }
                Err(e) => {
                    error!(?e, "could not get duties from strata");
                }
            }

            tokio::time::sleep(self.config.poll_interval).await;
        }
    }
}
