use std::{collections::HashSet, sync::Arc, time::Duration};

use bitcoin::Txid;
use strata_bridge_primitives::duties::{BridgeDuties, BridgeDuty};
use strata_rpc::StrataApiClient;
use tokio::sync::broadcast;
use tracing::{debug, error, info};

#[derive(Debug, Clone)]
pub struct DutyWatcherConfig {
    pub poll_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct DutyWatcher<StrataClient: StrataApiClient> {
    config: DutyWatcherConfig,

    strata_rpc_client: Arc<StrataClient>,

    last_fetched_duty_index: u64,

    dispatched_duties: HashSet<Txid>,
}

impl<StrataClient: StrataApiClient + Send + Sync> DutyWatcher<StrataClient> {
    pub fn new(config: DutyWatcherConfig, strata_rpc_client: Arc<StrataClient>) -> Self {
        Self {
            config,
            strata_rpc_client,
            last_fetched_duty_index: 0,
            dispatched_duties: HashSet::new(),
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
                        let txid = match &duty {
                            BridgeDuty::SignDeposit(deposit_info) => {
                                deposit_info.deposit_request_outpoint().txid
                            }
                            BridgeDuty::FulfillWithdrawal(withdrawal_info) => {
                                withdrawal_info.deposit_outpoint().txid
                            }
                        };

                        if self.dispatched_duties.contains(&txid) {
                            debug!(action = "ignoring duplicate duty", %txid);
                            continue;
                        }

                        self.dispatched_duties.insert(txid);

                        debug!(action = "dispatching duty", ?duty);
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
