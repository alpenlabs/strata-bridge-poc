use std::{sync::Arc, time::Duration};

use bitcoin::Txid;
use strata_bridge_db::tracker::DutyTrackerDb;
use strata_bridge_primitives::duties::{
    BridgeDuties, BridgeDuty, BridgeDutyRpcResponse, BridgeDutyStatus, DepositStatus,
    WithdrawalStatus,
};
use strata_rpc::StrataApiClient;
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinSet,
};
use tracing::{debug, error, info};

#[derive(Debug, Clone)]
pub struct DutyWatcherConfig {
    pub poll_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct DutyWatcher<StrataClient: StrataApiClient, Db: DutyTrackerDb> {
    config: DutyWatcherConfig,

    strata_rpc_client: Arc<StrataClient>,

    db: Arc<Db>,
}

impl<StrataClient, Db> DutyWatcher<StrataClient, Db>
where
    StrataClient: StrataApiClient + Send + Sync + 'static,
    Db: DutyTrackerDb + Send + Sync + 'static,
{
    pub fn new(
        config: DutyWatcherConfig,
        strata_rpc_client: Arc<StrataClient>,
        db: Arc<Db>,
    ) -> Self {
        Self {
            config,
            strata_rpc_client,
            db,
        }
    }

    pub async fn start(
        &mut self,
        duty_sender: broadcast::Sender<BridgeDuty>,
        status_receiver: mpsc::Receiver<(Txid, BridgeDutyStatus)>,
    ) {
        let mut handles = JoinSet::new();

        let mut status_receiver = status_receiver;
        let db = self.db.clone();

        handles.spawn(async move {
            while let Some((duty_id, status)) = status_receiver.recv().await {
                info!(event = "received duty report", %duty_id, ?status);
                db.update_duty_status(duty_id, status.clone()).await;
                info!(event = "updated duty status in db", %duty_id, ?status);
            }
        });

        let db = self.db.clone();
        let strata_rpc_client = self.strata_rpc_client.clone();
        let poll_interval = self.config.poll_interval;

        handles.spawn(async move {
            loop {
                let operator_idx = u32::MAX; // doesn't really matter in the current impl
                let last_fetched_duty_index = db.get_last_fetched_duty_index().await;

                match strata_rpc_client
                    .get_bridge_duties(operator_idx, last_fetched_duty_index)
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
                            let txid = duty.get_id();

                            // FIXME: store deposit and withdrawal duties to enforce type safety and
                            // remove the ugly nested matches below
                            let stored_status = db.fetch_duty_status(txid).await;
                            if stored_status.as_ref().is_some_and(|status| status.is_done()) {
                                debug!(action = "ignoring duty that has already been executed", %txid);
                                continue;
                            }

                            let bridge_duty = match duty {
                                BridgeDutyRpcResponse::SignDeposit(deposit_info) => {
                                        let status = stored_status.unwrap_or(DepositStatus::Received.into());

                                        match status {
                                            BridgeDutyStatus::Deposit(deposit_status) => BridgeDuty::Deposit { details: deposit_info, status: deposit_status },
                                            _ => unreachable!("deposit duty must be tied to deposit status")
                                        }
                                    },
                                BridgeDutyRpcResponse::FulfillWithdrawal(withdrawal_info) => {
                                        let status = stored_status.unwrap_or(WithdrawalStatus::Received.into());

                                        match status {
                                            BridgeDutyStatus::Withdrawal(withdrawal_status) => BridgeDuty::Withdrawal { details: withdrawal_info, status: withdrawal_status },
                                            _ => unreachable!("withdrawal duty must be tied to withdrawal status"),
                                        }
                                    },
                            };

                            debug!(action = "dispatching duty", ?bridge_duty);
                            duty_sender
                                .send(bridge_duty)
                                .expect("should be able to send duty");
                        }

                        db.set_last_fetched_duty_index(stop_index).await;
                    }
                    Err(e) => {
                        error!(?e, "could not get duties from strata");
                    }
                }

                tokio::time::sleep(poll_interval).await;
            }
        });

        handles.join_all().await;
    }
}
