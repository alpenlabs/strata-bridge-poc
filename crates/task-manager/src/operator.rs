use std::{sync::Arc, time::Duration};

use esplora_client::AsyncClient;
use jsonrpsee::core::client::async_client::Client as L2RpcClient;
use strata_bridge_client::BitVMClient;
use strata_bridge_tx_builder::prelude::{CooperativeWithdrawalInfo, DepositInfo};
use strata_bridge_tx_graph::transactions::peg_out::PegOutTransaction;
use strata_rpc_api::StrataApiClient;
use strata_rpc_types::BridgeDuties;
use strata_state::bridge_duties::BridgeDuty;
use tokio::{sync::mpsc, task::JoinSet};
use tracing::error;

use crate::config::TaskConfig;

#[derive(Debug)]
pub struct TaskManager {
    pub bitvm_client: Arc<BitVMClient>,

    pub duty_poll_interval: Duration,

    pub l2_rpc_client: Arc<L2RpcClient>,

    pub esplora_client: Arc<AsyncClient>,

    pub config: TaskConfig,
    // add db
}

impl TaskManager {
    pub async fn start(&self) {
        let (deposit_duty_sender, mut deposit_duty_receiver) =
            mpsc::channel::<DepositInfo>(self.config.task_queue_size);
        let (withdrawal_duty_sender, mut withdrawal_duty_receiver) =
            mpsc::channel::<CooperativeWithdrawalInfo>(self.config.task_queue_size);

        let l2_rpc_client = self.l2_rpc_client.clone();
        let duty_poll_interval = self.duty_poll_interval;

        let mut handles = JoinSet::new();

        handles.spawn(async move {
            poll_for_duties(
                l2_rpc_client,
                deposit_duty_sender,
                withdrawal_duty_sender,
                duty_poll_interval,
            )
            .await
        });

        let bitvm_client = self.bitvm_client.clone();
        handles
            .spawn(async move { deposit_handler(bitvm_client, &mut deposit_duty_receiver).await });

        let bitvm_client = self.bitvm_client.clone();
        handles.spawn(async move {
            withdrawal_intent_handler(bitvm_client, &mut withdrawal_duty_receiver).await
        });

        let results = handles.join_all().await;

        for result in results {
            if let Err(e) = result {
                error!(%e, "task manager encountered error");
            }
        }

        unreachable!("task manager failed; please check logs");
    }
}

pub async fn poll_for_duties(
    l2_rpc_client: Arc<L2RpcClient>,
    deposit_duty_sender: mpsc::Sender<DepositInfo>,
    withdrawal_duty_sender: mpsc::Sender<CooperativeWithdrawalInfo>,
    duty_poll_interval: Duration,
) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(duty_poll_interval);

    loop {
        let BridgeDuties {
            duties,
            start_index: _,
            stop_index: _,
        } = l2_rpc_client.get_bridge_duties(0u32, 0).await?;

        for duty in duties {
            match duty {
                BridgeDuty::SignDeposit(deposit_request) => {
                    deposit_duty_sender.send(deposit_request).await?;
                    todo!("sign the covenant with the BitVM2 Client if this particular deposit is new");
                }
                BridgeDuty::FulfillWithdrawal(withdrawal_intent) => {
                    withdrawal_duty_sender.send(withdrawal_intent).await?;
                    todo!("store the duty in the database indexed by the UTXO to match against any BridgeOut requests");
                }
            }
        }

        ticker.tick().await;
    }
}

pub async fn deposit_handler(
    _bitvm_client: Arc<BitVMClient>,
    deposit_receiver: &mut mpsc::Receiver<DepositInfo>,
) -> anyhow::Result<()> {
    while let Some(_deposit_request) = deposit_receiver.recv().await {
        todo!("handle creation of covenant and the publishing of the PegIn Tx");
    }

    Ok(())
}

pub async fn withdrawal_intent_handler(
    _bitvm_client: Arc<BitVMClient>,
    withdrawal_intent_receiver: &mut mpsc::Receiver<CooperativeWithdrawalInfo>,
) -> anyhow::Result<()> {
    while let Some(_withdrawal_intent) = withdrawal_intent_receiver.recv().await {
        todo!("just store the withdrawal intent in the database to query later");
    }

    Ok(())
}

pub async fn withdrawal_handler(
    _bitvm_client: &Arc<BitVMClient>,
    _peg_out_tx: PegOutTransaction,
) -> anyhow::Result<()> {
    todo!("check that the fees are enough and then, fund the transaction and broadcast");
}
