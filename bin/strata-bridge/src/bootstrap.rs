//! Module to bootstrap the operator node by hooking up all the required services.

use std::sync::Arc;

use bitcoin::Address;
use jsonrpsee::ws_client::WsClientBuilder;
use rand::{rngs::OsRng, Rng};
use secp256k1::SECP256K1;
use strata_bridge_agent::{
    base::Agent,
    duty_watcher::{DutyWatcher, DutyWatcherConfig},
    operator::Operator,
    signal::{CovenantSignal, DepositSignal},
};
use strata_bridge_btcio::traits::Reader;
use strata_bridge_db::{operator::OperatorDb, public::PublicDb};
use strata_bridge_primitives::{
    build_context::{BuildContext, TxBuildContext},
    duties::BridgeDuty,
    types::PublickeyTable,
};
use strata_common::logging;
use strata_rpc::StrataApiClient;
use tokio::{sync::broadcast, task::JoinSet};
use tracing::{error, info};

use crate::{
    cli::Cli,
    constants::{COVENANT_QUEUE_MULTIPLIER, DEPOSIT_QUEUE_MULTIPLIER, DUTY_QUEUE_SIZE},
    rpc_server::{self, BridgeRpc},
    xpriv::get_keypairs_and_load_xpriv,
};

pub(crate) async fn bootstrap(args: Cli) {
    logging::init();

    // instantiate RPC client for Strata and Bitcoin
    let strata_rpc_client = WsClientBuilder::default()
        .request_timeout(args.strata_ws_timeout)
        .build(args.strata_url.as_str())
        .await
        .expect("failed to connect to the strata RPC server");

    let pubkey_table = strata_rpc_client
        .get_active_operator_chain_pubkey_set()
        .await
        .expect("should be able to fetch pubkey table");

    let duty_watcher_config = DutyWatcherConfig {
        poll_interval: args.duty_interval,
    };

    let mut duty_watcher = DutyWatcher::new(duty_watcher_config, Arc::new(strata_rpc_client));

    let (duty_sender, _duty_receiver) = broadcast::channel::<BridgeDuty>(DUTY_QUEUE_SIZE);

    let operators = generate_operator_set(&args, pubkey_table).await;

    let mut tasks = JoinSet::new();

    let duty_sender_copy = duty_sender.clone();
    tasks.spawn(async move {
        duty_watcher.start(duty_sender_copy.clone()).await;
    });

    for operator in operators {
        let mut duty_receiver = duty_sender.subscribe();

        tasks.spawn(async move {
            let mut operator = operator;
            operator.start(&mut duty_receiver).await;
        });
    }

    // TODO: spawn verifier

    // spawn rpc server
    let bridge_rpc = BridgeRpc::new();

    let rpc_host = args.rpc_host.clone();
    let rpc_port = args.rpc_port;
    let rpc_addr = format!("{rpc_host}:{rpc_port}");

    tasks.spawn(async move {
        if let Err(e) = rpc_server::start(&bridge_rpc, rpc_addr.as_str()).await {
            error!(error = %e, "could not start RPC server");
        }
    });

    tasks.join_all().await;
}

pub async fn generate_operator_set(args: &Cli, pubkey_table: PublickeyTable) -> Vec<Operator> {
    // initialize public database
    let public_db = PublicDb::default();

    public_db.set_musig_pubkey_table(&pubkey_table.0).await;

    let operator_indexes_and_keypairs =
        get_keypairs_and_load_xpriv(&args.xpriv_file, &pubkey_table);

    let num_operators = operator_indexes_and_keypairs.len();

    assert!(
        num_operators == pubkey_table.0.len(),
        "operator count in strata and number of xprivs do not match"
    );

    let deposit_queue_size = num_operators * DEPOSIT_QUEUE_MULTIPLIER; // buffer for nonces and signatures (overkill)
    let (deposit_signal_sender, _deposit_signal_receiver) =
        broadcast::channel::<DepositSignal>(deposit_queue_size);

    let covenant_queue_size = num_operators * COVENANT_QUEUE_MULTIPLIER; // higher 'cause signatures are sent in bulk
    let (covenant_signal_sender, _covenant_signal_receiver) =
        broadcast::channel::<CovenantSignal>(covenant_queue_size);

    let mut faulty_idxs = Vec::new();
    let mut operator_set: Vec<Operator> = Vec::with_capacity(num_operators);
    for (operator_idx, keypair) in operator_indexes_and_keypairs {
        let agent = Agent::new(keypair, &args.btc_url, &args.btc_user, &args.btc_pass).await;

        let network = agent
            .client
            .network()
            .await
            .expect("should be able to get network information");

        let build_context = TxBuildContext::new(network, pubkey_table.clone(), operator_idx);

        let aggregated_pubkey = build_context.aggregated_pubkey();
        let bridge_address = Address::p2tr(SECP256K1, aggregated_pubkey, None, network);
        info!(event = "build context initialized", %bridge_address, %network, %aggregated_pubkey);

        let is_faulty = OsRng.gen_ratio(args.fault_tolerance as u32, 100);

        faulty_idxs.push(operator_idx);

        let operator_db = OperatorDb::default();
        let operator = Operator::new(
            agent,
            build_context,
            is_faulty,
            operator_db,
            public_db.clone(),
            deposit_signal_sender.clone(),
            deposit_signal_sender.subscribe(),
            covenant_signal_sender.clone(),
            covenant_signal_sender.subscribe(),
        )
        .await;

        operator_set.push(operator);
    }

    info!(event = "operator set initialization complete", %num_operators, num_faulty_operators=%faulty_idxs.len(), ?faulty_idxs);

    operator_set
}
