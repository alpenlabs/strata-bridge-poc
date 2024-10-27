//! Module to bootstrap the operator node by hooking up all the required services.

use bitcoin::{
    bip32::Xpriv,
    key::Parity,
    secp256k1::{PublicKey, SecretKey, XOnlyPublicKey},
};
use jsonrpsee::{core::client::async_client::Client as L2RpcClient, ws_client::WsClientBuilder};
use secp256k1::SECP256K1;
use strata_primitives::bridge::OperatorIdx;
use strata_rpc_api::StrataApiClient;
use tracing::{error, info};

use crate::{
    args::Cli,
    rpc_server::{self, BridgeRpc},
    xpriv::derive_op_purpose_xprivs,
};

/// Bootstraps the bridge client in Operator mode by hooking up all the required auxiliary services
/// including database, rpc server, etc. Logging needs to be initialized at the call
/// site (main function) itself.
pub(crate) async fn bootstrap(args: Cli) -> anyhow::Result<()> {
    // // Parse the data_dir
    // let data_dir = args.datadir.map(PathBuf::from);
    //
    // // Initialize a rocksdb instance with the required column families.
    // let rbdb = open_rocksdb_database(data_dir)?;
    // let retry_count = args.retry_count.unwrap_or(ROCKSDB_RETRY_COUNT);
    // let ops_config = DbOpsConfig::new(retry_count);
    //
    // // Setup Threadpool for the database I/O ops.
    // let bridge_db_pool = ThreadPool::new(DB_THREAD_COUNT);
    //
    // // Setup bridge duty databases.
    // let bridge_duty_db = BridgeDutyRocksDb::new(rbdb.clone(), ops_config);
    // let bridge_duty_db_ctx = DutyContext::new(Arc::new(bridge_duty_db));
    // let bridge_duty_db_ops = Arc::new(bridge_duty_db_ctx.into_ops(bridge_db_pool.clone()));
    //
    // let bridge_duty_idx_db = BridgeDutyIndexRocksDb::new(rbdb.clone(), ops_config);
    // let bridge_duty_idx_db_ctx = DutyIndexContext::new(Arc::new(bridge_duty_idx_db));
    // let bridge_duty_idx_db_ops =
    // Arc::new(bridge_duty_idx_db_ctx.into_ops(bridge_db_pool.clone()));
    //
    // // Setup RPC clients.
    // let l1_rpc_client = Arc::new(
    //     BitcoinClient::new(args.btc_url, args.btc_user, args.btc_pass)
    //         .expect("error creating the bitcoin client"),
    // );
    let l2_rpc_client: L2RpcClient = WsClientBuilder::default()
        .build(args.strata_url)
        .await
        .expect("failed to connect to the rollup RPC server");

    // Get the keypair after deriving the wallet xpriv.
    let root_xpriv = args
        .root_xpriv
        .parse::<Xpriv>()
        .expect("could not parse xpriv");
    let (_, wallet_xpriv) = derive_op_purpose_xprivs(&root_xpriv)?;

    let keypair = wallet_xpriv.to_keypair(SECP256K1);
    let mut sk = SecretKey::from_keypair(&keypair);

    // adjust for parity, which should always be even
    let (_, parity) = XOnlyPublicKey::from_keypair(&keypair);
    if matches!(parity, Parity::Odd) {
        sk = sk.negate();
        // keypair = Keypair::from_secret_key(SECP256K1, &sk);
    };

    let pubkey = PublicKey::from_secret_key(SECP256K1, &sk);

    // Get this client's pubkey from the bitcoin wallet.
    let operator_pubkeys = l2_rpc_client.get_active_operator_chain_pubkey_set().await?;
    let own_index: OperatorIdx = operator_pubkeys
        .0
        .iter()
        .find_map(|(id, pk)| {
            if pk.to_string() == pubkey.to_string() {
                Some(*id)
            } else {
                None
            }
        })
        .expect("could not find this operator's pubkey in the rollup pubkey table");

    info!(%own_index, "got own index");
    //
    // // Set up the signature manager.
    // let bridge_tx_db = BridgeTxRocksDb::new(rbdb, ops_config);
    // let bridge_tx_db_ctx = TxContext::new(Arc::new(bridge_tx_db));
    // let bridge_tx_db_ops = Arc::new(bridge_tx_db_ctx.into_ops(bridge_db_pool));
    // let sig_manager = SignatureManager::new(bridge_tx_db_ops, own_index, keypair);
    //
    // // Set up the TxBuildContext.
    // let network = l1_rpc_client.network().await?;
    // let tx_context = TxBuildContext::new(network, operator_pubkeys, own_index);
    //
    // Spawn RPC server.
    let bridge_rpc = BridgeRpc::new();

    let rpc_addr = format!("{}:{}", args.rpc_host, args.rpc_port);

    let rpc_task = tokio::spawn(async move {
        if let Err(e) = rpc_server::start(&bridge_rpc, rpc_addr.as_str()).await {
            error!(error = %e, "could not start RPC server");
        }
    });

    //
    // let rollup_block_time = l2_rpc_client
    //     .block_time()
    //     .await
    //     .expect("should be able to get block time from rollup RPC client");
    //
    // let msg_polling_interval = args.message_interval.map_or(
    //     Duration::from_millis(rollup_block_time / 2),
    //     Duration::from_millis,
    // );
    //
    // // Spawn poll duties task.
    // let exec_handler = ExecHandler {
    //     tx_build_ctx: tx_context,
    //     sig_manager,
    //     l2_rpc_client,
    //     keypair,
    //     own_index,
    //     msg_polling_interval,
    // };
    //
    // let task_manager = TaskManager {
    //     exec_handler: Arc::new(exec_handler),
    //     broadcaster: l1_rpc_client,
    //     bridge_duty_db_ops,
    //     bridge_duty_idx_db_ops,
    // };
    //
    // let duty_polling_interval = args.duty_interval.map_or(
    //     Duration::from_millis(rollup_block_time),
    //     Duration::from_millis,
    // );
    //
    // // TODO: wrap these in `strata-tasks`
    // // let duty_task = tokio::spawn(async move {
    // //     if let Err(e) = task_manager.start(duty_polling_interval).await {
    // //         error!(error = %e, "could not start task manager");
    // //     };
    // // });

    // Wait for all tasks to run
    // They are supposed to run indefinitely in most cases
    // tokio::try_join!(rpc_task, duty_task)?;
    tokio::try_join!(rpc_task)?;

    Ok(())
}
