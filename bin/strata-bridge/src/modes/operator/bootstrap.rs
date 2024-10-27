//! Module to bootstrap the operator node by hooking up all the required services.

use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::Context;
use bitcoin::{
    bip32::Xpriv,
    hex,
    key::Parity,
    secp256k1::{PublicKey, SecretKey, XOnlyPublicKey},
    Network,
};
use esplora_client::Builder as EsploraBuilder;
use hex::prelude::*;
use jsonrpsee::{core::client::async_client::Client as L2RpcClient, ws_client::WsClientBuilder};
use secp256k1::SECP256K1;
use strata_bridge_client::BitVMClient;
use strata_bridge_task_manager::{config::TaskConfig, operator::TaskManager};
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
    let l2_rpc_client: L2RpcClient = WsClientBuilder::default()
        .build(args.strata_url)
        .await
        .expect("failed to connect to the rollup RPC server");
    let l2_rpc_client = Arc::new(l2_rpc_client);

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

    let source_network = l2_rpc_client
        .get_l1_status()
        .await
        .context("unable to get bitcoin status from strata")
        .expect("should be able to connect to strata node")
        .network
        .to_string();
    let source_network = Network::from_str(&source_network).unwrap();

    let n_of_n_public_keys = &operator_pubkeys
        .0
        .values()
        .copied()
        .map(|pk| bitcoin::PublicKey::from_str(&pk.to_string()).unwrap())
        .collect::<Vec<_>>()[..];

    let operator_secret = format!("{:x}", sk.as_ref().as_hex());
    let bitvm_client = BitVMClient::new(
        source_network,
        &args.esplora_url,
        n_of_n_public_keys,
        None,
        Some(operator_secret.as_str()),
        None,
        None,
    )
    .await;
    let bitvm_client = Arc::new(bitvm_client);

    let esplora_client = EsploraBuilder::new(&args.esplora_url)
        .build_async()
        .expect("Could not build esplora client");
    let esplora_client = Arc::new(esplora_client);

    let task_config = TaskConfig {
        task_queue_size: 100,
    };

    let rollup_block_time = l2_rpc_client
        .block_time()
        .await
        .expect("should be able to get block time from rollup RPC client");

    let duty_poll_interval = args.duty_interval.unwrap_or(rollup_block_time);
    let duty_poll_interval = Duration::from_millis(duty_poll_interval);

    let task_manager = TaskManager {
        bitvm_client: bitvm_client.clone(),
        duty_poll_interval,
        l2_rpc_client,
        esplora_client,
        config: task_config,
    };

    // Spawn operator task manager
    let duty_task = tokio::spawn(async move {
        task_manager.start().await;
    });

    // Spawn RPC server.
    let bridge_rpc = BridgeRpc::new();

    let rpc_addr = format!("{}:{}", args.rpc_host, args.rpc_port);

    let rpc_task = tokio::spawn(async move {
        if let Err(e) = rpc_server::start(&bridge_rpc, rpc_addr.as_str()).await {
            error!(error = %e, "could not start RPC server");
        }
    });

    // Wait for all tasks to run
    // They are supposed to run indefinitely in most cases
    // tokio::try_join!(rpc_task, duty_task)?;
    tokio::try_join!(rpc_task, duty_task)?;

    Ok(())
}
