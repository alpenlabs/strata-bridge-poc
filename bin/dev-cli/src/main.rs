mod bridge_in;
mod bridge_out;

use std::str::FromStr;

use alloy::{
    network::EthereumWallet,
    primitives::{Address as EvmAddress, U256},
    signers::local::PrivateKeySigner,
};
use alloy_signer::k256::ecdsa::SigningKey;
use anyhow::{Context, Error, Result};
use bitcoin::{secp256k1::Secp256k1, Amount};
use bridge_in::deposit_request;
use clap::Parser;
use tracing::info;

use crate::bridge_in::wallet::PsbtWallet;

mod constants;

mod cli;

fn main() -> Result<(), Error> {
    let cli = cli::Cli::parse();
    match cli.command {
        cli::Commands::BridgeIn(args) => handle_bridge_in(args),
        cli::Commands::BridgeOut(args) => handle_bridge_out(args),
    }
}

fn handle_bridge_in(args: cli::BridgeInArgs) -> Result<()> {
    let deposit_amount = Amount::from_btc(10.0)?;
    let rpc_client = crate::bridge_in::bitcoin_rpc_client::setup_rpc(
        &args.btc_url,
        args.btc_user,
        args.btc_pass,
    );
    let psbt_wallet = crate::bridge_in::wallet::BitcoinRpcWallet::new(rpc_client);
    let secp = Secp256k1::new();

    info!(action = "Initiating bridge-in", %deposit_amount, strata_address=%args.strata_address);

    let strata_address = EvmAddress::from_str(&args.strata_address)?;
    let recovery_pubkey = deposit_request::get_recovery_pubkey();

    let aggregated_pubkey = deposit_request::get_aggregated_pubkey();

    let n_of_n_multisig_script =
        crate::bridge_in::deposit_request::build_n_of_n_multisig_miniscript(aggregated_pubkey);
    let timelock_script =
        crate::bridge_in::deposit_request::build_timelock_miniscript(recovery_pubkey);

    let (script_hash, taproot_address) =
        crate::bridge_in::deposit_request::generate_taproot_address(
            &secp,
            n_of_n_multisig_script,
            timelock_script,
        );

    let psbt = psbt_wallet.create_psbt(
        &taproot_address,
        &strata_address,
        &script_hash,
        &constants::NETWORK,
    )?;
    psbt_wallet.sign_and_broadcast_psbt(&psbt)?;

    Ok(())
}

fn handle_bridge_out(args: cli::BridgeOutArgs) -> Result<()> {
    let private_key_bytes = hex::decode(args.private_key).context("decode private key")?;
    let signing_key = SigningKey::from_slice(&private_key_bytes).context("signing key")?;

    let signer = PrivateKeySigner::from(signing_key);
    let wallet = EthereumWallet::new(signer);

    let data: Vec<u8> =
        hex::decode(args.destination_address_pubkey).context("decode address pubkey")?;
    let amount = U256::from(constants::BRIDGE_OUT_AMOUNT.to_sat() as u128 * constants::SATS_TO_WEI);
    let rollup_address =
        EvmAddress::from_str(constants::ROLLUP_ADDRESS).context("precompile address")?;

    let runtime = tokio::runtime::Runtime::new()?;
    let tx = runtime.block_on(
        crate::bridge_out::withdrawal::create_withdrawal_transaction(
            rollup_address,
            constants::ETH_RPC_URL,
            data,
            &wallet,
            amount,
        ),
    );

    info!(
        event = "Withdrawal transaction created and sent successfully",
        ?tx
    );

    Ok(())
}
