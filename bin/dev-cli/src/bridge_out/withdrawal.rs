use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address as EvmAddress, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{TransactionInput, TransactionRequest},
};
use eyre::Result;
use tracing::info;

pub(crate) async fn create_withdrawal_transaction(
    rollup_address: EvmAddress,
    eth_rpc_url: &str,
    data: Vec<u8>,
    wallet: &EthereumWallet,
    amount: U256,
) -> Result<TransactionRequest> {
    // Build a transaction to call the withdrawal precompile
    let tx = TransactionRequest::default()
        .with_to(rollup_address)
        .with_value(amount)
        .input(TransactionInput::new(Bytes::from(data)));

    // Send the transaction and listen for the transaction to be included.
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_http(eth_rpc_url.parse()?);

    let tx_hash = provider.send_transaction(tx.clone()).await?.watch().await?;

    info!(event = "Sent transaction: {:?}", %tx_hash);

    Ok(tx)
}
