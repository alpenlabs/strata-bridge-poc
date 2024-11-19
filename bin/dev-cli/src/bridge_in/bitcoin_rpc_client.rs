use anyhow::anyhow;
use bitcoincore_rpc::{Auth, Client};

pub(crate) fn setup_rpc(url: &str, user: Option<String>, password: Option<String>) -> Client {
    let rpc_url = url;
    let rpc_auth = Auth::UserPass(user.unwrap(), password.unwrap());
    Client::new(rpc_url, rpc_auth)
        .map_err(|e| anyhow!("Failed to connect to RPC: {}", e))
        .unwrap()
}
