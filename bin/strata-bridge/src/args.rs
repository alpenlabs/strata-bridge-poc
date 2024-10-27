//! Parses command-line arguments for the bridge-client CLI.
use std::{fmt::Display, path::PathBuf, str::FromStr};

use clap::{crate_version, Parser, ValueEnum};

use crate::constants::{DEFAULT_RPC_HOST, DEFAULT_RPC_PORT};

#[derive(Debug, Parser)]
#[clap(
    name = "strata-bridge",
    about = "The bridge node for Strata",
    version = crate_version!()
)]
pub(crate) struct Cli {
    #[arg(
        value_enum,
        help = "What mode to run the client in `Signer` (alias: si), `Operator` (alias: op) or `Verifier` (alias: ve)",
        default_value_t = OperationMode::Operator,
    )]
    pub mode: OperationMode,

    #[clap(
        long,
        help = "Path to the directory where to store the rocksdb databases",
        default_value = "."
    )]
    pub datadir: PathBuf,

    #[clap(
        long,
        help = "xpriv to be loaded into the bitcoin wallet using the RPC client",
        env = "STRATA_OP_ROOT_XPRIV"
    )]
    pub root_xpriv: String,

    #[clap(
        long,
        help = "Host to run the RPC server on",
        default_value_t = String::from(DEFAULT_RPC_HOST)
    )]
    pub rpc_host: String,

    #[clap(long, help = "Port to run the RPC server on", default_value_t = DEFAULT_RPC_PORT)]
    pub rpc_port: u32,

    #[clap(long, help = "URL for the Bitcoin RPC")]
    pub esplora_url: String,

    #[clap(long, help = "URL for the rollup RPC server")]
    pub strata_url: String,

    #[clap(
        long,
        help = "Bridge duty polling interval in milliseconds (default: block time according to strata RPC)"
    )]
    pub duty_interval: Option<u64>,

    #[clap(
        long,
        help = "Bridge message polling interval in milliseconds (default: half of the block time according to the strata RPC client)"
    )]
    pub message_interval: Option<u64>,
}

#[derive(Debug, Clone, ValueEnum, Parser)]
pub(super) enum OperationMode {
    /// Run client in Operator mode to create/store covenants to handle deposits, withdrawals and
    /// challenging.
    #[clap(alias = "op")]
    Operator,

    /// Run client in Verifier mode to verify/verify Operator claims.
    #[clap(alias = "ch")]
    Verifier,
}

impl Display for OperationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationMode::Operator => write!(f, "operator"),
            OperationMode::Verifier => write!(f, "verifier"),
        }
    }
}

impl FromStr for OperationMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "operator" => Ok(Self::Operator),
            "verifier" => Ok(Self::Verifier),
            _ => Err("Invalid mode".to_string()),
        }
    }
}
