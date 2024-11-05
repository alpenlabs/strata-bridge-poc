//! Parses command-line arguments for the bridge-client CLI.

use std::{path::PathBuf, time::Duration};

use clap::{crate_version, Parser};

use crate::constants::{DEFAULT_RPC_HOST, DEFAULT_RPC_PORT};

#[derive(Debug, Parser)]
#[clap(
    name = "strata-bridge",
    about = "The bridge node for Strata",
    version = crate_version!()
)]
pub(crate) struct Cli {
    #[clap(long, help = "ws URL of the rollup RPC server")]
    pub strata_url: String,

    #[clap(long, help = "Request timeout for websocket connection to strata (in secs)", default_value = "300", value_parser = parse_duration)]
    pub strata_ws_timeout: Duration,

    #[clap(long, help = "URL of the bitcoind node")]
    pub btc_url: String,

    #[clap(long, help = "Bitcoind username")]
    pub btc_user: String,

    #[clap(long, help = "Bitcoind password")]
    pub btc_pass: String,

    #[clap(long, help = "RPC server host for the bridge node", default_value_t = DEFAULT_RPC_HOST.to_string())]
    pub rpc_host: String,

    #[clap(long, help = "RPC server host for the bridge node", default_value_t = DEFAULT_RPC_PORT)]
    pub rpc_port: u32,

    #[clap(
        long,
        help = "percentage of operators that are faulty (max: 100)",
        default_value_t = 20,
        value_parser = parse_fault_tolerance,
    )]
    pub fault_tolerance: u8,

    #[clap(
        long,
        default_value = "30",
        help = "Bridge duty polling interval (in secs)",
        value_parser = parse_duration,
    )]
    pub duty_interval: Duration,

    #[clap(
        long,
        help = "The file containing the list of client privkeys to use (one per line)",
        default_value = "xpriv.bin"
    )]
    pub xpriv_file: PathBuf,
}

fn parse_duration(arg: &str) -> Result<Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;

    Ok(std::time::Duration::from_secs(seconds))
}

fn parse_fault_tolerance(arg: &str) -> anyhow::Result<u8> {
    let value: u8 = arg.parse()?;

    let value = value.min(100);

    Ok(value)
}
