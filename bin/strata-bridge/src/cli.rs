//! Parses command-line arguments for the bridge-client CLI.

use clap::{crate_version, Parser};

#[derive(Debug, Parser)]
#[clap(
    name = "strata-bridge",
    about = "The bridge node for Strata",
    version = crate_version!()
)]
pub(crate) struct Cli {
    #[clap(long, help = "URL for the rollup RPC server")]
    pub strata_url: String,

    #[clap(long, help = "Bitcoind username")]
    pub btc_user: String,

    #[clap(long, help = "Bitcoind password")]
    pub btc_pass: String,

    #[clap(
        long,
        default_value_t = 30_000,
        help = "Bridge duty polling interval (in milliseconds)"
    )]
    pub duty_interval: u64,
}
