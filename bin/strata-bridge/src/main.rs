//! Bridge Operator client.
//!
//! Responsible for facilitating bridge-in and bridge-out operations by creating, storing and
//! publishing appropriate transactions. Can also perform challenger duties.

mod args;
pub(crate) mod constants;
mod modes;
pub(crate) mod rpc_server;
mod xpriv;

use args::{Cli, OperationMode};
use clap::Parser;
use modes::{operator, verifier};
use strata_common::logging;
use tracing::info;

#[tokio::main]
async fn main() {
    logging::init();

    let cli_args: Cli = Cli::parse();

    info!("running bridge client in {} mode", cli_args.mode);

    match cli_args.mode {
        OperationMode::Operator => {
            operator::bootstrap(cli_args)
                .await
                .expect("bootstrap operator node");
        }
        OperationMode::Verifier => {
            verifier::bootstrap().await;
        }
    }
}
