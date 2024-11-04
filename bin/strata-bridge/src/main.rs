//! Bridge Operator client.
//!
//! Responsible for facilitating bridge-in and bridge-out operations by creating, storing and
//! publishing appropriate transactions. Can also perform challenger duties.

mod bootstrap;
mod cli;
pub mod xpriv;

use bootstrap::bootstrap;
use clap::Parser;
use cli::Cli;

#[tokio::main]
async fn main() {
    let cli_args: Cli = Cli::parse();

    bootstrap(cli_args)
        .await
        .expect("should be able to bootstrap node");
}
