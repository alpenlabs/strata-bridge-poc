//! Module to bootstrap the operator node by hooking up all the required services.

use strata_common::logging;

use crate::cli::Cli;

pub(crate) async fn bootstrap(_args: Cli) -> anyhow::Result<()> {
    logging::init();

    // initialize database
    // instantiate RPC clients for strata and bitcoin
    //
    // spawn signer set with keys from config with db access
    // spawn operators with keys with db access
    // spawn bitcoin watcher with db access
    // spawn verifier with db access

    Ok(())
}
