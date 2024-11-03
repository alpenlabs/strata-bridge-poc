use std::{error::Error, fs, path::PathBuf, process::Command, thread, time::Duration};

use tempfile::{tempdir, TempDir};
use tracing::{info, trace};

#[derive(Debug)]
pub struct BitcoinD<'a> {
    /// URL of the `bitcoind` RPC server.
    pub url: &'a str,
    /// Username for the `bitcoind` RPC server.
    pub user: &'a str,
    /// Password for the `bitcoind` RPC server.
    pub password: &'a str,
    /// Temporary superdirectory where the `bitcoind` data is stored.
    ///
    /// Needed for the drop check.
    _temp_dir: TempDir,
    /// Directory where the `bitcoind` data is stored.
    pub data_dir: PathBuf,
}

impl Default for BitcoinD<'_> {
    fn default() -> Self {
        let url = "http://127.0.0.1:18443";
        let user = "strata";
        let password = "strata";
        BitcoinD::new(url, user, password).expect("Failed to start bitcoind")
    }
}

impl<'a> BitcoinD<'a> {
    /// Creates a new [`BitcoinD`] instance.
    pub fn new(url: &'a str, user: &'a str, password: &'a str) -> Result<Self, Box<dyn Error>> {
        // Creates a temporary data dir
        let temp_dir = tempdir()?;
        let data_dir = temp_dir.path().join("strata-bitcoind");
        fs::create_dir(&data_dir)?;
        info!(?data_dir, "created data directory");

        let process = Command::new("bitcoind")
            .arg("-regtest")
            .arg("-daemon")
            .arg("-rpcuser=strata")
            .arg("-rpcpassword=strata")
            .arg(format!("-datadir={}", data_dir.display()))
            .arg("-fallbackfee=0.00001")
            .spawn()?
            .wait_with_output()?;
        trace!(?process, "bitcoind started");

        thread::sleep(Duration::from_millis(100));

        // wait until the wallet is created
        let process = Command::new("bitcoin-cli")
            .arg("-regtest")
            .arg("-rpcuser=strata")
            .arg("-rpcpassword=strata")
            .arg(format!("-datadir={}", data_dir.display()))
            .arg("createwallet")
            .arg("default")
            .spawn()?
            .wait()?;
        info!("wallet created");
        trace!(?process, "wallet created");

        thread::sleep(Duration::from_millis(100));

        Ok(BitcoinD {
            url,
            user,
            password,
            _temp_dir: temp_dir,
            data_dir,
        })
    }

    /// Returns the `data_dir` [`PathBuf`].
    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }
}

impl Drop for BitcoinD<'_> {
    fn drop(&mut self) {
        // Call bitcoin-cli to stop the bitcoind.
        let _ = Command::new("bitcoin-cli")
            .arg("-regtest")
            .arg("-rpcuser=strata")
            .arg("-rpcpassword=strata")
            .arg(format!("-datadir={}", self.data_dir.display()))
            .arg("stop")
            .spawn()
            .expect("Failed to stop bitcoind")
            .wait();
        // Delete the data_dir
        fs::remove_dir_all(&self.data_dir).expect("Failed to remove data_dir");
    }
}

#[cfg(test)]
mod tests {
    use strata_common::logging;
    use tracing::debug;

    use super::*;

    #[test]
    fn test_bitcoind() {
        logging::init();
        debug!("Starting bitcoind");
        let bitcoind = BitcoinD::default();

        let data_dir = bitcoind.data_dir().clone();
        debug!(?data_dir, "Data directory");

        // Assert that the bitcoind is running
        debug!("Checking if bitcoind is running");
        assert!(Command::new("bitcoin-cli")
            .arg("-regtest")
            .arg("-rpcuser=strata")
            .arg("-rpcpassword=strata")
            .arg(format!("-datadir={}", data_dir.display()))
            .arg("getblockchaininfo")
            .output()
            .is_ok());

        // Assert that the data directory is created
        debug!("Checking if data directory is created");
        assert!(data_dir.exists());
    }

    #[test]
    fn bitcoind_drop_check() {
        let bitcoind = BitcoinD::default();
        let data_dir = bitcoind.data_dir().clone();
        drop(bitcoind);

        // Assert that the bitcoind is stopped
        let output = Command::new("bitcoin-cli")
            .arg("-regtest")
            .arg("-rpcuser=strata")
            .arg("-rpcpassword=strata")
            .arg(format!("-datadir={}", data_dir.display()))
            .arg("getblockchaininfo")
            .output()
            .unwrap();

        debug!(?output, "Output");

        assert_eq!(output.status.code(), Some(1));

        // Check if the data directory is deleted
        assert!(!data_dir.exists());
    }
}
