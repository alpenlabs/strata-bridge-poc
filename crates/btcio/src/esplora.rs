use std::collections::HashMap;

use async_trait::async_trait;
use bitcoin::{Block, BlockHash, Network, Transaction, Txid};
use esplora_client::{r#async::AsyncClient, Builder};
use tracing::*;

use crate::{
    error::{ClientError, ClientResult},
    traits::{Broadcaster, Reader},
    types::{GetBlockchainInfo, TestMempoolAccept},
};

pub struct EsploraClient {
    pub(crate) client: AsyncClient,
    #[allow(dead_code)] // We might need this later
    pub(crate) base_url: String,
    pub(crate) network: Network,
}

impl EsploraClient {
    pub fn new(base_url: String, network: Network) -> Self {
        trace!(%base_url, "creating esplora client");
        let client = Builder::new(&base_url)
            .build_async()
            .expect("failed to build client");
        Self {
            client,
            base_url,
            network,
        }
    }
}

#[async_trait]
impl Reader for EsploraClient {
    async fn estimate_smart_fee(&self, conf_target: u16) -> ClientResult<u64> {
        let fee: HashMap<u16, f64> = self.client.get_fee_estimates().await?;

        // If we have the exact fee rate, return it
        if let Some(&fee_rate) = fee.get(&conf_target) {
            return Ok(fee_rate.round() as u64);
        }

        // Otherwise, search for the nearest both higher and lower
        let mut lower: Option<(u16, f64)> = None;
        let mut higher: Option<(u16, f64)> = None;

        for (&target, &rate) in &fee {
            if target < conf_target {
                if lower.is_none() || target > lower.unwrap().0 {
                    lower = Some((target, rate));
                }
            } else if target > conf_target && (higher.is_none() || target < higher.unwrap().0) {
                higher = Some((target, rate));
            }
        }

        // FIXME: this is ugly AF.
        match (lower, higher) {
            (Some((_, lower_rate)), Some((_, higher_rate))) => {
                // Average the lower and higher rates
                Ok(((lower_rate + higher_rate) / 2.0).round() as u64)
            }
            (Some((_, lower_rate)), None) => Ok(lower_rate.round() as u64),
            (None, Some((_, higher_rate))) => Ok(higher_rate.round() as u64),
            (None, None) => Err(ClientError::Other("No fee estimates available".to_string())),
        }
    }

    async fn get_block(&self, hash: &BlockHash) -> ClientResult<Block> {
        let result = self.client.get_block_by_hash(hash).await?;
        if let Some(block) = result {
            Ok(block)
        } else {
            Err(ClientError::Other(format!("Block not found: {hash}")))
        }
    }

    async fn get_block_at(&self, height: u64) -> ClientResult<Block> {
        let height = height as u32;
        let result = self.client.get_blocks(Some(height)).await?;
        if let Some(summary) = result.first() {
            // get the first one from the vec
            let block_hash = summary.id;
            let block = self.get_block(&block_hash).await?;
            Ok(block)
        } else {
            Err(ClientError::Other(format!("Block not found: {height}")))
        }
    }

    async fn get_block_count(&self) -> ClientResult<u64> {
        Ok(self.client.get_height().await? as u64)
    }

    async fn get_block_hash(&self, height: u64) -> ClientResult<BlockHash> {
        Ok(self.client.get_block_hash(height as u32).await?)
    }

    // NOTE: I don't know if this is possible in esplora.
    async fn get_blockchain_info(&self) -> ClientResult<GetBlockchainInfo> {
        unimplemented!()
    }

    async fn get_superblock(&self, start_time: u64, end_time: u64) -> ClientResult<BlockHash> {
        if start_time >= end_time {
            return Err(ClientError::Other("Invalid time range".to_string()));
        }

        let mut block_hashes = Vec::with_capacity((end_time as usize - start_time as usize) + 1);
        for height in start_time..=end_time {
            // inclusive range
            block_hashes.push(self.get_block_hash(height).await.expect("block hash"))
        }

        block_hashes
            .iter()
            .min()
            .copied()
            .ok_or(ClientError::Other("No block found".to_string()))
    }

    async fn get_current_timestamp(&self) -> ClientResult<u64> {
        let best_block_hash = self.client.get_tip_hash().await?;
        let block = self.get_block(&best_block_hash).await?;
        Ok(block.header.time as u64)
    }

    // NOTE: I don't know if this is possible in esplora.
    async fn get_raw_mempool(&self) -> ClientResult<Vec<Txid>> {
        unimplemented!()
    }

    async fn network(&self) -> ClientResult<Network> {
        Ok(self.network)
    }
}

#[async_trait]
impl Broadcaster for EsploraClient {
    async fn send_raw_transaction(&self, tx: &Transaction) -> ClientResult<Txid> {
        let txid = tx.compute_txid();
        trace!(?tx, "Sending raw transaction");
        debug!(%txid, "Broadcasting transaction");
        let _ = self.client.broadcast(tx).await?;
        Ok(txid)
    }

    // NOTE: I don't know if this is possible in esplora.
    async fn test_mempool_accept(&self, _tx: &Transaction) -> ClientResult<Vec<TestMempoolAccept>> {
        unimplemented!()
    }
}

mod tests {
    #[allow(unused_imports)] // Don't know why this is flagging unused
    use std::str::FromStr;

    use tokio::test;

    use super::*;

    #[allow(dead_code)] // Don't know why this is flagging unused
    const BASE_URL: &str = "https://mempool.space/testnet4/api";
    #[allow(dead_code)] // Don't know why this is flagging unused
    const NETWORK: Network = Network::Testnet;

    #[allow(dead_code)] // Don't know why this is flagging unused
    fn create_client() -> EsploraClient {
        EsploraClient::new(BASE_URL.to_string(), NETWORK)
    }

    #[test]
    async fn estimate_smart_fee() {
        let client = create_client();

        // estimate_smart_fee
        let got = client.estimate_smart_fee(1).await.unwrap();
        assert!(got >= 1);
    }

    #[test]
    async fn get_block() {
        let client = create_client();

        // block 1337 (EASTER EGG SPOTTED)
        let hash =
            BlockHash::from_str("0000000028617006aab774b7d36fbe28c960aade7db34294ac2f24c5f68eef0a")
                .unwrap();
        let got = client
            .get_block(&hash)
            .await
            .unwrap()
            .bip34_block_height()
            .unwrap();
        let expected = 1337;
        assert_eq!(got, expected);
    }

    #[test]
    async fn get_block_at() {
        let client = create_client();

        // block 1337 (EASTER EGG SPOTTED)
        let got = client.get_block_at(1337).await.unwrap().header.block_hash();
        let expected =
            BlockHash::from_str("0000000028617006aab774b7d36fbe28c960aade7db34294ac2f24c5f68eef0a")
                .unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    async fn get_block_count() {
        let client = create_client();

        let got = client.get_block_count().await.unwrap();
        assert!(got >= 52742); // 2024-10-29
    }

    #[test]
    async fn get_block_hash() {
        let client = create_client();

        // block 1337 (EASTER EGG SPOTTED)
        let got = client.get_block_hash(1337).await.unwrap();
        let expected =
            BlockHash::from_str("0000000028617006aab774b7d36fbe28c960aade7db34294ac2f24c5f68eef0a")
                .unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    async fn get_superblock() {
        let client = create_client();

        let got = client.get_superblock(50, 100).await.unwrap();
        let block_hash_50 = client.get_block_hash(50).await.unwrap();
        let block_hash_100 = client.get_block_hash(100).await.unwrap();
        assert!(got <= block_hash_50);
        assert!(got <= block_hash_100);
    }
}
