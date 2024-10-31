use std::collections::HashMap;

use async_trait::async_trait;
use bitcoin::{block::Header, Block, BlockHash, Network, Transaction, Txid};
use esplora_client::{r#async::AsyncClient, Builder};
use tracing::*;

use crate::{
    error::{ClientError, ClientResult},
    traits::{Broadcaster, Reader},
    types::{GetBlockchainInfo, TestMempoolAccept},
    BLOCK_TIME,
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

    async fn get_block_at(&self, height: u32) -> ClientResult<Block> {
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

    async fn get_block_count(&self) -> ClientResult<u32> {
        Ok(self.client.get_height().await?)
    }

    async fn get_block_hash(&self, height: u32) -> ClientResult<BlockHash> {
        Ok(self.client.get_block_hash(height).await?)
    }

    // NOTE: I don't know if this is possible in esplora.
    async fn get_blockchain_info(&self) -> ClientResult<GetBlockchainInfo> {
        unimplemented!()
    }

    async fn get_superblock(
        &self,
        start_time: u32,
        end_time: u32,
        block_time: Option<u32>,
    ) -> ClientResult<Header> {
        if start_time >= end_time {
            return Err(ClientError::Other("Invalid time range".to_string()));
        }

        if end_time > self.get_current_timestamp().await? {
            return Err(ClientError::Other("End time is in the future".to_string()));
        }

        let block_time = block_time.unwrap_or(BLOCK_TIME);
        // inclusive range that's why we add 1.
        let n_blocks = ((end_time - start_time) / block_time) + 1;

        // iterate over the chaintip and get the blocks, while trying to be clever
        // in order to minimize the number of requests.
        let mut blocks_to_include = Vec::with_capacity(n_blocks as usize);
        let chain_tip = self.get_block_count().await?;
        let current_time = self.get_current_timestamp().await?;

        // Finding the last block with a timestamp less than the end_time
        // using 2 * block_time as leeway
        let delta_with_leeway = current_time
            .checked_sub(end_time)
            .and_then(|delta| delta.checked_add(2 * block_time))
            .ok_or(ClientError::Other(
                "Overflow occurred in delta_with_leeway calculation".to_string(),
            ))?;

        // Finding the potential last block
        let potential_last_block_height = chain_tip - delta_with_leeway / block_time;
        let mut last_block = {
            let hash = self.get_block_hash(potential_last_block_height).await?;
            self.get_block(&hash).await?
        };
        while last_block.header.time > end_time {
            let hash = last_block.header.prev_blockhash;
            last_block = self.get_block(&hash).await?;
            if last_block.header.time < start_time {
                return Err(ClientError::Other("No block found".to_string()));
            }
        }

        // Found the last block
        blocks_to_include.push(last_block.header); // Only include the header

        // Now, continue going backwards until we find the first block
        let mut first_block = last_block.clone();
        while first_block.header.time > start_time {
            let hash = first_block.header.prev_blockhash;
            first_block = self.get_block(&hash).await?;
            // Since we are iterating backwards, let's add'em to the blocks_to_include
            blocks_to_include.push(first_block.header); // Only include the header
            if first_block.header.time < start_time {
                return Err(ClientError::Other("No block found".to_string()));
            }
        }

        // We have all the block headers, let's return the one with the lowest hash.
        blocks_to_include
            .iter()
            .min_by(|a, b| a.block_hash().cmp(&b.block_hash()))
            .copied()
            .ok_or(ClientError::Other("No block found".to_string()))
    }

    async fn get_current_timestamp(&self) -> ClientResult<u32> {
        let best_block_hash = self.client.get_tip_hash().await?;
        let block = self.get_block(&best_block_hash).await?;
        Ok(block.header.time)
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

    use tokio::{
        test,
        time::{sleep, Duration},
    };

    use super::*;

    #[allow(dead_code)] // Don't know why this is flagging unused
    const BASE_URL: &str = "https://mempool.space/testnet4/api";
    #[allow(dead_code)] // Don't know why this is flagging unused
    const NETWORK: Network = Network::Testnet;

    #[allow(dead_code)] // Don't know why this is flagging unused
    async fn create_client() -> EsploraClient {
        sleep(Duration::from_millis(500)).await; // To avoid spamming the esplora API
        EsploraClient::new(BASE_URL.to_string(), NETWORK)
    }

    #[test]
    async fn estimate_smart_fee() {
        let client = create_client().await;

        // estimate_smart_fee
        let got = client.estimate_smart_fee(1).await.unwrap();
        assert!(got >= 1);
    }

    #[test]
    async fn get_block() {
        let client = create_client().await;

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
        let client = create_client().await;

        // block 1337 (EASTER EGG SPOTTED)
        let got = client.get_block_at(1337).await.unwrap().header.block_hash();
        let expected =
            BlockHash::from_str("0000000028617006aab774b7d36fbe28c960aade7db34294ac2f24c5f68eef0a")
                .unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    async fn get_block_count() {
        let client = create_client().await;

        let got = client.get_block_count().await.unwrap();
        assert!(got >= 52742); // 2024-10-29
    }

    #[test]
    async fn get_block_hash() {
        let client = create_client().await;

        // block 1337 (EASTER EGG SPOTTED)
        let got = client.get_block_hash(1337).await.unwrap();
        let expected =
            BlockHash::from_str("0000000028617006aab774b7d36fbe28c960aade7db34294ac2f24c5f68eef0a")
                .unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    async fn get_superblock() {
        let client = create_client().await;

        // This is pointing towards testnet4, hence block time is 10 minutes := 600 seconds.
        let block_time = 600;
        let current_time = client.get_current_timestamp().await.unwrap();
        sleep(Duration::from_millis(500)).await; // To avoid spamming the esplora API

        // To avoid spamming the network, let's get the superblock from 1 hour ago until 30 minutes
        // ago.
        let start_time = current_time - (3600 * 2);
        let end_time = current_time - (3600.0 * 1.5) as u32;

        let got = client
            .get_superblock(start_time, end_time, Some(block_time))
            .await
            .unwrap();

        sleep(Duration::from_millis(500)).await; // To avoid spamming the esplora API
        let block_hash_previous = client.get_block(&got.prev_blockhash).await.unwrap();

        assert!(got.block_hash() <= block_hash_previous.header.block_hash());
    }
}
