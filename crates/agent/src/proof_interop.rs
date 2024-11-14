use bitcoin::{
    block::Header,
    blockdata::block::Block,
    consensus::encode::{deserialize_hex, serialize_hex},
    hashes::Hash,
    merkle_tree::PartialMerkleTree,
    Transaction, Txid, Wtxid,
};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone)]
pub struct InclusionProof(pub PartialMerkleTree);

/// Implement `Serialize` for `PartialMerkleTree` using hex encoding.
impl Serialize for InclusionProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&serialize_hex(&self.0))
    }
}

/// Implement `Deserialize` for `PartialMerkleTree` using hex decoding.
impl<'de> Deserialize<'de> for InclusionProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(InclusionProof(
            deserialize_hex(&String::deserialize(deserializer)?).map_err(D::Error::custom)?,
        ))
    }
}

pub trait WtxidToTxid {
    fn to_txid(&self) -> Txid;
}

impl WtxidToTxid for Wtxid {
    fn to_txid(&self) -> Txid {
        Txid::from_byte_array(self.to_byte_array())
    }
}

pub trait WithInclusionProof {
    fn with_inclusion_proof(&self, block: &Block) -> TransactionWithInclusionProof;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionWithInclusionProof {
    // Transaction and PMT for transaction (and coinbase) inclusion proof
    pub tx: (Transaction, InclusionProof),

    // Coinbase transaction and PMT for witness inclusion proof
    pub witness: Option<(Transaction, InclusionProof)>,
}

impl WithInclusionProof for Transaction {
    fn with_inclusion_proof(&self, block: &Block) -> TransactionWithInclusionProof {
        let (txids, wtxids): (Vec<_>, Vec<_>) = block
            .txdata
            .iter()
            .map(|tx| {
                (
                    tx.compute_txid(),
                    if tx.is_coinbase() {
                        Txid::all_zeros()
                    } else {
                        tx.compute_wtxid().to_txid()
                    },
                )
            })
            .unzip();

        let txid = self.compute_txid();
        let wtxid = self.compute_wtxid().to_txid();

        let (incl_txids, witness) = if txid == wtxid {
            // Non-Segwit
            (vec![txid], None)
        } else {
            // Segwit
            let coinbase_tx = block.txdata[0].clone();
            let coinbase_txid = coinbase_tx.compute_txid();
            (
                vec![coinbase_txid, txid],
                Some((
                    coinbase_tx,
                    InclusionProof(PartialMerkleTree::from_txids(
                        &wtxids,
                        &wtxids.iter().map(|&id| id == wtxid).collect::<Vec<_>>(),
                    )),
                )),
            )
        };

        TransactionWithInclusionProof {
            tx: (
                self.clone(),
                InclusionProof(PartialMerkleTree::from_txids(
                    &txids,
                    &txids
                        .iter()
                        .map(|id| incl_txids.contains(id))
                        .collect::<Vec<_>>(),
                )),
            ),
            witness,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeProofInput {
    /// headers after last verified l1 block
    pub headers: Vec<Header>,

    /// Deposit Txid
    pub deposit_txid: [u8; 32],

    /// Block height of checkpoint tx, and it's inclusion proof
    pub checkpoint: (u32, TransactionWithInclusionProof),

    /// Block height of bridge_out tx, and it's inclusion proof
    pub bridge_out: (u32, TransactionWithInclusionProof),

    /// superblock period start ts
    pub superblock_period_start_ts: u32,
}
