use bitcoin::Txid;
use musig2::{PartialSignature, PubNonce};

use crate::types::OperatorIdx;

#[derive(Debug, Clone)]
pub enum Signal {
    /// Sent by signers to each other.
    Nonce {
        txid: Txid,
        pubnonce: PubNonce,
        sender_id: OperatorIdx,
    },

    /// Sent by signers to each other.
    Signature {
        txid: Txid,
        signature: PartialSignature,
        sender_id: OperatorIdx,
    },

    /// Sent by operators to each other.
    PegOutGraphPublished(OperatorIdx),

    /// Sent by bitcoin watcher to disprover
    AssertChainAvailable {
        claim_txid: Txid,
        pre_assrt_txid: Txid,
        assert_data_txid: Txid,
        post_assert_txid: Txid,
    },
}
