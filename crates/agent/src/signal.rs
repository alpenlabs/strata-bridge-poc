use bitcoin::Txid;
use musig2::{AggNonce, PartialSignature, PubNonce};
use strata_bridge_primitives::types::{OperatorIdx, TxSigningData};
use strata_bridge_tx_graph::{
    peg_out_graph::PegOutGraphInput,
    transactions::prelude::{DisproveTx, PayoutTx, PostAssertTx, PreAssertTx},
};

#[derive(Debug, Clone)]
pub enum DepositSignal {
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
}

#[derive(Debug, Clone)]
pub enum WatcherSignal {
    /// Sent by bitcoin watcher to disprover
    AssertChainAvailable {
        claim_txid: Txid,
        pre_assrt_txid: Txid,
        assert_data_txid: Txid,
        post_assert_txid: Txid,
    },
    // Add other signals like: `ChallengeReceived`
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum CovenantSignal {
    /// Sent by operators to signers.
    CovenantRequest {
        details: Request,
        sender_id: OperatorIdx,
    },

    /// Sent by signers to operators.
    CovenantRequestFulfilled {
        details: RequestFulfilled,
        sender_id: OperatorIdx,
        destination_id: OperatorIdx,
    },
}

/// Request for signatures in the covenant
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Request {
    Nonce(PegOutGraphInput),
    Signature {
        agg_nonces: AggNonces,
        peg_out_graph_input: PegOutGraphInput,
    },
}

#[derive(Debug, Clone)]
pub struct AggNonces {
    pub pre_assert: AggNonce,
    pub post_assert: AggNonce,
    pub disprove: AggNonce,
    pub payout_0: AggNonce,
    pub payout_1: AggNonce,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RequestFulfilled {
    Nonce {
        pre_assert: PubNonce,
        post_assert: PubNonce,
        disprove: PubNonce,
        payout_0: PubNonce, // requires key-spend key aggregation
        payout_1: PubNonce, // requires script-spend key aggregation
    },

    Signature {
        pre_assert: Vec<PartialSignature>,
        post_assert: Vec<PartialSignature>, // for each of the inputs
        disprove: Vec<PartialSignature>,
        payout: Vec<PartialSignature>,
    },
}

#[derive(Debug, Clone)]
pub enum TxWithCovenant {
    PreAssert(PreAssertTx),

    PostAssert(PostAssertTx),

    Disprove(DisproveTx),

    Payout(PayoutTx),

    Deposit(TxSigningData),
}
