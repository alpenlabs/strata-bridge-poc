use bitcoin::Txid;
use serde::{Deserialize, Serialize};

use crate::{
    deposit::DepositInfo, params::prelude::NUM_ASSERT_DATA_TX, types::OperatorIdx,
    withdrawal::WithdrawalInfo,
};

/// The various duties that can be assigned to an operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum BridgeDutyRpcResponse {
    /// The duty to create and sign a Deposit Transaction so as to move funds from the user to the
    /// Bridge Address.
    ///
    /// This duty is created when a user deposit request comes in, and applies to all operators.
    SignDeposit(DepositInfo),

    /// The duty to fulfill a withdrawal request that is assigned to a particular operator.
    ///
    /// This duty is created when a user requests a withdrawal by calling a precompile in the EL
    /// and the [`crate::bridge_state::DepositState`] transitions to
    /// [`crate::bridge_state::DepositState::Dispatched`].
    ///
    /// This kicks off the withdrawal process which involves cooperative signing by the operator
    /// set, or a more involved unilateral withdrawal process (in the future) if not all operators
    /// cooperate in the process.
    FulfillWithdrawal(WithdrawalInfo),
}

impl BridgeDutyRpcResponse {
    pub fn get_id(&self) -> Txid {
        match self {
            BridgeDutyRpcResponse::SignDeposit(deposit_info) => {
                deposit_info.deposit_request_outpoint().txid
            }
            BridgeDutyRpcResponse::FulfillWithdrawal(withdrawal_info) => {
                withdrawal_info.deposit_outpoint().txid
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BridgeDuty {
    Deposit {
        details: DepositInfo,
        status: DepositStatus,
    },

    Withdrawal {
        details: WithdrawalInfo,
        status: WithdrawalStatus,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDuties {
    pub duties: Vec<BridgeDutyRpcResponse>,

    pub start_index: u64,

    pub stop_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeDutyStatus {
    Deposit(DepositStatus),

    Withdrawal(WithdrawalStatus),
}

impl From<DepositStatus> for BridgeDutyStatus {
    fn from(value: DepositStatus) -> Self {
        Self::Deposit(value)
    }
}

impl From<WithdrawalStatus> for BridgeDutyStatus {
    fn from(value: WithdrawalStatus) -> Self {
        Self::Withdrawal(value)
    }
}

impl BridgeDutyStatus {
    pub fn is_done(&self) -> bool {
        match self {
            BridgeDutyStatus::Deposit(deposit_status) => deposit_status.is_done(),
            BridgeDutyStatus::Withdrawal(withdrawal_status) => withdrawal_status.is_done(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositStatus {
    /// The duty has been received.
    ///
    /// This usually entails collecting nonces before the corresponding transaction can be
    /// partially signed.
    Received,

    /// The required nonces are being collected.
    CollectingNonces {
        /// The number of nonces collected so far.
        collected: u32,

        /// The indexes of operators that are yet to provide nonces.
        remaining: Vec<OperatorIdx>,
    },

    /// The required nonces have been collected.
    ///
    /// This state can be inferred from the previous state but might still be useful as the
    /// required number of nonces is context-driven and it cannot be determined whether all
    /// nonces have been collected by looking at the above variant alone.
    CollectedNonces,

    /// The partial signatures are being collected.
    CollectingSignatures {
        /// The number of nonces collected so far.
        collected: u32,

        /// The indexes of operators that are yet to provide partial signatures.
        remaining: Vec<OperatorIdx>,
    },

    /// The required partial signatures have been collected.
    ///
    /// This state can be inferred from the previous state but might still be useful as the
    /// required number of signatures is context-driven and it cannot be determined whether all
    /// partial signatures have been collected by looking at the above variant alone.
    CollectedSignatures,

    /// The duty has been executed.
    ///
    /// This means that the required transaction has been fully signed and broadcasted to Bitcoin.
    Executed,

    /// The duty could not be executed.
    ///
    /// Holds the error message as a [`String`] for context and the number of retries for a
    /// particular duty.
    // TODO: this should hold `strata-bridge-exec::ExecError` instead but that requires
    // implementing `BorshSerialize` and `BorshDeserialize`.
    Failed {
        /// The error message.
        error_msg: String,

        /// The number of times a duty has been retried.
        num_retries: u32,
    },

    /// The duty could not be executed even after repeated tries.
    ///
    /// Holds the error message encountered during the last execution.
    Discarded(String),
}

impl DepositStatus {
    pub fn is_done(&self) -> bool {
        matches!(self, Self::Executed) || matches!(self, Self::Discarded(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalStatus {
    Received,

    PaidUser(Txid),

    Kickoff {
        bridge_out_txid: Txid,
        kickoff_txid: Txid,
    },

    Claim {
        bridge_out_txid: Txid,
        superblock_start_ts: u32,
        claim_txid: Txid,
    },

    PreAssert {
        bridge_out_txid: Txid,
        superblock_start_ts: u32,
        pre_assert_txid: Txid,
    },

    AssertData {
        bridge_out_txid: Txid,
        superblock_start_ts: u32,
        assert_data_txids: Vec<Txid>, // dynamic for assert data txs that have been broadcasted
    },

    PostAssert,

    Executed,

    Failed {
        /// The error message.
        error_msg: String,

        /// The number of times a duty has been retried.
        num_retries: u32,
    },

    Discarded(String),
}

impl WithdrawalStatus {
    pub fn next(&mut self, txid: Txid, superblock_start_ts: Option<u32>) {
        match self {
            Self::Received => *self = Self::PaidUser(txid),
            Self::PaidUser(bridge_out_txid) => {
                *self = Self::Kickoff {
                    bridge_out_txid: *bridge_out_txid,
                    kickoff_txid: txid,
                }
            }
            Self::Kickoff {
                bridge_out_txid,
                kickoff_txid: _,
            } => {
                *self = Self::Claim {
                    bridge_out_txid: *bridge_out_txid,
                    superblock_start_ts: superblock_start_ts.unwrap_or(0),
                    claim_txid: txid,
                }
            }
            Self::Claim {
                bridge_out_txid,
                superblock_start_ts,
                claim_txid: _,
            } => {
                *self = Self::PreAssert {
                    bridge_out_txid: *bridge_out_txid,
                    superblock_start_ts: *superblock_start_ts,
                    pre_assert_txid: txid,
                }
            }
            Self::PreAssert {
                bridge_out_txid,
                superblock_start_ts,
                pre_assert_txid: _,
            } => {
                *self = Self::AssertData {
                    bridge_out_txid: *bridge_out_txid,
                    superblock_start_ts: *superblock_start_ts,
                    assert_data_txids: vec![],
                }
            }
            Self::AssertData {
                bridge_out_txid: _,
                superblock_start_ts: _,
                assert_data_txids,
            } => {
                if assert_data_txids.len() == NUM_ASSERT_DATA_TX {
                    *self = Self::PostAssert
                } else {
                    assert_data_txids.push(txid);
                }
            }
            Self::PostAssert => *self = Self::Executed,
            _ => {}
        }
    }

    pub fn should_pay(&self) -> bool {
        matches!(self, WithdrawalStatus::Received)
    }

    pub fn should_kickoff(&self) -> Option<Txid> {
        match self {
            WithdrawalStatus::PaidUser(txid) => Some(*txid),
            _ => None,
        }
    }

    pub fn should_claim(&self) -> Option<Txid> {
        match self {
            WithdrawalStatus::Kickoff {
                bridge_out_txid,
                kickoff_txid: _,
            } => Some(*bridge_out_txid),
            _ => None,
        }
    }

    pub fn should_pre_assert(&self) -> Option<(Txid, u32)> {
        match self {
            WithdrawalStatus::Claim {
                bridge_out_txid,
                superblock_start_ts,
                claim_txid: _,
            } => Some((*bridge_out_txid, *superblock_start_ts)),
            _ => None,
        }
    }

    pub fn should_assert_data(&self, assert_data_index: usize) -> Option<(Txid, u32)> {
        match self {
            WithdrawalStatus::PreAssert {
                bridge_out_txid,
                superblock_start_ts,
                pre_assert_txid: _,
            } => Some((*bridge_out_txid, *superblock_start_ts)),
            WithdrawalStatus::AssertData {
                bridge_out_txid,
                superblock_start_ts,
                assert_data_txids,
            } if assert_data_txids.len() < assert_data_index + 1 => {
                Some((*bridge_out_txid, *superblock_start_ts))
            }
            _ => None,
        }
    }

    pub fn should_post_assert(&self) -> bool {
        matches!(self, WithdrawalStatus::AssertData { bridge_out_txid: _, superblock_start_ts: _, assert_data_txids } if assert_data_txids.len() == NUM_ASSERT_DATA_TX)
    }

    pub fn should_get_payout(&self) -> bool {
        matches!(self, WithdrawalStatus::PostAssert)
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Executed) || matches!(self, Self::Discarded(_))
    }
}
