use serde::{Deserialize, Serialize};

use crate::{
    deposit::DepositInfo, params::prelude::NUM_ASSERT_DATA_TX, types::OperatorIdx,
    withdrawal::WithdrawalInfo,
};

/// The various duties that can be assigned to an operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum BridgeDuty {
    /// The duty to create and sign a Deposit Transaction so as to move funds from the user to the
    /// Bridge Address.
    ///
    /// This duty is created when a user deposit request comes in, and applies to all operators.
    SignDeposit {
        details: DepositInfo,
        status: DepositStatus,
    },

    /// The duty to fulfill a withdrawal request that is assigned to a particular operator.
    ///
    /// This duty is created when a user requests a withdrawal by calling a precompile in the EL
    /// and the [`crate::bridge_state::DepositState`] transitions to
    /// [`crate::bridge_state::DepositState::Dispatched`].
    ///
    /// This kicks off the withdrawal process which involves cooperative signing by the operator
    /// set, or a more involved unilateral withdrawal process (in the future) if not all operators
    /// cooperate in the process.
    FulfillWithdrawal {
        details: WithdrawalInfo,
        status: WithdrawalStatus,
    },
}

impl From<DepositInfo> for BridgeDuty {
    fn from(value: DepositInfo) -> Self {
        Self::SignDeposit {
            details: value,
            status: DepositStatus::Received,
        }
    }
}

impl From<WithdrawalInfo> for BridgeDuty {
    fn from(value: WithdrawalInfo) -> Self {
        Self::FulfillWithdrawal {
            details: value,
            status: WithdrawalStatus::Received,
        }
    }
}

impl BridgeDuty {
    pub fn is_done(&self) -> bool {
        matches!(self, BridgeDuty::SignDeposit { details: _, status } if status.is_done())
            || matches!(self, BridgeDuty::FulfillWithdrawal { details: _, status } if status.is_done())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDuties {
    pub duties: Vec<BridgeDuty>,

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

    PaidUser,

    Kickoff,

    Claim,

    PreAssert,

    AssertData(usize), // number of assert data txs that have been broadcasted

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
    pub fn next(&self) -> Self {
        match self {
            Self::Received => Self::PaidUser,
            Self::PaidUser => Self::Kickoff,
            Self::Kickoff => Self::Claim,
            Self::Claim => Self::PreAssert,
            Self::PreAssert => Self::AssertData(0),
            Self::AssertData(i) if *i == NUM_ASSERT_DATA_TX => Self::PostAssert,
            Self::AssertData(i) => Self::AssertData(i + 1),
            Self::PostAssert => Self::Executed,
            _ => self.clone(),
        }
    }

    pub fn should_pay(&self) -> bool {
        matches!(self, WithdrawalStatus::Received)
    }

    pub fn should_kickoff(&self) -> bool {
        matches!(self, WithdrawalStatus::PaidUser)
    }

    pub fn should_claim(&self) -> bool {
        matches!(self, WithdrawalStatus::Kickoff)
    }

    pub fn should_pre_assert(&self) -> bool {
        matches!(self, WithdrawalStatus::Claim)
    }

    pub fn should_assert_data(&self, assert_data_index: usize) -> bool {
        matches!(self, WithdrawalStatus::PreAssert)
            || matches!(self, WithdrawalStatus::AssertData(count) if *count < assert_data_index)
    }

    pub fn should_post_assert(&self) -> bool {
        matches!(self, WithdrawalStatus::AssertData(count) if *count == NUM_ASSERT_DATA_TX)
    }

    pub fn should_get_payout(&self) -> bool {
        matches!(self, WithdrawalStatus::PostAssert)
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Executed) || matches!(self, Self::Discarded(_))
    }
}
