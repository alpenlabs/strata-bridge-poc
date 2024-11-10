use strata_primitives::{
    bridge::OperatorIdx,
    l1::{BitcoinAmount, XOnlyPk},
};

pub type WithdrawalInfo = (OperatorIdx, (XOnlyPk, BitcoinAmount));
