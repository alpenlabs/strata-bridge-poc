use strata_primitives::{
    buf::Buf32,
    l1::{BitcoinAmount, XOnlyPk},
};

pub type WithdrwalInfo = (Buf32, (XOnlyPk, BitcoinAmount));
