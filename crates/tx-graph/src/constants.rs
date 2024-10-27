//! Defines constants for block/network information.
use core::fmt;

use bitcoin::Amount;

pub const OPERATOR_STAKE: Amount = Amount::from_int_btc(2);

pub const NUM_BLOCKS_PER_HOUR: u32 = 120; // 30 second block time
pub const NUM_BLOCKS_PER_6_HOURS: u32 = NUM_BLOCKS_PER_HOUR * 6;

pub const NUM_BLOCKS_PER_DAY: u32 = NUM_BLOCKS_PER_HOUR * 24;
pub const NUM_BLOCKS_PER_3_DAYS: u32 = NUM_BLOCKS_PER_DAY * 3;

pub const NUM_BLOCKS_PER_WEEK: u32 = NUM_BLOCKS_PER_DAY * 7;
pub const NUM_BLOCKS_PER_2_WEEKS: u32 = NUM_BLOCKS_PER_WEEK * 2;
pub const NUM_BLOCKS_PER_4_WEEKS: u32 = NUM_BLOCKS_PER_WEEK * 4;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum DestinationNetwork {
    /// Current devnet.
    Devnet,
    /// Devnet for PoC.
    DevnetPoC,
}

impl fmt::Display for DestinationNetwork {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use DestinationNetwork::*;

        let s = match *self {
            Devnet => "devnet",
            DevnetPoC => "devnet_poc",
        };
        write!(f, "{}", s)
    }
}
