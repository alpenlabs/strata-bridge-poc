//! Constants that should be configurable params.
use std::time::Duration;

pub const BLOCK_TIME: Duration = Duration::from_secs(30);

pub const SUPERBLOCK_MEASUREMENT_PERIOD: u32 = 2000; // blocks

pub const TS_COMMITMENT_MARGIN: u32 = 288; // 2 days' worth of blocks in mainnet

pub const PAYOUT_OPTIMISTIC_TIMELOCK: u32 = 3000;

const _: u32 =
    PAYOUT_OPTIMISTIC_TIMELOCK - (SUPERBLOCK_MEASUREMENT_PERIOD + TS_COMMITMENT_MARGIN + 100); // 100
                                                                                               // is slack
