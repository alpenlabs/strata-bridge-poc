use crate::connectors::constants::{NUM_CONNECTOR_A160, NUM_CONNECTOR_A256};

pub const NUM_ASSERT_DATA_TX1: usize = 5;
pub const NUM_ASSERT_DATA_TX1_A160_PK11: usize = 10;
pub const NUM_ASSERT_DATA_TX1_A256_PK7: usize = 1;

pub const NUM_ASSERT_DATA_TX2: usize = 1;
pub const NUM_ASSERT_DATA_TX2_A160_PK11: usize = 2;
pub const NUM_ASSERT_DATA_TX2_A160_PK2: usize = 1;
pub const NUM_ASSERT_DATA_TX2_A256_PK6: usize = 1;

pub const TOTAL_CONNECTORS: usize = NUM_CONNECTOR_A256 + NUM_CONNECTOR_A160 + 2; // +2 for the
                                                                                 // residual A160(2 scripts) and A256(6 scripts) connectors
pub const TOTAL_VALUES: usize = NUM_ASSERT_DATA_TX1
    * (NUM_ASSERT_DATA_TX1_A160_PK11 + NUM_ASSERT_DATA_TX1_A256_PK7)
    + NUM_ASSERT_DATA_TX2
        * (NUM_ASSERT_DATA_TX2_A160_PK11
            + NUM_ASSERT_DATA_TX2_A256_PK6
            + NUM_ASSERT_DATA_TX2_A160_PK2);

pub const SUPERBLOCK_PERIOD: u32 = 2 * 7 * 24 * 60 * 60; // 2w in secs

// compile time to check to ensure that the numbers are sound.
const _: [(); 0] = [(); (TOTAL_VALUES - TOTAL_CONNECTORS)];
