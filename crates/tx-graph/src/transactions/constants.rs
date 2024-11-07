use strata_bridge_primitives::params::connectors::{NUM_CONNECTOR_A160, NUM_CONNECTOR_A256};

pub const NUM_ASSERT_DATA_TX1: usize = 5;
pub const NUM_ASSERT_DATA_TX1_A160_PK11: usize = 10;
pub const NUM_ASSERT_DATA_TX1_A256_PK7: usize = 1;

pub const NUM_ASSERT_DATA_TX2: usize = 1;
pub const NUM_ASSERT_DATA_TX2_A256_PK7: usize = 1;
pub const NUM_ASSERT_DATA_TX2_A160_PK11: usize = 2;
pub const NUM_ASSERT_DATA_TX2_A160_PK2: usize = 1;

pub const NUM_ASSERT_DATA_TX: usize = NUM_ASSERT_DATA_TX1 + NUM_ASSERT_DATA_TX2;
pub const NUM_INPUTS_PER_ASSERT_DATA_TX_1: usize =
    NUM_ASSERT_DATA_TX1_A160_PK11 + NUM_ASSERT_DATA_TX1_A256_PK7;

pub const NUM_INPUTS_PER_ASSERT_DATA_TX_2: usize =
    NUM_ASSERT_DATA_TX2_A256_PK7 + NUM_ASSERT_DATA_TX2_A160_PK11 + NUM_ASSERT_DATA_TX2_A160_PK2;

pub const TOTAL_CONNECTORS: usize = NUM_CONNECTOR_A256 + NUM_CONNECTOR_A160 + 1; // +1 for the
                                                                                 // residual A160(2 scripts) connectors
pub const TOTAL_VALUES: usize = NUM_ASSERT_DATA_TX1
    * (NUM_ASSERT_DATA_TX1_A160_PK11 + NUM_ASSERT_DATA_TX1_A256_PK7)
    + NUM_ASSERT_DATA_TX2
        * (NUM_ASSERT_DATA_TX2_A256_PK7
            + NUM_ASSERT_DATA_TX2_A160_PK11
            + NUM_ASSERT_DATA_TX2_A160_PK2);

pub const SUPERBLOCK_PERIOD: u32 = 2 * 7 * 24 * 60 * 60; // 2w in secs

// compile time to check to ensure that the numbers are sound.
const _: [(); 0] = [(); (TOTAL_VALUES - TOTAL_CONNECTORS)];
