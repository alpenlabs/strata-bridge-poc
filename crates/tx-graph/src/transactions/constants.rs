use strata_bridge_primitives::params::prelude::TOTAL_CONNECTORS;

pub const NUM_ASSERT_DATA_TX1: usize = 1;
pub const NUM_ASSERT_DATA_TX1_A256_PK7: usize = 6;

pub const NUM_ASSERT_DATA_TX2: usize = 5;
pub const NUM_ASSERT_DATA_TX2_A160_PK11: usize = 9;

pub const NUM_ASSERT_DATA_TX3: usize = 1;
pub const NUM_ASSERT_DATA_TX3_A160_PK11: usize = 7;
pub const NUM_ASSERT_DATA_TX3_A160_PK2: usize = 1;

pub const NUM_ASSERT_DATA_TX: usize =
    NUM_ASSERT_DATA_TX1 + NUM_ASSERT_DATA_TX2 + NUM_ASSERT_DATA_TX3;

pub const TOTAL_VALUES: usize = NUM_ASSERT_DATA_TX1 * NUM_ASSERT_DATA_TX1_A256_PK7
    + NUM_ASSERT_DATA_TX2 * NUM_ASSERT_DATA_TX2_A160_PK11
    + NUM_ASSERT_DATA_TX3 * (NUM_ASSERT_DATA_TX3_A160_PK11 + NUM_ASSERT_DATA_TX3_A160_PK2);

pub const SUPERBLOCK_PERIOD: u32 = 2 * 7 * 24 * 60 * 60; // 2w in secs

// compile time to check to ensure that the numbers are sound.
const _: [(); 0] = [(); (TOTAL_VALUES - TOTAL_CONNECTORS)];
