pub const ASSERT_DATA_TX1_COUNT: usize = 5;
pub const ASSERT_DATA_TX1_A160_PK11_COUNT: usize = 10;
pub const ASSERT_DATA_TX1_A256_PK7_COUNT: usize = 1;

pub const ASSERT_DATA_TX2_COUNT: usize = 1;
pub const ASSERT_DATA_TX2_A160_PK11_COUNT: usize = 4;
pub const ASSERT_DATA_TX2_A256_PK7_COUNT: usize = 2;
pub const ASSERT_DATA_TX2_A160_PK4_COUNT: usize = 1;

pub const TOTAL_CONNECTORS: usize = (49 / 7) + (598 / 11) + 1;

// compile time to check to ensure that the numbers are sound.
const _: usize = ASSERT_DATA_TX1_COUNT
    * (ASSERT_DATA_TX1_A160_PK11_COUNT + ASSERT_DATA_TX1_A256_PK7_COUNT)
    + ASSERT_DATA_TX2_COUNT
        * (ASSERT_DATA_TX2_A160_PK11_COUNT
            + ASSERT_DATA_TX2_A256_PK7_COUNT
            + ASSERT_DATA_TX2_A160_PK4_COUNT)
    - TOTAL_CONNECTORS;
