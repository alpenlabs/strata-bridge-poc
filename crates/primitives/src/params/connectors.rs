//! Params related to the bridge tx graph connectors;

pub const NUM_PKS_A256_PER_CONNECTOR: usize = 7;
pub const NUM_PKS_A256: usize = 49;
pub const NUM_CONNECTOR_A256: usize = NUM_PKS_A256 / NUM_PKS_A256_PER_CONNECTOR;

pub const NUM_PKS_A160_PER_CONNECTOR: usize = 11;
pub const NUM_PKS_A160: usize = 598;
pub const NUM_CONNECTOR_A160: usize = NUM_PKS_A160 / NUM_PKS_A160_PER_CONNECTOR;
pub const NUM_PKS_A160_RESIDUAL: usize = NUM_PKS_A160 % NUM_PKS_A160_PER_CONNECTOR;
