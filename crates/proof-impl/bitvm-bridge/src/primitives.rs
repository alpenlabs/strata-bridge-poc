use strata_primitives::params::RollupParams;
use strata_state::{batch::BatchCheckpoint, bridge_state::DepositState, chain_state::ChainState};

// pub type BridgeProofPublicParams = (BlockHash, Txid, u32);
pub type BridgeProofPublicParams = ([u8; 32], [u8; 32], [u8; 32], u32);

/// Necessary information to prove the execution of the bridge proof.
pub struct BridgeProofInput {
    pub l1_sgements: Vec<L1Segment>,
    pub batch_checkpoint: BatchCheckpoint,
    pub rollup_params: RollupParams,

    pub deposit_state: DepositState,
    pub l2_state: ChainState,
}

pub struct L1Segment {
    pub idx: u64,
    pub header: L1Header,
}

pub struct L1Header {}

impl L1Header {
    pub fn verify(&self) -> bool {
        true
    }
}

/// Initializes BridgeProofPublicParams with hardcoded values.
pub fn get_bridge_proof_public_params() -> BridgeProofPublicParams {
    // Hardcoded 32-byte arrays (example values)
    let param1: [u8; 32] = [
        0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8,
        0x09, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71, 0x82, 0x93, 0xA4, 0xB5, 0xC6, 0xD7, 0xE8,
        0xF9, 0x0A,
    ];

    let param2: [u8; 32] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x20, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x20, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99,
    ];

    let param3: [u8; 32] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
        0x20, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x20,
    ];

    // Hardcoded u32 value (example value)
    let param4: u32 = 0xDEADBEEF;

    // Return the tuple with all hardcoded values
    (param1, param2, param3, param4)
}

#[cfg(test)]
mod test {
    use super::get_bridge_proof_public_params;

    #[test]
    fn test_proof_with_public_params() {
        let res = get_bridge_proof_public_params();
        println!("res {:?}", res)
    }
}
