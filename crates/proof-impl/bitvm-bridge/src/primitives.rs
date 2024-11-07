use bitcoin::{block::Header, Block};
use strata_primitives::l1::OutputRef;
use strata_state::l1::HeaderVerificationState;

/// Parameters for Bridge Proof operations as a tuple.
///
/// Contains:
///
/// - `deposit_utxo`: The Deposit UTXO.
/// - `payment_txn`: The Payment Transaction.
/// - `super_block_hash`: The Super Block Hash.
/// - `timestamp`: The timestamp of the TS block.
pub type BridgeProofPublicParams = ([u8; 32], [u8; 32], [u8; 32], u32);

#[derive(serde::Serialize, serde::Deserialize)]
pub struct CheckpointInput {
    pub block: Block,
    pub out_ref: OutputRef,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BridgeProofInput {
    pub checkpoint_input: CheckpointInput,
    pub payment_txn_block: Block,
    pub claim_txn_block: Block,
    pub ts_block_header: Header,
    pub headers: Vec<Header>,
    pub start_header_state: HeaderVerificationState,
}

#[cfg(test)]
mod test {
    use super::BridgeProofPublicParams;

    /// Initializes BridgeProofPublicParams with hardcoded values.
    fn get_bridge_proof_public_params() -> BridgeProofPublicParams {
        // Hardcoded 32-byte arrays (example values)
        let param1: [u8; 32] = [
            0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7,
            0xF8, 0x09, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71, 0x82, 0x93, 0xA4, 0xB5, 0xC6,
            0xD7, 0xE8, 0xF9, 0x0A,
        ];

        let param2: [u8; 32] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x20, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x20, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        ];

        let param3: [u8; 32] = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
            0xF0, 0x20, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF, 0x20,
        ];

        // Hardcoded u32 value (example value)
        let param4: u32 = 0xDEADBEEF;

        // Return the tuple with all hardcoded values
        (param1, param2, param3, param4)
    }

    #[test]
    fn test_proof_with_public_params() {
        let res = get_bridge_proof_public_params();
        println!("res {:?}", res)
    }
}
