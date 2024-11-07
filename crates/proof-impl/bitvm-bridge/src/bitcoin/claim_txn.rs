use bitcoin::{hashes::Hash, Block, Txid};
use strata_proofimpl_btc_blockspace::block::{check_merkle_root, check_witness_commitment};

// Ts is commited in the Claim Transaction
// pub type TxId = [u8; 32];
pub fn get_claim_txn(block: &Block) -> (u32, Txid) {
    assert!(check_merkle_root(block));
    assert!(check_witness_commitment(block));

    // TODO: Filter out the claim txn and parse the Ts
    // TODO: Add bridgeout tx -> TxId
    // block.header.time
    // todo!()
    (
        0,
        Txid::from_slice(&[0u8; 32]).expect("Failed to create Txid from bytes"),
    )
}
