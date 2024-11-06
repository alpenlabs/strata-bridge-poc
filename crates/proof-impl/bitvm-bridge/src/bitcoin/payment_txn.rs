use bitcoin::Block;
use strata_primitives::l1::{BitcoinAmount, XOnlyPk};
use strata_proofimpl_btc_blockspace::block::{check_merkle_root, check_witness_commitment};

use super::primitives::WithdrwalInfo;

// Paid to the user Tap Scripit
// OP Return has the Operator info
// Find these infos and return the:
// i)  User <Address, Aamt>
// ii) Operator address <- signature
// Actual payment
pub fn get_payment_txn(block: &Block) -> WithdrwalInfo {
    assert!(check_merkle_root(block));
    assert!(check_witness_commitment(block));

    let amt = BitcoinAmount::from_sat(1000000000);
    let dest_addrs = XOnlyPk::new(Default::default());
    let operator_address = Default::default();

    (operator_address, (dest_addrs, amt))
}
