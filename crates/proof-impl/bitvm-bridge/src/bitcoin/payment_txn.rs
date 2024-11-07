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
pub fn get_payment_txn(block: &Block, payment_txn_idx: u32) -> WithdrwalInfo {
    assert!(check_merkle_root(block));
    assert!(check_witness_commitment(block));

    let _payment_txn = block
        .txdata
        .get(payment_txn_idx as usize)
        .expect("Claim txn not found for the payment_txn_idx");

    // TODO: Use `_payment_txn` info to obtain these
    let amt = BitcoinAmount::from_sat(1000000000);
    let dest_addrs = XOnlyPk::new(Default::default());
    let operator_address = Default::default();

    (operator_address, (dest_addrs, amt))
}

#[cfg(test)]
mod test {
    use prover_test_utils::get_bitcoin_client;
    use strata_btcio::rpc::traits::Reader;

    use super::get_payment_txn;

    #[tokio::test]
    async fn test_get_payment_txn() {
        let btc_client = get_bitcoin_client();
        let payment_txn_block_num = 750;
        let payment_txn_block = btc_client
            .get_block_at(payment_txn_block_num)
            .await
            .unwrap();

        let claim_txn_index = 0;
        let payment_txn_result = get_payment_txn(&payment_txn_block, claim_txn_index);
        println!("{:?}", payment_txn_result)
    }
}
