use bitcoin::Block;
use borsh::BorshDeserialize;
use strata_primitives::l1::XOnlyPk;
use strata_proofimpl_btc_blockspace::block::{check_merkle_root, check_witness_commitment};

use super::primitives::WithdrawalInfo;

// Paid to the user Tap Scripit
// OP Return has the Operator info
// Find these infos and return the:
// i)  User <Address, Aamt>
// ii) Operator address <- signature
// Actual payment
pub fn get_payment_txn(block: &Block, payment_txn_idx: u32) -> WithdrawalInfo {
    assert!(check_merkle_root(block));
    assert!(check_witness_commitment(block));

    let payment_txn = block
        .txdata
        .get(payment_txn_idx as usize)
        .expect("Claim txn not found for the payment_txn_idx");

    let amt = payment_txn.output[0].value.into();
    let dest_pub_key = &payment_txn.output[0].script_pubkey.as_bytes()[2..];
    let dest_addrs = XOnlyPk::try_from_slice(dest_pub_key).expect("invalid destination address");

    dbg!(&payment_txn.output[1].script_pubkey);
    let operator_idx_bytes: &[u8; 4] = &payment_txn.output[1].script_pubkey.as_bytes()[2..6]
        .try_into()
        .expect("invalid operator idx");
    let operator_idx = u32::from_le_bytes(*operator_idx_bytes);

    (operator_idx, (dest_addrs, amt))
}

#[cfg(test)]
mod test {
    use prover_test_utils::get_bitcoin_client;
    use strata_btcio::rpc::traits::Reader;

    use super::get_payment_txn;

    #[tokio::test]
    async fn test_get_payment_txn() {
        let btc_client = get_bitcoin_client();
        let payment_txn_block_num = 1026;
        let payment_txn_block = btc_client
            .get_block_at(payment_txn_block_num)
            .await
            .unwrap();

        let payment_txn_index = 1;
        let payment_txn_result = get_payment_txn(&payment_txn_block, payment_txn_index);
    }
}
