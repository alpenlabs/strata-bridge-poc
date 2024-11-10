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

    let operator_idx_bytes: &[u8; 4] = &payment_txn.output[2].script_pubkey.as_bytes()[2..6]
        .try_into()
        .expect("invalid operator idx");
    let operator_idx = u32::from_be_bytes(*operator_idx_bytes);

    (operator_idx, (dest_addrs, amt))
}

#[cfg(test)]
mod test {
    use bitcoin::{consensus::deserialize, Block};
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
        dbg!(payment_txn_result);
    }

    #[test]
    fn test_payment_tx_static() {
        let block_raw = "000000202a11acb82f0dc6b5d1ddf989e28908e977f1ca9587b3969de48c12d8317f2110d5d1db094e70cb371f3ef7991f2f3163c16c643ea816a4e3872d2f1144f6a9897f362d67ffff7f200300000002020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402020400ffffffff02502ba8040000000016001406d6ede725893732fb24c3468ff3225b831686280000000000000000266a24aa21a9edac85ec9f45b83cdd2519414806bdcdf428b4131128e7108294a2975b120ec252012000000000000000000000000000000000000000000000000000000000000000000000000002000000000101b54c732675a677619167c1cae48a7ce57bda1a21e19271f70d52ba8aa8226a910000000000fdffffff030008af2f00000000225120ce5ef52ccb3e688435e2621a68e1f316af590d299b9d7427894b9e591ee9442e78dd53650000000016001447e87aa09a301089ae4482156f85d0ab2ea8d6ab0000000000000000086a0600000002a76b02473044022004d6a00fa257ff09f1c295e1be7af7643f30edd36516a0861490f0589723dbf5022045d2106a2e3b6665c5393731de9f38956192c556524b884cf10854a76a3fc221012103b299d12b9a8ea09e377e477c4cebc56a4b8f23dea6d9de6897cf6f95997bd36700000000";
        let block: Block = deserialize(&hex::decode(block_raw).unwrap()).unwrap();

        let payment_txn_result = get_payment_txn(&block, 1);
        dbg!(payment_txn_result);
    }
}
