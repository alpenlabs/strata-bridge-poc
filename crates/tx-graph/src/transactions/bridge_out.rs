use bitcoin::{Address, Amount, Network, OutPoint, Transaction};
use rand::Rng;
use secp256k1::{XOnlyPublicKey, SECP256K1};
use strata_bridge_primitives::scripts::general::{
    create_tx, create_tx_ins, create_tx_outs, op_return_nonce,
};

#[derive(Debug, Clone)]
pub struct BridgeOut(Transaction);

impl BridgeOut {
    pub fn new(
        network: Network,
        sender_outpoints: Vec<OutPoint>,
        amount: Amount,
        change_address: Address,
        change_amount: Amount,
        recipient_key: XOnlyPublicKey,
    ) -> Self {
        let tx_ins = create_tx_ins(sender_outpoints);
        let recipient_address = Address::p2tr(SECP256K1, recipient_key, None, network);
        let recipient_pubkey = recipient_address.script_pubkey();

        let change_pubkey = change_address.script_pubkey();

        let op_return_amount = Amount::from_int_btc(0);

        let mut rng = rand::thread_rng();
        loop {
            let random_data: Vec<u8> = (0..2).map(|_| rng.gen()).collect(); // 2 random bytes

            let op_return_script = op_return_nonce(random_data);

            let scripts_and_amounts = [
                (recipient_pubkey.clone(), amount),
                (change_pubkey.clone(), change_amount),
                (op_return_script, op_return_amount),
            ];

            let tx_outs = create_tx_outs(scripts_and_amounts);

            let tx = create_tx(tx_ins.clone(), tx_outs);

            let txid = tx.compute_txid();

            if txid.to_string().starts_with('0') {
                return Self(tx);
            }
        }
    }

    pub fn tx(self) -> Transaction {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        address::Address, blockdata::transaction::OutPoint, hashes::Hash, network::Network, Amount,
    };
    use rand::RngCore;
    use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};

    use super::*;

    // Helper function to create a random `OutPoint`
    fn random_outpoint() -> OutPoint {
        let mut txid = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut txid);
        OutPoint::new(bitcoin::Txid::from_slice(&txid).unwrap(), 0)
    }

    // Helper function to create a random `XOnlyPublicKey`
    fn random_xonly_pubkey() -> XOnlyPublicKey {
        let keypair = Keypair::new(SECP256K1, &mut rand::thread_rng());
        XOnlyPublicKey::from_keypair(&keypair).0
    }

    #[test]
    fn test_bridge_out_with_pow() {
        // Set up parameters
        let network = Network::Regtest;
        let sender_outpoints = vec![random_outpoint(), random_outpoint()]; // Sample outpoints
        let amount = Amount::from_sat(10000); // Recipient amount
        let change_amount = Amount::from_sat(5000); // Change amount
        let recipient_key = random_xonly_pubkey();

        // Use a random change address
        let change_keypair = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let change_address = Address::p2tr(
            SECP256K1,
            XOnlyPublicKey::from_keypair(&change_keypair).0,
            None,
            network,
        );

        // Call the `new` function to create a transaction
        let bridge_out = BridgeOut::new(
            network,
            sender_outpoints,
            amount,
            change_address.clone(),
            change_amount,
            recipient_key,
        );

        // Extract the transaction from the returned struct
        let tx = bridge_out.tx();

        // Check if the transaction hash starts with a zero nibble
        let txid = tx.compute_txid();
        dbg!(&txid);
        assert!(
            txid.to_string().starts_with('0'),
            "Transaction ID does not start with zero nibble"
        );

        // Verify the outputs contain the recipient, change, and OP_RETURN with expected values
        let recipient_pubkey =
            Address::p2tr(SECP256K1, recipient_key, None, network).script_pubkey();
        let change_pubkey = change_address.script_pubkey();
        let op_return_amount = Amount::from_int_btc(0);

        assert!(
            tx.output
                .iter()
                .any(|out| out.script_pubkey == recipient_pubkey && out.value == amount),
            "Recipient output is missing or incorrect"
        );
        assert!(
            tx.output
                .iter()
                .any(|out| out.script_pubkey == change_pubkey && out.value == change_amount),
            "Change output is missing or incorrect"
        );
        assert!(
            tx.output
                .iter()
                .any(|out| out.value == op_return_amount && out.script_pubkey.is_op_return()),
            "OP_RETURN output is missing or incorrect"
        );
    }
}
