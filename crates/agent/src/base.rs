use bitcoin::{
    sighash::{Prevouts, SighashCache},
    TapSighashType, Transaction, TxOut,
};
use secp256k1::{schnorr::Signature, Keypair, SECP256K1};
use strata_bridge_btcio::BitcoinClient;
use strata_bridge_tx_graph::scripts::taproot::{create_message_hash, TaprootWitness};

#[derive(Debug)]
pub struct Base {
    keypair: Keypair,

    pub client: BitcoinClient,
}

impl Base {
    pub fn new(keypair: Keypair, btc_url: &str, btc_user: &str, btc_pass: &str) -> Self {
        let client = BitcoinClient::new(btc_url, btc_user, btc_pass)
            .expect("should be able to create bitcoin client");

        Self { keypair, client }
    }

    pub fn sign(&self, tx: &mut Transaction, prevouts: &[TxOut], input_index: usize) -> Signature {
        let mut sighash_cache = SighashCache::new(tx);
        let msg = create_message_hash(
            &mut sighash_cache,
            Prevouts::All(prevouts),
            &TaprootWitness::Key,
            TapSighashType::All,
            input_index,
        )
        .expect("should be ablet o create message hash");

        SECP256K1.sign_schnorr(&msg, &self.keypair)
    }
}
