use std::{collections::HashSet, sync::Arc};

use bitcoin::{
    hashes::Hash,
    sighash::{Prevouts, SighashCache},
    Address, Amount, OutPoint, TapSighashType, Transaction, TxOut, Txid,
};
use musig2::{KeyAggContext, SecNonce};
use rand::{rngs::OsRng, RngCore};
use secp256k1::{schnorr::Signature, Keypair, PublicKey, SecretKey, SECP256K1};
use strata_bridge_btcio::{
    traits::{Reader, Wallet},
    BitcoinClient,
};
use strata_bridge_primitives::{params::prelude::MIN_RELAY_FEE, scripts::prelude::*};
use tracing::trace;

#[derive(Debug, Clone)]
pub struct Agent {
    keypair: Keypair,

    pub client: Arc<BitcoinClient>,
}

impl Agent {
    pub async fn new(keypair: Keypair, btc_url: &str, btc_user: &str, btc_pass: &str) -> Self {
        let client = BitcoinClient::new(btc_url, btc_user, btc_pass)
            .expect("should be able to create bitcoin client");
        let client = Arc::new(client);

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
        .expect("should be able to create message hash");

        SECP256K1.sign_schnorr(&msg, &self.keypair)
    }

    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    pub fn secret_key(&self) -> SecretKey {
        SecretKey::from_keypair(&self.keypair)
    }

    pub async fn select_utxo(
        &self,
        target_amount: Amount,
        reserved_utxos: HashSet<OutPoint>,
    ) -> Option<(Address, OutPoint, Amount, TxOut)> {
        let unspent_utxos = self
            .client
            .get_utxos()
            .await
            .expect("should be able to get unspent utxos");

        let change_address = self
            .client
            .get_new_address()
            .await
            .expect("should get change address");

        // FIXME: allow selecting multiple UTXOs that sum up to the required amount
        for entry in unspent_utxos {
            let outpoint = OutPoint {
                txid: entry.txid,
                vout: entry.vout,
            };
            if reserved_utxos.contains(&outpoint) {
                // this utxo has already been selected for some other tx
                continue;
            }

            let network = self
                .client
                .network()
                .await
                .expect("should get network from node");

            trace!(%entry.amount, %entry.txid, %entry.vout, %entry.confirmations, "checking unspent utxos");
            if entry.amount > target_amount + MIN_RELAY_FEE {
                return Some((
                    change_address,
                    OutPoint {
                        txid: entry.txid,
                        vout: entry.vout,
                    },
                    entry.amount,
                    TxOut {
                        value: entry.amount,
                        script_pubkey: entry
                            .address
                            .require_network(network)
                            .expect("address should be valid")
                            .script_pubkey(),
                    },
                ));
            }
        }

        None
    }

    /// Generate a random secret nonce.
    ///
    /// Please refer to MuSig2 nonce generation section in
    /// [BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).
    ///
    /// # Notes
    ///
    /// The entropy is pooled using the underlying operating system's
    /// cryptographic-safe pseudo-random number generator with [`OsRng`].
    pub fn generate_sec_nonce(&self, txid: &Txid, key_agg_ctx: &KeyAggContext) -> SecNonce {
        let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();

        let mut nonce_seed = [0u8; 32];
        OsRng.fill_bytes(&mut nonce_seed);

        let seckey = SecretKey::from_keypair(&self.keypair);

        SecNonce::build(nonce_seed)
            .with_seckey(seckey)
            .with_message(txid.as_byte_array())
            .with_aggregated_pubkey(aggregated_pubkey)
            .build()
    }
}
