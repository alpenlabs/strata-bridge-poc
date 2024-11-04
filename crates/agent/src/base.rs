use std::{collections::HashSet, sync::Arc};

use bitcoin::{
    sighash::{Prevouts, SighashCache},
    Address, Amount, OutPoint, TapSighashType, Transaction, TxOut,
};
use secp256k1::{schnorr::Signature, Keypair, PublicKey, SECP256K1};
use strata_bridge_btcio::{traits::Wallet, BitcoinClient};
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
        .expect("should be ablet o create message hash");

        SECP256K1.sign_schnorr(&msg, &self.keypair)
    }

    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    pub async fn select_utxo(
        &self,
        target_amount: Amount,
        reserved_utxos: HashSet<OutPoint>,
    ) -> Option<(Address, OutPoint, Amount)> {
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

            trace!(%entry.amount, %entry.txid, %entry.vout, %entry.confirmations, "checking unspent utxos");
            if entry.amount > target_amount + MIN_RELAY_FEE {
                return Some((
                    change_address,
                    OutPoint {
                        txid: entry.txid,
                        vout: entry.vout,
                    },
                    entry.amount,
                ));
            }
        }

        None
    }
}
