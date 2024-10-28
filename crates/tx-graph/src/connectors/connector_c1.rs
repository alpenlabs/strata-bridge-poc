use bitcoin::{Network, ScriptBuf};
use secp256k1::XOnlyPublicKey;

use crate::scripts::prelude::*;

#[derive(Debug, Clone, Copy)]
pub struct ConnectorC1 {
    agg_pubkey: XOnlyPublicKey,
    network: Network,
}

impl ConnectorC1 {
    pub fn new(agg_pubkey: &XOnlyPublicKey, network: &Network) -> Self {
        Self {
            agg_pubkey: *agg_pubkey,
            network: *network,
        }
    }

    pub fn generate_locking_script(&self) -> ScriptBuf {
        let (taproot_address, _) = create_taproot_addr(
            &self.network,
            SpendPath::KeySpend {
                internal_key: self.agg_pubkey,
            },
        )
        .expect("should be able to create taproot address");

        taproot_address.script_pubkey()
    }
}
