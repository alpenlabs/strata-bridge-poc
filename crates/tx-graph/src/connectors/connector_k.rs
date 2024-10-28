use bitcoin::{psbt::Input, taproot::Signature, Address, Network, ScriptBuf};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

use crate::scripts::prelude::*;

#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub struct ConnectorK {
    pub n_of_n_agg_key: XOnlyPublicKey,

    pub network: Network,
    // this needs WOTS data
}

impl ConnectorK {
    fn create_locking_script(&self) -> ScriptBuf {
        unimplemented!(
            "call bitvm impl to create the locking script for T_s and SuperBlock bitcommitments"
        );
    }

    pub fn create_taproot_address(&self) -> Address {
        let scripts = &[self.create_locking_script()];

        let (taproot_address, _) =
            create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
                .expect("should be able to add scripts");

        taproot_address
    }

    pub fn create_tx_input(&self, _n_of_n_sig: Signature /* , wots data */) -> Input {
        // 1. Create an array of witness data (`[Vec<u8>]`) `n_of_n_sig` and bitcommitments.
        // 2. Call taproot::finalize_input() to create the signed psbt input.
        unimplemented!("call the bitvm impl to generate witness data for bitcommitments");
    }
}
