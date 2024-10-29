use bitcoin::{psbt::Input, Address, Network};
use secp256k1::{schnorr::Signature, XOnlyPublicKey};

use crate::scripts::prelude::*;

#[derive(Debug, Clone, Copy)]
pub struct ConnectorS {
    pub agg_key: XOnlyPublicKey,
    pub network: Network,
}

impl ConnectorS {
    pub fn create_taproot_address(&self) -> Address {
        let (addr, _spend_info) = create_taproot_addr(
            &self.network,
            SpendPath::KeySpend {
                internal_key: self.agg_key,
            },
        )
        .expect("should be able to create taproot address");

        addr
    }

    pub fn create_tx_input<'input>(
        &self,
        signature: Signature,
        input: &'input mut Input,
    ) -> &'input Input {
        finalize_input(input, [signature.as_ref()]);

        input
    }
}
