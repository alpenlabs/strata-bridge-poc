use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

use super::{super::transactions::base::Input, connector::*};
use crate::scripts::UNSPENDABLE_INTERNAL_KEY;

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorK {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
}

impl ConnectorK {
    pub fn new(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
    ) -> Self {
        ConnectorK {
            network,
            operator_taproot_public_key: *operator_taproot_public_key,
            n_of_n_taproot_public_key: *n_of_n_taproot_public_key,
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        todo!("add a script that allows bitcommitments to `T_s` and `BridgeOutOutPoint` (may or may not require N/N)")
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        // FIXME: should read the `T_s` commitment from the `input` and use that as the timelock.
        generate_timelock_tx_in(input, 0)
    }
}

impl TaprootConnector for ConnectorK {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(0, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .finalize(SECP256K1, *UNSPENDABLE_INTERNAL_KEY)
            .expect("should be able to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}
