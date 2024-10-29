use bitcoin::{
    psbt::Input, taproot::{ControlBlock, LeafVersion, Signature}, Address, Network, ScriptBuf, Transaction, Witness
};
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

    pub fn generate_spend_info(&self) -> (ScriptBuf, ControlBlock) {
        let script = self.create_locking_script();

        let (_, spend_info) = create_taproot_addr(
            &self.network,
            SpendPath::ScriptSpend {
                scripts: &[script.clone()],
            },
        )
        .expect("should be able to create taproot address");

        let control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script must be part of the address");

        (script, control_block)
    }

    pub fn create_tx_input(&self, _n_of_n_sig: Signature /* , wots data */) -> Input {
        let mut witness_stack = Witness::new();

        let (script, control_block) = self.generate_spend_info();
        witness_stack.push(script.to_bytes());
        witness_stack.push(control_block.serialize());

        Transaction { version: todo!(), lock_time: todo!(), input: todo!(), output: todo!() }

        // 1. Create an array of witness data (`[Vec<u8>]`) `n_of_n_sig` and bitcommitments.
        // 2. Call taproot::finalize_input() to create the signed psbt input.
        unimplemented!("call the bitvm impl to generate witness data for bitcommitments and push it beofre the script to the stack");
    }
}
