use bitcoin::{
    psbt::Input,
    taproot::{ControlBlock, LeafVersion},
    Address, Network, ScriptBuf,
};

use super::constants::{NUM_CONNECTOR_A256, NUM_SCRIPTS_A256_PER_CONNECTOR};
use crate::scripts::prelude::{create_taproot_addr, finalize_input, SpendPath};

#[derive(Debug, Clone)]
pub struct ConnectorA256Factory {
    pub network: Network,
    // full data
}

impl ConnectorA256Factory {
    pub fn new(network: &Network) -> Self {
        Self { network: *network }
    }

    pub fn create_connectors(&self) -> [ConnectorA256; NUM_CONNECTOR_A256] {
        todo!();
    }
}

#[derive(Debug, Clone)]
pub struct ConnectorA256 {
    network: Network,
    // relevant data
}

impl ConnectorA256 {
    pub fn new(network: &Network) -> Self {
        Self { network: *network }
    }

    pub fn create_locking_script(&self) -> ScriptBuf {
        unimplemented!(
            "generate locking script to bitcommit to NUM_SCRIPTS_A256_PER_CONNECTOR values"
        );
    }

    pub fn create_taproot_address(&self) -> Address {
        let script = self.create_locking_script();
        let (addr, _spend_info) =
            create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts: &[script] })
                .expect("should be able to create taproot address");

        addr
    }

    pub fn generate_control_block(&self) -> (ScriptBuf, ControlBlock) {
        let script = self.create_locking_script();
        let (_, taproot_spend_info) = create_taproot_addr(
            &self.network,
            SpendPath::ScriptSpend {
                scripts: &[script.clone()],
            },
        )
        .expect("should be able to create taproot address");

        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script is always present in the address");

        (script, control_block)
    }

    pub fn create_tx_input(
        &self,
        input: &mut Input,
        _field_elements_256: [[u8; 256]; NUM_SCRIPTS_A256_PER_CONNECTOR],
    ) {
        let (script, control_block) = self.generate_control_block();

        // TODO: create witness script sig
        let witness = vec![];

        finalize_input(
            input,
            [witness, script.to_bytes(), control_block.serialize()],
        );
    }
}
