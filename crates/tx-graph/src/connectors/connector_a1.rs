use bitcoin::{
    psbt::Input,
    taproot::{ControlBlock, LeafVersion},
    Address, Network, ScriptBuf, Witness,
};

use super::constants::{NUM_CONNECTOR_A256, NUM_SCRIPTS_A256, NUM_SCRIPTS_A256_PER_CONNECTOR};
use crate::scripts::prelude::{create_taproot_addr, finalize_input, SpendPath};

#[derive(Debug, Clone)]
pub struct ConnectorA256Factory {
    pub network: Network,
}

impl ConnectorA256Factory {
    pub fn new(network: &Network) -> Self {
        Self { network: *network }
    }

    pub fn create_connectors(&self) -> [ConnectorA256; NUM_CONNECTOR_A256] {
        let scripts: [ScriptBuf; NUM_SCRIPTS_A256] = [ScriptBuf::new(); NUM_SCRIPTS_A256];

        let mut connectors: Vec<ConnectorA256> = Vec::with_capacity(NUM_CONNECTOR_A256);

        for (offset, script) in scripts
            .iter()
            .enumerate()
            .step_by(NUM_SCRIPTS_A256_PER_CONNECTOR)
        {
            let connector_a256 = ConnectorA256::new(
                &self.network,
                scripts[offset..offset + NUM_SCRIPTS_A256_PER_CONNECTOR],
            );

            connectors.push(connector_a256);
        }

        connectors[..NUM_CONNECTOR_A256]
            .try_into()
            .expect("must have exactly NUM_CONNECTOR_A256 elements")
    }
}

#[derive(Debug, Clone)]
pub struct ConnectorA256 {
    network: Network,
    scripts: [ScriptBuf; NUM_SCRIPTS_A256_PER_CONNECTOR],
}

impl ConnectorA256 {
    pub fn new(network: &Network, scripts: [ScriptBuf; NUM_SCRIPTS_A256_PER_CONNECTOR]) -> Self {
        Self {
            network: *network,
            scripts,
        }
    }

    pub fn create_taproot_address(&self) -> Address {
        let (addr, _spend_info) = create_taproot_addr(
            &self.network,
            SpendPath::ScriptSpend {
                scripts: &[self.scripts.clone()],
            },
        )
        .expect("should be able to create taproot address");

        addr
    }

    pub fn generate_control_block(&self) -> ControlBlock {
        let (_, taproot_spend_info) = create_taproot_addr(
            &self.network,
            SpendPath::ScriptSpend {
                scripts: &[self.scripts.clone()],
            },
        )
        .expect("should be able to create taproot address");

        let control_block = taproot_spend_info
            .control_block(&(self.scripts.clone(), LeafVersion::TapScript))
            .expect("script is always present in the address");

        control_block
    }

    pub fn create_tx_input<'input>(
        &self,
        input: &'input mut Input,
        field_element_256: [[u8; 256]; NUM_SCRIPTS_A256_PER_CONNECTOR],
    ) -> &'input Input {
        let mut witness_stack = Witness::new();

        witness_stack.push(data);

        let control_block = self.generate_control_block();

        witness_stack.push(self.scripts.to_bytes());
        witness_stack.push(control_block.serialize());

        finalize_input(input, witness_stack.into_iter());

        input
    }
}
