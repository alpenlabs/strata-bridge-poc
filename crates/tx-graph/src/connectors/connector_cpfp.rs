use bitcoin::{Address, Network, ScriptBuf, TxIn};
use bitcoin_script::script;
use serde::{Deserialize, Serialize};

use super::connector::*;
use crate::transactions::base::Input;

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorCpfp {
    pub network: Network,
}

impl ConnectorCpfp {
    pub fn new(network: Network) -> Self {
        Self { network }
    }
}

impl P2wshConnector for ConnectorCpfp {
    fn generate_script(&self) -> ScriptBuf {
        script! {
            OP_TRUE
        }
        .compile()
    }

    fn generate_address(&self) -> Address {
        Address::p2wsh(&self.generate_script(), self.network)
    }

    fn generate_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }
}
