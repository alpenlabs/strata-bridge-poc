use bitcoin::{Psbt, Txid};
use serde::{Deserialize, Serialize};

use crate::connectors::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertWithOutputChunksData {
    claim_txid: Txid,
}

#[derive(Debug, Clone)]
pub struct AssertWithOutputChunks {
    psbt: Psbt,

    data: AssertWithOutputChunksData,
}

impl AssertWithOutputChunksData {
    pub fn new(
        data: AssertWithOutputChunksData,
        connector_c0: ConnectorC0,
        connector_s: ConnectorS,
        connector_a1: ConnectorA1Factory,
    ) -> Self {
        todo!()
    }
}
