use bitcoin::{Psbt, Txid};
use serde::{Deserialize, Serialize};

use crate::connectors::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAssertData {
    claim_txid: Txid,
}

#[derive(Debug, Clone)]
pub struct PreAssertTx {
    _psbt: Psbt,

    _data: PreAssertData,
}

impl PreAssertTx {
    pub fn new(
        _data: PreAssertData,
        _connector_c0: ConnectorC0,
        _connector_s: ConnectorS,
        _connector_a1: ConnectorA256Factory<7, 7, 49>,
    ) -> Self {
        todo!()
    }
}
