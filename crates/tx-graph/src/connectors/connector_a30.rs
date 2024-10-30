use bitcoin::{
    psbt::Input,
    taproot::{ControlBlock, LeafVersion, TaprootSpendInfo},
    Address, Network, ScriptBuf, Txid, XOnlyPublicKey,
};

use super::params::PAYOUT_TIMELOCK;
use crate::{db::Database, scripts::prelude::*};

#[derive(Debug, Clone, Copy)]
pub struct ConnectorA30<Db: Database> {
    agg_pubkey: XOnlyPublicKey,
    network: Network,

    db: Db,
}

#[derive(Debug, Clone)]
pub enum ConnectorA30Leaf {
    Payout,
    Disprove,
}

impl<Db: Database + Clone> ConnectorA30<Db> {
    pub fn new(agg_pubkey: &XOnlyPublicKey, network: &Network, db: Db) -> Self {
        Self {
            agg_pubkey: *agg_pubkey,
            network: *network,

            db: db.clone(),
        }
    }

    pub fn generate_tapleaf(&self, tapleaf: ConnectorA30Leaf) -> ScriptBuf {
        match tapleaf {
            ConnectorA30Leaf::Payout => n_of_n_with_timelock(&self.agg_pubkey, PAYOUT_TIMELOCK),
            ConnectorA30Leaf::Disprove => n_of_n_script(&self.agg_pubkey),
        }
    }

    pub fn generate_locking_script(&self) -> ScriptBuf {
        let (address, _) = self.generate_taproot_address();

        address.script_pubkey()
    }

    pub fn generate_spend_info(&self, tapleaf: ConnectorA30Leaf) -> (ScriptBuf, ControlBlock) {
        let (_, taproot_spend_info) = self.generate_taproot_address();

        let script = self.generate_tapleaf(tapleaf);
        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script is always present in the address");

        (script, control_block)
    }

    fn generate_taproot_address(&self) -> (Address, TaprootSpendInfo) {
        let scripts = &[
            self.generate_tapleaf(ConnectorA30Leaf::Payout),
            self.generate_tapleaf(ConnectorA30Leaf::Disprove),
        ];

        create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
            .expect("should be able to create taproot address")
    }

    pub fn finalize_input(&self, input: &mut Input, txid: Txid, tapleaf: ConnectorA30Leaf) {
        let (script, control_block) = self.generate_spend_info(tapleaf);
        let n_of_n_sig = self.db.get_signature(txid);

        finalize_input(
            input,
            [
                n_of_n_sig.serialize().to_vec(),
                script.to_bytes(),
                control_block.serialize(),
            ],
        );
    }
}
