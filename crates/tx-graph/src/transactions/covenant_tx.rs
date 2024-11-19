use bitcoin::{sighash::Prevouts, Psbt, TxOut, Txid};
use strata_bridge_primitives::scripts::taproot::TaprootWitness;

pub trait CovenantTx {
    fn psbt(&self) -> &Psbt;

    fn psbt_mut(&mut self) -> &mut Psbt;

    fn prevouts(&self) -> Prevouts<'_, TxOut>;

    fn witnesses(&self) -> &[TaprootWitness];

    fn compute_txid(&self) -> Txid;
}
