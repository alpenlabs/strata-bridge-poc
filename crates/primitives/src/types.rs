use std::collections::BTreeMap;

use bitcoin::Psbt;
use musig2::{errors::KeyAggError, KeyAggContext};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

use crate::scripts::taproot::TaprootWitness;

pub type OperatorIdx = u32;
pub type BitcoinBlockHeight = u64;

/// A table that maps [`OperatorIdx`] to the corresponding [`PublicKey`].
///
/// We use a [`PublicKey`] instead of an [`bitcoin::secp256k1::XOnlyPublicKey`] for convenience
/// since the [`musig2`] crate has functions that expect a [`PublicKey`] and this table is most
/// useful for interacting with those functions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublickeyTable(pub BTreeMap<OperatorIdx, PublicKey>);

impl From<BTreeMap<OperatorIdx, PublicKey>> for PublickeyTable {
    fn from(value: BTreeMap<OperatorIdx, PublicKey>) -> Self {
        Self(value)
    }
}

impl From<PublickeyTable> for Vec<PublicKey> {
    fn from(value: PublickeyTable) -> Self {
        value.0.values().copied().collect()
    }
}

impl TryFrom<PublickeyTable> for KeyAggContext {
    type Error = KeyAggError;

    fn try_from(value: PublickeyTable) -> Result<Self, Self::Error> {
        KeyAggContext::new(Into::<Vec<PublicKey>>::into(value))
    }
}

/// All the information necessary to produce a valid signature for a transaction in the bridge.
#[derive(Debug, Clone)]
pub struct TxSigningData {
    /// The unsigned [`Transaction`](bitcoin::Transaction) (with the `script_sig` and `witness`
    /// fields empty).
    pub psbt: Psbt,

    /// The spend path for the unsigned taproot input in the transaction
    /// respectively.
    ///
    /// If a script-path path is being used, the witness stack needs the script being spent and the
    /// control block in addition to the signature.
    /// See [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs).
    pub spend_path: TaprootWitness,
}
