use bitcoin::{Amount, OutPoint, PubkeyHash, PublicKey};

#[derive(Debug)]
pub struct PegOutEvent {
    pub withdrawer_chain_address: String,
    pub withdrawer_public_key_hash: PubkeyHash,
    pub source_outpoint: OutPoint,
    pub amount: Amount,
    pub operator_public_key: PublicKey,
    pub timestamp: u32,
}

#[derive(Debug)]
pub struct PegOutBurntEvent {
    pub withdrawer_chain_address: String,
    pub source_outpoint: OutPoint,
    pub amount: Amount,
    pub operator_public_key: PublicKey,
    pub timestamp: u32,
}

#[derive(Debug)]
pub struct PegInEvent {
    pub depositor: String,
    pub amount: Amount,
    pub depositor_pubkey: PublicKey,
}

#[allow(unused)] // this will be used later
static CLIENT_MISSING_ORACLE_DRIVER_ERROR: &str = "Bridge client is missing chain adaptor";
