use bitcoin::Txid;
use bitvm::{
    groth16::g16,
    signatures::wots::{wots160, wots256, wots32},
};
use strata_bridge_tx_graph::commitments::{
    secret_key_for_bridge_out_txid, secret_key_for_proof_element, secret_key_for_superblock_hash,
    secret_key_for_superblock_period_start_ts,
};

pub struct Operator {
    id: u32,
    wots_master_secret_key: String,
}

impl Operator {
    pub fn new(id: u32, wots_master_secret_key: String) -> Self {
        Self {
            id,
            wots_master_secret_key,
        }
    }

    pub fn run() {}

    pub fn get_deposit_master_secret_key(&self, deposit_txid: Txid) -> String {
        format!(
            "{}:{}",
            self.wots_master_secret_key,
            deposit_txid.to_string()
        )
    }

    fn generate_wots_public_keys(&self, deposit_txid: Txid) -> g16::WotsPublicKeys {
        let deposit_msk = self.get_deposit_master_secret_key(deposit_txid);
        (
            (
                wots32::generate_public_key(&secret_key_for_superblock_period_start_ts(
                    &deposit_msk,
                )),
                wots256::generate_public_key(&secret_key_for_bridge_out_txid(&deposit_msk)),
                wots256::generate_public_key(&secret_key_for_superblock_hash(&deposit_msk)),
            ),
            std::array::from_fn(|i| {
                wots256::generate_public_key(&secret_key_for_proof_element(&deposit_msk, i as u32))
            }),
            std::array::from_fn(|i| {
                wots160::generate_public_key(&secret_key_for_proof_element(&deposit_msk, i as u32))
            }),
        )
    }
}
