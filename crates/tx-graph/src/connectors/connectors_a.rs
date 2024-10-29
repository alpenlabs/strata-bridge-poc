use bitcoin::Network;
use bitvm::{
    bigint::U254,
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    signatures::wots::wots256,
    treepp::*,
};

use crate::{
    commitments::{secret_key_for_bridge_out_txid, secret_key_for_proof_element},
    scripts::transform::fq_from_nibbles,
};

struct ConnectorA256<const N_PUBLIC_KEYS: usize> {
    network: Network,
    public_keys: [(u32, wots256::PublicKey); N_PUBLIC_KEYS],
}

impl ConnectorA256 {
    fn create_locking_script(&self) -> ScriptBuf {
        script! {
            for (_, public_key) in self.public_keys {
                { wots256::checksig_verify(public_key) }
                { fq_from_nibbles }
                { U254::push_u32_le(&Fq::MODULUS_LIMBS)}
                { U254::greaterthan(0, 1) }
                OP_VERIFY
            }
        }
    }

    pub fn create_taproot_address(&self) -> Address {
        let scripts = &[self.create_locking_script()];

        let (taproot_address, _) =
            create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
                .expect("should be able to add scripts");

        taproot_address
    }

    pub fn create_tx_input(
        &self,
        msk: &str,
        _n_of_n_sig: Signature,
        values: [&[u8]; N_PUBLIC_KEYS],
    ) -> Input {
        script! {
            for i in (0..self.public_keys.len()).rev() {
                { wots256::sign(&secret_key_for_proof_element(msk, self.public_keys[i].0), values[i]) }
            }
        }
    }
}

struct ConnectorA160<const N_PUBLIC_KEYS: usize> {
    network: Network,
    public_keys: [(u32, wots160::PublicKey); N_PUBLIC_KEYS],
}

impl ConnectorA160 {
    fn create_locking_script(&self) -> ScriptBuf {
        script! {
            for (_, public_key) in self.public_keys {
                { wots160::checksig_verify(public_key) }
                { fq_from_nibbles }
                { U254::push_u32_le(&Fq::MODULUS_LIMBS)}
                { U254::greaterthan(0, 1) }
                OP_VERIFY
            }
        }
    }

    pub fn create_taproot_address(&self) -> Address {
        let scripts = &[self.create_locking_script()];

        let (taproot_address, _) =
            create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
                .expect("should be able to add scripts");

        taproot_address
    }

    pub fn create_tx_input(
        &self,
        msk: &str,
        _n_of_n_sig: Signature,
        values: [&[u8]; N_PUBLIC_KEYS],
    ) -> Input {
        script! {
            for i in (0..self.public_keys.len()).rev() {
                { wots160::sign(&secret_key_for_proof_element(msk, self.public_keys[i].0), values[i]) }
            }
        }
    }
}
