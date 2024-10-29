use bitcoin::{psbt::Input, Address, Network, ScriptBuf};
use bitvm::{
    bigint::U254,
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    signatures::wots::{wots160, wots256},
    treepp::*,
};
use secp256k1::schnorr::Signature;

use crate::{
    commitments::secret_key_for_proof_element,
    scripts::{
        prelude::{create_taproot_addr, SpendPath},
        transform::fq_from_nibbles,
    },
};

struct ConnectorA256<const N_PUBLIC_KEYS: usize> {
    network: Network,
    public_keys: [(u32, wots256::PublicKey); N_PUBLIC_KEYS],
}

impl<const N_PUBLIC_KEYS: usize> ConnectorA256<N_PUBLIC_KEYS> {
    fn create_locking_script(&self) -> ScriptBuf {
        script! {
            for (_, public_key) in self.public_keys {
                { wots256::checksig_verify(public_key) }
                { fq_from_nibbles() }
                { U254::push_u32_le(&Fq::MODULUS_LIMBS)}
                { U254::greaterthan(0, 1) }
                OP_VERIFY
            }
        }
        .compile()
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
        input: &mut Input,
        values: [&[u8]; N_PUBLIC_KEYS],
    ) -> Input {
        // let script = script! {
        //     for i in (0..self.public_keys.len()).rev() {
        //         { wots256::sign(&secret_key_for_proof_element(msk, self.public_keys[i].0),
        // values[i]) }     }
        // };
        todo!()
    }
}

struct ConnectorA160<const N_PUBLIC_KEYS: usize> {
    network: Network,
    public_keys: [(u32, wots160::PublicKey); N_PUBLIC_KEYS],
}

impl<const N_PUBLIC_KEYS: usize> ConnectorA160<N_PUBLIC_KEYS> {
    fn create_locking_script(&self) -> ScriptBuf {
        script! {
            for (_, public_key) in self.public_keys {
                { wots160::checksig_verify(public_key) }
                { fq_from_nibbles() }
                { U254::push_u32_le(&Fq::MODULUS_LIMBS)}
                { U254::greaterthan(0, 1) }
                OP_VERIFY
            }
        }
        .compile()
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
        // script! {
        //     for i in (0..self.public_keys.len()).rev() {
        //         { wots160::sign(&secret_key_for_proof_element(msk, self.public_keys[i].0),
        // values[i]) }     }
        // }
        todo!()
    }
}
