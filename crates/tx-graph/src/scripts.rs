//! Defines bitcoin scripts that are reused across various transactions.
//!
//! There are two sets of functions in this module:
//!
//! * Ones that create Bitcoin script, and
//! * Ones that create addresses (p2wsh, p2tr, etc.) from the created script.
use std::str::FromStr;

use bitcoin::{
    hashes::{ripemd160::Hash as Ripemd160, sha256::Hash as Sha256, Hash},
    Address, CompressedPublicKey, Network, PublicKey, ScriptBuf, XOnlyPublicKey,
};
use bitcoin_script::script;
use lazy_static::lazy_static;

lazy_static! {
    /// This is an unspendable pubkey.
    ///
    /// This is generated via <https://github.com/alpenlabs/unspendable-pubkey-gen> following [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs)
    /// with `r = 0x82758434e13488368e0781c4a94019d3d6722f854d26c15d2d157acd1f464723`.
    pub static ref UNSPENDABLE_INTERNAL_KEY: XOnlyPublicKey =
        XOnlyPublicKey::from_str("2be4d02127fedf4c956f8e6d8248420b9af78746232315f72894f0b263c80e81").unwrap();
}

/// Creates a script locked with an unspendable pubkey.
///
/// The funds sent to this address are not exactly burnt but are just unspendable possibly forever
/// till the private key is discovered.
pub fn generate_burn_script() -> ScriptBuf {
    let mut unspendable_public_key = [0u8; 33];

    unspendable_public_key[0] = 0x02; // Even parity
    unspendable_public_key[1..].clone_from_slice(&UNSPENDABLE_INTERNAL_KEY.serialize());

    let unspendable_public_key =
        PublicKey::from_slice(&unspendable_public_key).expect("must be valid");

    generate_pay_to_pubkey_script(&unspendable_public_key)
}

/// Creates first a burn script and then, creates a `p2wsh` address from it.
pub fn generate_burn_script_address(network: Network) -> Address {
    Address::p2wsh(&generate_burn_script(), network)
}

/// Creates first a burn script and then, creates a `p2tr` address from it.
pub fn generate_burn_taproot_script() -> ScriptBuf {
    generate_pay_to_pubkey_taproot_script(&UNSPENDABLE_INTERNAL_KEY)
}

/// Creates a p2wsh script that anyone can spend.
pub fn generate_anyone_can_spend_address(network: Network) -> Address {
    let script = script! {
        OP_TRUE
    }
    .compile();

    Address::p2wsh(&script, network)
}

/// Creates a pay to pubkey script with [`OP_CHECKSIG`].
pub fn generate_pay_to_pubkey_script(public_key: &PublicKey) -> ScriptBuf {
    script! {
        { *public_key }
        OP_CHECKSIG
    }
    .compile()
}

/// Creates a pay to pubkey script with [`OP_CHECKSIG`] including an inscription that includes:
///
/// * A public key hash
/// * A timestamp (u32) and
/// * An evm address
pub fn generate_pay_to_pubkey_hash_with_inscription_script(
    public_key: &PublicKey,
    timestamp: u32,
    evm_address: &str,
) -> ScriptBuf {
    let inscription = [
        public_key.pubkey_hash().as_byte_array().to_vec(),
        timestamp.to_be_bytes().to_vec(),
        evm_address.as_bytes().to_vec(),
    ]
    .concat();
    let inscription_hash = Ripemd160::hash(&Sha256::hash(&inscription).to_byte_array());
    script! {
        OP_FALSE
        OP_IF
        { inscription_hash.to_byte_array().to_vec() }
        OP_ENDIF
        OP_DUP
        OP_HASH160
        { public_key.pubkey_hash().as_byte_array().to_vec() }
        OP_EQUALVERIFY
        OP_CHECKSIG
    }
    .compile()
}

pub fn generate_p2pkh_address(network: Network, public_key: &PublicKey) -> Address {
    Address::p2pkh(
        CompressedPublicKey::try_from(*public_key).expect("Could not compress public key"),
        network,
    )
}

pub fn generate_p2wpkh_address(network: Network, public_key: &PublicKey) -> Address {
    Address::p2wpkh(
        &CompressedPublicKey::try_from(*public_key).expect("Could not compress public key"),
        network,
    )
}

pub fn generate_pay_to_pubkey_script_address(network: Network, public_key: &PublicKey) -> Address {
    Address::p2wsh(&generate_pay_to_pubkey_script(public_key), network)
}

pub fn generate_pay_to_pubkey_hash_with_inscription_script_address(
    network: Network,
    public_key: &PublicKey,
    timestamp: u32,
    evm_address: &str,
) -> Address {
    Address::p2wsh(
        &generate_pay_to_pubkey_hash_with_inscription_script(public_key, timestamp, evm_address),
        network,
    )
}

pub fn generate_pay_to_pubkey_taproot_script(public_key: &XOnlyPublicKey) -> ScriptBuf {
    script! {
        { *public_key }
        OP_CHECKSIG
    }
    .compile()
}

pub fn generate_pay_to_pubkey_taproot_script_address(
    network: Network,
    public_key: &XOnlyPublicKey,
) -> Address {
    Address::p2wsh(&generate_pay_to_pubkey_taproot_script(public_key), network)
}

/// Generates a timelock script with a pubkey using [`OP_CSV`] and [`OP_CHECKSIG`].
pub fn generate_timelock_script(public_key: &PublicKey, num_blocks_timelock: u32) -> ScriptBuf {
    script! {
      { num_blocks_timelock }
      OP_CSV
      OP_DROP
      { *public_key }
      OP_CHECKSIG
    }
    .compile()
}

pub fn generate_timelock_script_address(
    network: Network,
    public_key: &PublicKey,
    num_blocks_timelock: u32,
) -> Address {
    Address::p2wsh(
        &generate_timelock_script(public_key, num_blocks_timelock),
        network,
    )
}

pub fn generate_timelock_taproot_script(
    public_key: &XOnlyPublicKey,
    num_blocks_timelock: u32,
) -> ScriptBuf {
    script! {
      { num_blocks_timelock }
      OP_CSV
      OP_DROP
      { *public_key }
      OP_CHECKSIG
    }
    .compile()
}

pub fn generate_timelock_taproot_script_address(
    network: Network,
    public_key: &XOnlyPublicKey,
    num_blocks_timelock: u32,
) -> Address {
    Address::p2wsh(
        &generate_timelock_taproot_script(public_key, num_blocks_timelock),
        network,
    )
}
