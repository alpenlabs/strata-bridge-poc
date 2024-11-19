use std::str::FromStr;

use alloy::primitives::Address as EvmAddress;
use bitcoin::{
    address::Address,
    hashes::Hash,
    hex::DisplayHex,
    key::Keypair,
    secp256k1::{Secp256k1, XOnlyPublicKey},
    taproot::TaprootBuilder,
    ScriptBuf, TapNodeHash,
};
use miniscript::Miniscript;
use tracing::info;

use crate::constants::{AGGREGATED_PUBKEY, LOCKTIME, NETWORK, NUMS_POINT};

pub(crate) fn get_aggregated_pubkey() -> XOnlyPublicKey {
    *AGGREGATED_PUBKEY
}

pub(crate) fn generate_taproot_address(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    n_of_n_multisig_script: ScriptBuf,
    timelock_script: ScriptBuf,
) -> (TapNodeHash, Address) {
    let nums_point_str = NUMS_POINT;
    let xonly_bytes = hex::decode(&nums_point_str[2..]).expect("Decoding hex failed");
    assert_eq!(xonly_bytes.len(), 32); //TODO handle this more gracefully
    let unspendable_key =
        XOnlyPublicKey::from_slice(&xonly_bytes).expect("Failed to parse XOnlyPublicKey");

    let taproot_builder = TaprootBuilder::new()
        .add_leaf(1, n_of_n_multisig_script.clone())
        .expect("failed to add n-of-n multisig script to tree")
        .add_leaf(1, timelock_script.clone())
        .expect("failed to add timelock script");

    let script_hash =
        TapNodeHash::from_script(&timelock_script, bitcoin::taproot::LeafVersion::TapScript);

    let taproot_info = taproot_builder.finalize(secp, unspendable_key).unwrap();
    let merkle_root = taproot_info.merkle_root();

    let tr_address = Address::p2tr(secp, unspendable_key, merkle_root, NETWORK);
    (script_hash, tr_address)
}

pub(crate) fn build_n_of_n_multisig_miniscript(aggregated_pubkey: XOnlyPublicKey) -> ScriptBuf {
    let script = format!("pk({})", aggregated_pubkey);
    let miniscript = Miniscript::<XOnlyPublicKey, miniscript::Tap>::from_str(&script).unwrap();
    miniscript.encode()
}

pub(crate) fn build_timelock_miniscript(recovery_xonly_pubkey: XOnlyPublicKey) -> ScriptBuf {
    let script = format!("and_v(v:pk({}),older({}))", recovery_xonly_pubkey, LOCKTIME);
    let miniscript = Miniscript::<XOnlyPublicKey, miniscript::Tap>::from_str(&script).unwrap();
    miniscript.encode()
}

pub(crate) fn build_op_return_script(
    evm_address: &EvmAddress,
    script_hash: &TapNodeHash,
) -> Vec<u8> {
    let magic_bytes = b"alpenstrata".to_vec();
    let mut data = magic_bytes;
    data.extend(script_hash.to_raw_hash().as_byte_array());
    data.extend(evm_address.as_slice());

    data
}

pub(crate) fn get_recovery_pubkey() -> XOnlyPublicKey {
    let keypair = Keypair::new(
        &bitcoin::secp256k1::Secp256k1::new(),
        &mut bitcoin::key::rand::thread_rng(),
    );
    let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
    let secret_key = keypair.secret_bytes().to_lower_hex_string();

    info!(event = "generated random x-only pubkey for recovery", %secret_key, %xonly_pubkey);

    xonly_pubkey
}