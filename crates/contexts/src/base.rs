use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::{All, PublicKey as Secp256k1PublicKey},
    Network, PrivateKey, PublicKey, XOnlyPublicKey,
};
use musig2::{secp::Point, KeyAggContext};
/// Defines the methods expected of context required to create bridge-related transactions.
///
/// This includes the bitcoin [`Network`], the secp engine [`Secp256k1`], the list of bridge
/// operator's [`PublicKey`]'s and their aggregated version.
///
/// FIXME: Possible smell: this follows the `BaseClass` pattern where other "classes" may inherit
/// from this one.
pub trait BaseContext {
    fn network(&self) -> Network;
    fn secp(&self) -> &Secp256k1<All>;
    fn n_of_n_public_keys(&self) -> &Vec<PublicKey>;
    fn n_of_n_public_key(&self) -> &PublicKey;
    fn n_of_n_taproot_public_key(&self) -> &XOnlyPublicKey;
}

/// Utility to convert a secret [`str`] to a [`Keypair`] and a [`PublicKey`].
pub fn generate_keys_from_secret(
    network: Network,
    secret: &str,
) -> (Secp256k1<All>, Keypair, PublicKey) {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_str(&secp, secret).unwrap();
    let private_key = PrivateKey::new(keypair.secret_key(), network);
    let public_key = PublicKey::from_private_key(&secp, &private_key);

    (secp, keypair, public_key)
}

/// Utility to convert a list of [`PublicKey`]'s into a [`musig2`] aggregated pubkey.
pub fn generate_n_of_n_public_key(n_of_n_public_keys: &[PublicKey]) -> (PublicKey, XOnlyPublicKey) {
    let public_keys: Vec<Point> = n_of_n_public_keys
        .iter()
        .map(|&public_key| public_key.inner.into())
        .collect();

    let key_agg_context = KeyAggContext::new(public_keys).unwrap();
    let aggregated_key: Secp256k1PublicKey = key_agg_context.aggregated_pubkey();

    let n_of_n_public_key = PublicKey::from(aggregated_key);
    let n_of_n_taproot_public_key = XOnlyPublicKey::from(n_of_n_public_key);

    (n_of_n_public_key, n_of_n_taproot_public_key)
}
