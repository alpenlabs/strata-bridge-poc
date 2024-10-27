use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::All,
    Network, PublicKey, XOnlyPublicKey,
};

use crate::base::{generate_keys_from_secret, generate_n_of_n_public_key, BaseContext};

/// Holds all the information required to implement the [`BaseContext`] along with extra
/// information required to identify itself (such as the `Operator`'s own keypair and public
/// keys).
// FIXME: there is a lot of duplication on these structs. If we're following the `BaseClass`
// inheritance pattern, might make sense to just introduce an `Actor`/`Agent` that holds all the
// relevant information.
#[derive(Debug)]
pub struct OperatorContext {
    pub network: Network,
    pub secp: Secp256k1<All>,

    pub operator_keypair: Keypair,
    pub operator_public_key: PublicKey,
    pub operator_taproot_public_key: XOnlyPublicKey,

    pub n_of_n_public_keys: Vec<PublicKey>,
    pub n_of_n_public_key: PublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
}

impl BaseContext for OperatorContext {
    fn network(&self) -> Network {
        self.network
    }
    fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }
    fn n_of_n_public_keys(&self) -> &Vec<PublicKey> {
        &self.n_of_n_public_keys
    }
    fn n_of_n_public_key(&self) -> &PublicKey {
        &self.n_of_n_public_key
    }
    fn n_of_n_taproot_public_key(&self) -> &XOnlyPublicKey {
        &self.n_of_n_taproot_public_key
    }
}

impl OperatorContext {
    pub fn new(network: Network, operator_secret: &str, n_of_n_public_keys: &[PublicKey]) -> Self {
        let (secp, keypair, public_key) = generate_keys_from_secret(network, operator_secret);
        let (n_of_n_public_key, n_of_n_taproot_public_key) =
            generate_n_of_n_public_key(n_of_n_public_keys);

        OperatorContext {
            network,
            secp,

            operator_keypair: keypair,
            operator_public_key: public_key,
            operator_taproot_public_key: XOnlyPublicKey::from(public_key),

            n_of_n_public_keys: n_of_n_public_keys.to_vec(),
            n_of_n_public_key,
            n_of_n_taproot_public_key,
        }
    }
}
