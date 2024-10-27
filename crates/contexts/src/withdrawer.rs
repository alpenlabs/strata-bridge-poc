use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::All,
    Network, PublicKey, XOnlyPublicKey,
};

use crate::base::{generate_keys_from_secret, generate_n_of_n_public_key, BaseContext};

/// Holds all the information required to implement the [`BaseContext`] along with extra
/// information required to identify itself (such as the `Withdrawer`'s own keypair and public
/// keys).
// NOTE: since the withdrawal happens on the sidechain (in this case, `Ethereum`), was expecting
// the context to hold some `EVM`-specific information but this only holds bitcoin-specific
// information which also makes sense since that is all that the bridge cares about.
#[derive(Debug)]
pub struct WithdrawerContext {
    pub network: Network,
    pub secp: Secp256k1<All>,

    pub withdrawer_keypair: Keypair,
    pub withdrawer_public_key: PublicKey,
    pub withdrawer_taproot_public_key: XOnlyPublicKey,

    pub n_of_n_public_keys: Vec<PublicKey>,
    pub n_of_n_public_key: PublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
}

impl BaseContext for WithdrawerContext {
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

/// NOTE: this should at least be a macro at this point.
impl WithdrawerContext {
    pub fn new(
        network: Network,
        withdrawer_secret: &str,
        n_of_n_public_keys: &[PublicKey],
    ) -> Self {
        let (secp, keypair, public_key) = generate_keys_from_secret(network, withdrawer_secret);
        let (n_of_n_public_key, n_of_n_taproot_public_key) =
            generate_n_of_n_public_key(n_of_n_public_keys);

        WithdrawerContext {
            network,
            secp,

            withdrawer_keypair: keypair,
            withdrawer_public_key: public_key,
            withdrawer_taproot_public_key: XOnlyPublicKey::from(public_key),

            n_of_n_public_keys: n_of_n_public_keys.to_vec(),
            n_of_n_public_key,
            n_of_n_taproot_public_key,
        }
    }
}
