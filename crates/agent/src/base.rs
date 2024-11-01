use secp256k1::Keypair;

#[derive(Debug, Clone)]
pub struct Agent {
    keypair: Keypair,
}
