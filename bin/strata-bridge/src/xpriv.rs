//! Descriptor parsing utilities.

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};

// TODO: move some of these into a keyderiv crate
const DERIV_BASE_IDX: u32 = 56;
const DERIV_OP_IDX: u32 = 20;
const DERIV_OP_SIGNING_IDX: u32 = 100;
const DERIV_OP_WALLET_IDX: u32 = 101;

/// Derives the signing and wallet xprivs for a Strata operator.
pub(crate) fn derive_op_purpose_xprivs(root: &Xpriv) -> anyhow::Result<(Xpriv, Xpriv)> {
    let signing_path = DerivationPath::master().extend([
        ChildNumber::from_hardened_idx(DERIV_BASE_IDX).unwrap(),
        ChildNumber::from_hardened_idx(DERIV_OP_IDX).unwrap(),
        ChildNumber::from_normal_idx(DERIV_OP_SIGNING_IDX).unwrap(),
    ]);

    let wallet_path = DerivationPath::master().extend([
        ChildNumber::from_hardened_idx(DERIV_BASE_IDX).unwrap(),
        ChildNumber::from_hardened_idx(DERIV_OP_IDX).unwrap(),
        ChildNumber::from_normal_idx(DERIV_OP_WALLET_IDX).unwrap(),
    ]);

    let signing_xpriv = root.derive_priv(bitcoin::secp256k1::SECP256K1, &signing_path)?;
    let wallet_xpriv = root.derive_priv(bitcoin::secp256k1::SECP256K1, &wallet_path)?;

    Ok((signing_xpriv, wallet_xpriv))
}
