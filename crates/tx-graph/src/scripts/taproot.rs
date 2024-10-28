//! Provides some common, standalone utilities and wrappers over [`bitcoin`] to create
//! scripts, addresses and transactions.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context};
use bitcoin::{
    key::UntweakedPublicKey,
    psbt::Input,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, Witness,
};
use secp256k1::SECP256K1;

use crate::constants::UNSPENDABLE_INTERNAL_KEY;

/// Different spending paths for a taproot.
///
/// It can be a key path spend, a script path spend or both.
#[derive(Debug, Clone)]
pub enum SpendPath<'path> {
    /// Key path spend that requires just an untweaked (internal) public key.
    KeySpend {
        /// The internal key used to construct the taproot.
        internal_key: UntweakedPublicKey,
    },
    /// Script path spend that only allows spending via scripts in the taproot tree, with the
    /// internal key being the [`static@UNSPENDABLE_INTERNAL_KEY`].
    ScriptSpend {
        /// The scripts that live in the leaves of the taproot tree.
        scripts: &'path [ScriptBuf],
    },
    /// Allows spending via either a provided internal key or via scripts in the taproot tree.
    Both {
        /// The internal key used to construct the taproot.
        internal_key: UntweakedPublicKey,

        /// The scripts that live in the leaves of the taproot tree.
        scripts: &'path [ScriptBuf],
    },
}

/// Create a taproot address for the given `scripts` and `internal_key`.
///
/// # Errors
///
/// If the scripts is empty in [`SpendPath::ScriptSpend`].
pub fn create_taproot_addr<'creator>(
    network: &'creator Network,
    spend_path: SpendPath<'creator>,
) -> anyhow::Result<(Address, TaprootSpendInfo)> {
    match spend_path {
        SpendPath::KeySpend { internal_key } => build_taptree(internal_key, *network, &[]),
        SpendPath::ScriptSpend { scripts } => {
            if scripts.is_empty() {
                bail!("empty tapscript");
            }

            build_taptree(*UNSPENDABLE_INTERNAL_KEY, *network, scripts)
        }
        SpendPath::Both {
            internal_key,
            scripts,
        } => build_taptree(internal_key, *network, scripts),
    }
}

/// Constructs the taptree for the given scripts.
///
/// A taptree is a merkle tree made up of various scripts. Each script is a leaf in the merkle tree.
/// If the number of scripts is a power of 2, all the scripts lie at the deepest level (depth = n)
/// in the tree. If the number is not a power of 2, there are some scripts that will exist at the
/// penultimate level (depth = n - 1).
///
/// This function adds the scripts to the taptree after it computes the depth for each script.
fn build_taptree(
    internal_key: UntweakedPublicKey,
    network: Network,
    scripts: &[ScriptBuf],
) -> anyhow::Result<(Address, TaprootSpendInfo)> {
    let mut taproot_builder = TaprootBuilder::new();

    let num_scripts = scripts.len();

    // Compute the height of the taptree required to fit in all the scripts.
    // If the script count <= 1, the depth should be 0. Otherwise, we compute the log. For example,
    // 2 scripts can fit in a height of 1 (0 being the root node). 4 can fit in a height of 2 and so
    // on.
    let max_depth = if num_scripts > 1 {
        (num_scripts - 1).ilog2() + 1
    } else {
        0
    };

    // Compute the maximum number of scripts that can fit in the taproot. For example, at a depth of
    // 3, we can fit 8 scripts.
    //              [Root Hash]
    //              /          \
    //             /            \
    //        [Hash 0]           [Hash 1]
    //       /        \          /      \
    //      /          \        /        \
    // [Hash 00]   [Hash 01] [Hash 10] [Hash 11]
    //   /   \       /   \     /   \     /   \
    // S0    S1    S2    S3  S4    S5   S6    S7
    let max_num_scripts = 2usize.pow(max_depth);

    // But we may be given say 5 scripts, in which case the tree would not be fully complete and we
    // need to add leaves at a shallower point in a way that minimizes the overall height (to reduce
    // the size of the merkle proof). So, we need to compute how many such scripts exist and add
    // these, at the appropriate depth.
    //
    //              [Root Hash]
    //              /          \
    //             /            \
    //        [Hash 0]          [Hash 1]
    //       /        \          /    \
    //      /          \        /      \
    // [Hash 00]        S2    S4        S5  ---> penultimate depth has 3 scripts
    //   /   \
    // S0    S1   ---------> max depth has 2 scripts
    let num_penultimate_scripts = max_num_scripts.saturating_sub(num_scripts);
    let num_deepest_scripts = num_scripts.saturating_sub(num_penultimate_scripts);

    for (script_idx, script) in scripts.iter().enumerate() {
        let depth = if script_idx < num_deepest_scripts {
            max_depth as u8
        } else {
            // if the deepest node is not filled, use the node at the upper level instead
            (max_depth - 1) as u8
        };

        taproot_builder = taproot_builder
            .add_leaf(depth, script.clone())
            .context("add leaf")?;
    }

    let spend_info = taproot_builder
        .finalize(SECP256K1, internal_key)
        .map_err(|_e| anyhow!("taproot finalization".to_string()))?;

    let merkle_root = spend_info.merkle_root();

    Ok((
        Address::p2tr(SECP256K1, internal_key, merkle_root, network),
        spend_info,
    ))
}

pub fn finalize_input<D>(input: &mut Input, witnesses: impl IntoIterator<Item = D>) -> &Input
where
    D: AsRef<[u8]>,
{
    let mut witness_stack = Witness::new();

    witnesses
        .into_iter()
        .for_each(|witness| witness_stack.push(witness));

    // Finalize the psbt as per <https://github.com/rust-bitcoin/rust-bitcoin/blob/bitcoin-0.32.1/bitcoin/examples/taproot-psbt.rs#L315-L327>
    // NOTE: their ecdsa example states that we should use `miniscript` to finalize
    // PSBTs in production but they don't mention this for taproot.

    // Set final witness
    input.final_script_witness = Some(witness_stack);

    // And clear all other fields as per the spec
    input.partial_sigs = BTreeMap::new();
    input.sighash_type = None;
    input.redeem_script = None;
    input.witness_script = None;
    input.bip32_derivation = BTreeMap::new();

    input
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        key::Keypair,
        secp256k1::{rand, SecretKey},
    };
    use rand::rngs::OsRng;
    use secp256k1::XOnlyPublicKey;

    use super::*;

    #[test]
    fn test_create_taproot_addr() {
        // create a bunch of dummy scripts to add to the taptree
        let max_scripts = 10;
        let scripts: Vec<ScriptBuf> = vec![ScriptBuf::from_bytes(vec![2u8; 32]); max_scripts];

        let network = Network::Regtest;

        let spend_path = SpendPath::ScriptSpend {
            scripts: &scripts[0..1],
        };
        assert!(
            create_taproot_addr(&network, spend_path).is_ok(),
            "should work if the number of scripts is exactly 1 i.e., only root node exists"
        );

        let spend_path = SpendPath::ScriptSpend {
            scripts: &scripts[0..4],
        };
        assert!(
            create_taproot_addr(&network, spend_path).is_ok(),
            "should work if the number of scripts is an exact power of 2"
        );

        let spend_path = SpendPath::ScriptSpend {
            scripts: &scripts[..],
        };
        assert!(
            create_taproot_addr(&network, spend_path).is_ok(),
            "should work if the number of scripts is not an exact power of 2"
        );

        let secret_key = SecretKey::new(&mut OsRng);
        let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
        let (x_only_public_key, _) = XOnlyPublicKey::from_keypair(&keypair);

        let spend_path = SpendPath::KeySpend {
            internal_key: x_only_public_key,
        };
        assert!(
            create_taproot_addr(&network, spend_path).is_ok(),
            "should support empty scripts with some internal key"
        );

        let spend_path = SpendPath::Both {
            internal_key: x_only_public_key,
            scripts: &scripts[..3],
        };
        assert!(
            create_taproot_addr(&network, spend_path).is_ok(),
            "should support scripts with some internal key"
        );
    }
}
