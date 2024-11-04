//! Provides types/traits associated with the withdrawal process.

use anyhow::bail;
use bitcoin::{key::TapTweak, Address, Amount, FeeRate, OutPoint, Psbt, Transaction, TxOut};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

use crate::{
    build_context::{BuildContext, TxKind},
    params::prelude::{BRIDGE_DENOMINATION, MIN_RELAY_FEE, OPERATOR_FEE},
    scripts::{
        prelude::{
            anyone_can_spend_txout, create_taproot_addr, create_tx, create_tx_ins, create_tx_outs,
            SpendPath,
        },
        taproot::TaprootWitness,
    },
    types::{BitcoinBlockHeight, OperatorIdx, TxSigningData},
};

/// Details for a withdrawal info assigned to an operator.
///
/// It has all the information required to create a transaction for fulfilling a user's withdrawal
/// request and pay operator fees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalInfo {
    /// The [`OutPoint`] of the UTXO in the Bridge Address that is to be used to service the
    /// withdrawal request.
    deposit_outpoint: OutPoint,

    /// The x-only public key of the user used to create the taproot address that the user can
    /// spend from.
    user_pk: XOnlyPublicKey,

    /// The index of the operator that is assigned the withdrawal.
    assigned_operator_idx: OperatorIdx,

    /// The bitcoin block height before which the withdrawal has to be processed.
    ///
    /// Any withdrawal request whose `exec_deadline` is before the current bitcoin block height is
    /// considered stale and must be ignored.
    exec_deadline: BitcoinBlockHeight,
}

impl TxKind for WithdrawalInfo {
    fn construct_signing_data<C: BuildContext>(
        &self,
        build_context: &C,
    ) -> anyhow::Result<TxSigningData> {
        let prevout = self.create_prevout(build_context)?;
        let unsigned_tx = self.create_unsigned_tx(build_context, prevout.value)?;

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

        psbt.inputs
            .get_mut(0)
            .expect("withdrawal tx is guaranteed to have one UTXO -- the deposit")
            .witness_utxo = Some(prevout);

        Ok(TxSigningData {
            psbt,
            spend_path: TaprootWitness::Key,
        })
    }
}

impl WithdrawalInfo {
    /// Create a new withdrawal request.
    pub fn new(
        deposit_outpoint: OutPoint,
        user_pk: XOnlyPublicKey,
        assigned_operator_idx: OperatorIdx,
        exec_deadline: BitcoinBlockHeight,
    ) -> Self {
        Self {
            deposit_outpoint,
            user_pk,
            assigned_operator_idx,
            exec_deadline,
        }
    }

    /// Get the outpoint of the deposit UTXO that this withdrawal spends.
    pub fn deposit_outpoint(&self) -> OutPoint {
        self.deposit_outpoint
    }

    /// Get the assignee for this withdrawal request.
    pub fn assigned_operator_idx(&self) -> OperatorIdx {
        self.assigned_operator_idx
    }

    /// Get the recipient's [`XOnlyPk`].
    pub fn user_pk(&self) -> XOnlyPublicKey {
        self.user_pk
    }

    /// Get the execution deadline for the request.
    pub fn exec_deadline(&self) -> u64 {
        self.exec_deadline
    }

    /// Check if the passed bitcoin block height is greater than the deadline for the withdrawal.
    pub fn is_expired_at(&self, block_height: BitcoinBlockHeight) -> bool {
        self.exec_deadline < block_height
    }

    fn create_prevout<T: BuildContext>(&self, build_context: &T) -> anyhow::Result<TxOut> {
        // We are not committing to any script path as the internal key should already be
        // randomized due to MuSig2 aggregation. See: <https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-23>
        let spend_path = SpendPath::KeySpend {
            internal_key: build_context.aggregated_pubkey(),
        };

        let (bridge_addr, _) = create_taproot_addr(&build_context.network(), spend_path)?;

        Ok(TxOut {
            value: BRIDGE_DENOMINATION,
            script_pubkey: bridge_addr.script_pubkey(),
        })
    }

    fn create_unsigned_tx<T: BuildContext>(
        &self,
        build_context: &T,
        total_amount: Amount,
    ) -> anyhow::Result<Transaction> {
        let tx_ins = create_tx_ins([self.deposit_outpoint]);

        // create the output for the operator fees
        let pubkey_table = build_context.pubkey_table();
        let assigned_operator_pubkey = pubkey_table.0.get(&self.assigned_operator_idx);

        if assigned_operator_pubkey.is_none() {
            bail!("assignee not part of group")
        }

        let x_only_pubkey = assigned_operator_pubkey
            .expect("should be present")
            .x_only_public_key()
            .0;
        let spend_path = SpendPath::KeySpend {
            internal_key: x_only_pubkey,
        };

        let (operator_addr, _) = create_taproot_addr(&build_context.network(), spend_path)?;

        // create the `anyone can spend` output for CPFP
        let anyone_can_spend_out = anyone_can_spend_txout();

        // create the output that pays to the user
        let user_addr = Address::p2tr_tweaked(
            self.user_pk.dangerous_assume_tweaked(),
            build_context.network(),
        );
        let user_script_pubkey = user_addr.script_pubkey();

        // This fee pays for the entire transaction.
        // In the current configuration of `10` for `MIN_RELAY_FEE`, the total transaction fee
        // computes to ~5.5 SAT (run integration tests with `RUST_LOG=warn` to verify).
        let fee_rate = FeeRate::from_sat_per_vb(MIN_RELAY_FEE.to_sat())
            .expect("MIN_RELAY_FEE should be set correctly");
        let tx_fee = user_script_pubkey.minimal_non_dust_custom(fee_rate);

        let net_amount = total_amount - OPERATOR_FEE - anyone_can_spend_out.value - tx_fee;

        let tx_outs = create_tx_outs([
            (user_script_pubkey, net_amount),              // payout to the user
            (operator_addr.script_pubkey(), OPERATOR_FEE), // operator fees
            // anyone can spend for CPFP
            (
                anyone_can_spend_out.script_pubkey,
                anyone_can_spend_out.value,
            ),
        ]);

        let unsigned_tx = create_tx(tx_ins, tx_outs);

        Ok(unsigned_tx)
    }
}
