use std::str::FromStr;

use async_trait::async_trait;
use bitcoin::{consensus, Txid};
use rkyv::{from_bytes, rancor::Error as RkyvError, to_bytes};
use secp256k1::schnorr::Signature;
use sqlx::SqlitePool;
use strata_bridge_primitives::{scripts::wots, types::OperatorIdx};

use crate::public::PublicDb;

#[derive(Debug, Clone)]
pub struct SqliteDb {
    pool: SqlitePool,
}

impl SqliteDb {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PublicDb for SqliteDb {
    async fn get_wots_public_keys(&self, operator_id: u32, deposit_txid: Txid) -> wots::PublicKeys {
        let deposit_txid = consensus::encode::serialize_hex(&deposit_txid);

        let record = sqlx::query!(
            "SELECT public_keys FROM wots_public_keys WHERE operator_id = ? AND deposit_txid = ?",
            operator_id,
            deposit_txid
        )
        .fetch_one(&self.pool)
        .await
        .expect(
            "wots public keys should be present in database for given operator and deposit txid",
        );

        from_bytes::<wots::PublicKeys, RkyvError>(&record.public_keys)
            .expect("Failed to deserialize wots public keys")
    }

    async fn set_wots_public_keys(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        public_keys: &wots::PublicKeys,
    ) {
        let deposit_txid = consensus::encode::serialize_hex(&deposit_txid);

        let serialized_keys =
            to_bytes::<RkyvError>(public_keys).expect("Failed to serialize wots public keys");

        let serialized_keys = serialized_keys.as_slice();
        sqlx::query!(
            "INSERT OR REPLACE INTO wots_public_keys (operator_id, deposit_txid, public_keys) VALUES (?, ?, ?)",
            operator_id,
            deposit_txid,
            serialized_keys
        )
        .execute(&self.pool)
        .await
        .expect("wots public keys should be insertable into database");
    }

    async fn get_wots_signatures(&self, operator_id: u32, deposit_txid: Txid) -> wots::Signatures {
        let deposit_txid = consensus::encode::serialize_hex(&deposit_txid);

        let record = sqlx::query!(
            "SELECT signatures FROM wots_signatures WHERE operator_id = ? AND deposit_txid = ?",
            operator_id,
            deposit_txid
        )
        .fetch_one(&self.pool)
        .await
        .expect(
            "wots signatures should be present in database for given operator and deposit txid",
        );

        from_bytes::<wots::Signatures, RkyvError>(&record.signatures)
            .expect("Failed to deserialize wots signatures")
    }

    async fn set_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        signatures: &wots::Signatures,
    ) {
        let deposit_txid = consensus::encode::serialize_hex(&deposit_txid);

        let serialized_signatures =
            to_bytes::<RkyvError>(signatures).expect("Failed to serialize wots signatures");

        let serialized_signatures = serialized_signatures.as_slice();
        sqlx::query!(
            "INSERT OR REPLACE INTO wots_signatures (operator_id, deposit_txid, signatures) VALUES (?, ?, ?)",
            operator_id,
            deposit_txid,
            serialized_signatures
        )
        .execute(&self.pool)
        .await
        .expect("wots signatures should be insertable into database");
    }

    async fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> Signature {
        let txid = consensus::encode::serialize_hex(&txid);

        let record = sqlx::query!(
            "SELECT signature FROM signatures WHERE operator_id = ? AND txid = ? AND input_index = ?",
            operator_idx,
            txid,
            input_index
        )
        .fetch_one(&self.pool)
        .await
        .expect("signature should be present in database for given operator, txid, and input index");

        Signature::from_str(&record.signature)
            .expect("signature should be a valid hex-encoded value")
    }

    async fn set_signature(
        &self,
        operator_id: u32,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) {
        let _txid = consensus::encode::serialize_hex(&txid);
        let signature = signature.to_string();

        sqlx::query!(
            "INSERT OR REPLACE INTO signatures (signature, operator_id, txid, input_index) VALUES (?, ?, ?, ?)",
            signature,
            operator_id,
            true,
            input_index
        ).execute(&self.pool).await.expect("signature should be insertable into the database");
    }

    async fn register_claim_txid(
        &self,
        claim_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) {
        let claim_txid = consensus::encode::serialize_hex(&claim_txid);
        let deposit_txid = consensus::encode::serialize_hex(&deposit_txid);

        sqlx::query!(
            "INSERT OR REPLACE INTO claim_txid_to_operator_index_and_deposit_txid (claim_txid, operator_id, deposit_txid) VALUES (?, ?, ?)",
            claim_txid,
            operator_idx,
            deposit_txid
        )
        .execute(&self.pool)
        .await
        .expect("claim txid should be insertable into database");
    }

    async fn get_operator_and_deposit_for_claim(
        &self,
        claim_txid: &Txid,
    ) -> Option<(OperatorIdx, Txid)> {
        let claim_txid = consensus::encode::serialize_hex(claim_txid);

        let record = sqlx::query!(
            "SELECT operator_id, deposit_txid FROM claim_txid_to_operator_index_and_deposit_txid WHERE claim_txid = ?",
            claim_txid
        )
        .fetch_optional(&self.pool)
        .await
        .expect("database query for claim txid should succeed");

        record.map(|rec| {
            let deposit_txid = consensus::encode::deserialize_hex(&rec.deposit_txid)
                .expect("deposit txid in db should be valid");
            (rec.operator_id as OperatorIdx, deposit_txid)
        })
    }

    async fn register_post_assert_txid(
        &self,
        post_assert_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) {
        let post_assert_txid = consensus::encode::serialize_hex(&post_assert_txid);
        let deposit_txid = consensus::encode::serialize_hex(&deposit_txid);

        sqlx::query!(
            "INSERT OR REPLACE INTO post_assert_txid_to_operator_index_and_deposit_txid (post_assert_txid, operator_id, deposit_txid) VALUES (?, ?, ?)",
            post_assert_txid,
            operator_idx,
            deposit_txid
        )
        .execute(&self.pool)
        .await
        .expect("post assert txid should be insertable into database");
    }

    async fn get_operator_and_deposit_for_post_assert(
        &self,
        post_assert_txid: &Txid,
    ) -> Option<(OperatorIdx, Txid)> {
        let post_assert_txid = consensus::encode::serialize_hex(post_assert_txid);

        let record = sqlx::query!(
            "SELECT operator_id, deposit_txid FROM post_assert_txid_to_operator_index_and_deposit_txid WHERE post_assert_txid = ?",
            post_assert_txid
        )
        .fetch_optional(&self.pool)
        .await
        .expect("database query for post assert txid should succeed");

        record.map(|rec| {
            let deposit_txid = consensus::encode::deserialize_hex(&rec.deposit_txid)
                .expect("deposit txid in db should be valid");
            (rec.operator_id as OperatorIdx, deposit_txid)
        })
    }

    async fn register_assert_data_txids(
        &self,
        assert_data_txids: [Txid; 7],
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) {
        let deposit_txid = consensus::encode::serialize_hex(&deposit_txid);

        for txid in assert_data_txids.iter() {
            let txid = consensus::encode::serialize_hex(txid);

            sqlx::query!(
                "INSERT OR REPLACE INTO assert_data_txid_to_operator_and_deposit (assert_data_txid, operator_id, deposit_txid) VALUES (?, ?, ?)",
                txid,
                operator_idx,
                deposit_txid
            )
            .execute(&self.pool)
            .await
            .expect("assert data txid should be insertable into database");
        }
    }

    async fn get_operator_and_deposit_for_assert_data(
        &self,
        assert_data_txid: &Txid,
    ) -> Option<(OperatorIdx, Txid)> {
        let assert_data_txid = consensus::encode::serialize_hex(assert_data_txid);

        let record = sqlx::query!(
            "SELECT operator_id, deposit_txid FROM assert_data_txid_to_operator_and_deposit WHERE assert_data_txid = ?",
            assert_data_txid
        )
        .fetch_optional(&self.pool)
        .await
        .expect("database query for assert data txid should succeed");

        record.map(|rec| {
            let deposit_txid = consensus::encode::deserialize_hex(&rec.deposit_txid)
                .expect("deposit txid in db should be valid");
            (rec.operator_id as OperatorIdx, deposit_txid)
        })
    }

    async fn register_pre_assert_txid(
        &self,
        pre_assert_data_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) {
        let pre_assert_data_txid = consensus::encode::serialize_hex(&pre_assert_data_txid);
        let deposit_txid = consensus::encode::serialize_hex(&deposit_txid);

        sqlx::query!(
            "INSERT OR REPLACE INTO pre_assert_txid_to_operator_and_deposit (pre_assert_data_txid, operator_id, deposit_txid) VALUES (?, ?, ?)",
            pre_assert_data_txid,
            operator_idx,
            deposit_txid
        )
        .execute(&self.pool)
        .await
        .expect("pre assert txid should be insertable into database");
    }

    async fn get_operator_and_deposit_for_pre_assert(
        &self,
        pre_assert_data_txid: &Txid,
    ) -> Option<(OperatorIdx, Txid)> {
        let pre_assert_data_txid = consensus::encode::serialize_hex(pre_assert_data_txid);

        let record = sqlx::query!(
            "SELECT operator_id, deposit_txid FROM pre_assert_txid_to_operator_and_deposit WHERE pre_assert_data_txid = ?",
            pre_assert_data_txid
        )
        .fetch_optional(&self.pool)
        .await
        .expect("database query for pre assert txid should succeed");

        record.map(|rec| {
            let deposit_txid = consensus::encode::deserialize_hex(&rec.deposit_txid)
                .expect("deposit txid in db should be valid");
            (rec.operator_id as OperatorIdx, deposit_txid)
        })
    }
}
