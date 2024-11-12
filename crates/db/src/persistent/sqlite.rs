use std::{
    collections::{BTreeMap, HashSet},
    str::FromStr,
};

use async_trait::async_trait;
use bitcoin::{consensus, hex::DisplayHex, Amount, Network, OutPoint, Transaction, TxOut, Txid};
use musig2::{BinaryEncoding, PartialSignature, PubNonce, SecNonce};
use rkyv::{from_bytes, rancor::Error as RkyvError, to_bytes};
use secp256k1::schnorr::Signature;
use sqlx::SqlitePool;
use strata_bridge_primitives::{
    bitcoin::BitcoinAddress, duties::BridgeDutyStatus, scripts::wots, types::OperatorIdx,
};
use tracing::trace;

use crate::{
    operator::{KickoffInfo, MsgHashAndOpIdToSigMap, OperatorDb},
    public::PublicDb,
    tracker::{BitcoinBlockTrackerDb, DutyTrackerDb},
};

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
        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");
        sqlx::query!(
            "INSERT OR REPLACE INTO wots_public_keys (operator_id, deposit_txid, public_keys) VALUES (?, ?, ?)",
            operator_id,
            deposit_txid,
            serialized_keys
        )
        .execute(&mut *tx)
        .await
        .expect("wots public keys should be insertable into database");

        tx.commit()
            .await
            .expect("should be able to commit wots public keys");
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
        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start transaction");
        sqlx::query!(
            "INSERT OR REPLACE INTO wots_signatures (operator_id, deposit_txid, signatures) VALUES (?, ?, ?)",
            operator_id,
            deposit_txid,
            serialized_signatures
        )
        .execute(&mut *tx)
        .await
        .expect("wots signatures should be insertable into database");

        tx.commit()
            .await
            .expect("should be abel to commit wots signatures");
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
        let txid = consensus::encode::serialize_hex(&txid);
        let signature = signature.to_string();

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start transaction");
        sqlx::query!(
            "INSERT OR REPLACE INTO signatures (signature, operator_id, txid, input_index) VALUES (?, ?, ?, ?)",
            signature,
            operator_id,
            txid,
            input_index
        ).execute(&mut *tx).await.expect("signature should be insertable into the database");

        tx.commit()
            .await
            .expect("should be able to commit signature");
    }

    async fn register_claim_txid(
        &self,
        claim_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) {
        let claim_txid = consensus::encode::serialize_hex(&claim_txid);
        let deposit_txid = consensus::encode::serialize_hex(&deposit_txid);

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start transaction");
        sqlx::query!(
            "INSERT OR REPLACE INTO claim_txid_to_operator_index_and_deposit_txid (claim_txid, operator_id, deposit_txid) VALUES (?, ?, ?)",
            claim_txid,
            operator_idx,
            deposit_txid
        )
        .execute(&mut *tx)
        .await
        .expect("claim txid should be insertable into database");

        tx.commit()
            .await
            .expect("should be able to commit claim txid");
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

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");
        sqlx::query!(
            "INSERT OR REPLACE INTO post_assert_txid_to_operator_index_and_deposit_txid (post_assert_txid, operator_id, deposit_txid) VALUES (?, ?, ?)",
            post_assert_txid,
            operator_idx,
            deposit_txid
        )
        .execute(&mut *tx)
        .await
        .expect("post assert txid should be insertable into database");

        tx.commit()
            .await
            .expect("should be able to commit post assert txid");
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

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");
        for txid in assert_data_txids.iter() {
            let txid = consensus::encode::serialize_hex(txid);

            sqlx::query!(
                "INSERT OR REPLACE INTO assert_data_txid_to_operator_and_deposit (assert_data_txid, operator_id, deposit_txid) VALUES (?, ?, ?)",
                txid,
                operator_idx,
                deposit_txid
            )
            .execute(&mut *tx)
            .await
            .expect("assert data txid should be insertable into database");
        }

        tx.commit()
            .await
            .expect("should be able to commit assert data txids");
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

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");
        sqlx::query!(
            "INSERT OR REPLACE INTO pre_assert_txid_to_operator_and_deposit (pre_assert_data_txid, operator_id, deposit_txid) VALUES (?, ?, ?)",
            pre_assert_data_txid,
            operator_idx,
            deposit_txid
        )
        .execute(&mut *tx)
        .await
        .expect("pre assert txid should be insertable into database");

        tx.commit()
            .await
            .expect("should be able to commit pre-assert txid");
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

#[async_trait]
impl OperatorDb for SqliteDb {
    async fn add_pubnonce(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        pubnonce: PubNonce,
    ) {
        let txid = consensus::encode::serialize_hex(&txid);
        let pubnonce = pubnonce.to_string();

        trace!(action = "adding pubnonce to db", %txid, %operator_idx);

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");
        sqlx::query!(
            "INSERT OR REPLACE INTO collected_pubnonces (txid, input_index, operator_id, pubnonce) VALUES (?, ?, ?, ?)",
            txid,
            input_index,
            operator_idx,
            pubnonce
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to insert pubnonce into the db");

        tx.commit()
            .await
            .expect("should be able to commit pubnonce");

        trace!(event = "added pubnonce to db", %txid, %operator_idx);
    }

    async fn collected_pubnonces(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> Option<BTreeMap<OperatorIdx, PubNonce>> {
        let txid = consensus::encode::serialize_hex(&txid);
        let results = sqlx::query!(
            "SELECT operator_id, pubnonce FROM collected_pubnonces WHERE txid = ? AND input_index = ?",
            txid,
            input_index
        )
        .fetch_all(&self.pool)
        .await
        .expect("should be able to fetch pubnonce from the db");

        if results.is_empty() {
            None
        } else {
            Some(
                results
                    .into_iter()
                    .map(|record| {
                        (
                            record.operator_id as OperatorIdx,
                            PubNonce::from_str(&record.pubnonce)
                                .expect("pubnonce format should be valid"),
                        )
                    })
                    .collect(),
            )
        }
    }

    async fn add_secnonce(&self, txid: Txid, input_index: u32, secnonce: SecNonce) {
        let txid = consensus::encode::serialize_hex(&txid);
        let secnonce = secnonce.to_bytes().to_vec();

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");
        sqlx::query!(
            "INSERT OR REPLACE INTO sec_nonces (txid, input_index, sec_nonce) VALUES (?, ?, ?)",
            txid,
            input_index,
            secnonce,
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to add secnonce to db");

        tx.commit()
            .await
            .expect("should be able to commit secnonce into the db")
    }

    async fn get_secnonce(&self, txid: Txid, input_index: u32) -> Option<SecNonce> {
        let txid = consensus::encode::serialize_hex(&txid);

        let result = sqlx::query!(
            "SELECT sec_nonce FROM sec_nonces WHERE txid = ? AND input_index = ?",
            txid,
            input_index
        )
        .fetch_optional(&self.pool)
        .await
        .expect("should be able to fetch secnonce from the db");

        result
            .map(|record| SecNonce::from_bytes(&record.sec_nonce).expect("Invalid SecNonce format"))
    }

    // Add or update a message hash and associated partial signature
    async fn add_message_hash_and_signature(
        &self,
        txid: Txid,
        input_index: u32,
        message_sighash: Vec<u8>,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    ) {
        let txid_str = consensus::encode::serialize_hex(&txid);
        let partial_signature = signature.serialize().to_lower_hex_string();

        trace!(msg = "adding own partial signature", %txid_str, %input_index, %operator_idx, %partial_signature);

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");

        // Insert or ignore into `collected_messages` to avoid overwriting `msg_hash`
        sqlx::query!(
            "INSERT OR IGNORE INTO collected_messages (txid, input_index, msg_hash) VALUES (?, ?, ?)",
            txid_str,
            input_index,
            message_sighash
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to insert or ignore message entry");

        // Insert or replace the partial signature in `collected_signatures`
        sqlx::query!(
            "INSERT OR REPLACE INTO collected_signatures (txid, input_index, operator_id, partial_signature)
            VALUES (?, ?, ?, ?)",
            txid_str,
            input_index,
            operator_idx,
            partial_signature
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to insert or replace partial signature");

        tx.commit()
            .await
            .expect("should be able to commit message hash and signature");
    }

    // Add or update a partial signature for an existing `(txid, input_index, operator_id)`
    async fn add_partial_signature(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    ) {
        let txid_str = consensus::encode::serialize_hex(&txid);
        let partial_signature = signature.serialize().to_lower_hex_string();

        trace!(msg = "adding collected partial signature", %txid_str, %input_index, %operator_idx, %partial_signature);

        sqlx::query!(
            "INSERT OR REPLACE INTO collected_signatures (txid, input_index, operator_id, partial_signature)
            VALUES (?, ?, ?, ?)",
            txid_str,
            input_index,
            operator_idx,
            partial_signature
        )
        .execute(&self.pool)
        .await
        .expect("should be able to insert or replace partial signature");
    }

    // Fetch all collected signatures for a given `(txid, input_index)`, along with the message hash
    async fn collected_signatures_per_msg(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> Option<MsgHashAndOpIdToSigMap> {
        // Convert `txid` to a hex string for querying
        let txid_str = consensus::encode::serialize_hex(&txid);
        trace!(msg = "getting collected signatures", %txid_str, %input_index);

        // Fetch `msg_hash` from `collected_messages` and associated signatures from
        // `collected_signatures`
        let results = sqlx::query!(
            "SELECT m.msg_hash, s.operator_id, s.partial_signature
            FROM collected_messages m
            JOIN collected_signatures s ON m.txid = s.txid AND m.input_index = s.input_index
            WHERE m.txid = ? AND m.input_index = ?",
            txid_str,
            input_index
        )
        .fetch_all(&self.pool)
        .await
        .expect("Failed to fetch collected signatures");

        // Return None if no results are found
        if results.is_empty() {
            None
        } else {
            // Use the first record's `msg_hash` and initialize the BTreeMap for signatures
            let msg_hash = results[0].msg_hash.clone();
            let mut op_id_to_sig_map = BTreeMap::new();

            for record in results {
                let operator_id = record.operator_id as OperatorIdx;
                let signature = PartialSignature::from_str(&record.partial_signature)
                    .expect("Invalid signature format");

                let signature_str = signature.serialize().to_lower_hex_string();
                trace!(action = "getting partial signature", %signature_str, %txid, %input_index, %operator_id);

                op_id_to_sig_map.insert(operator_id, signature);
            }

            Some((msg_hash, op_id_to_sig_map))
        }
    }

    async fn add_outpoint(&self, outpoint: OutPoint) -> bool {
        let txid = consensus::encode::serialize_hex(&outpoint.txid);

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");
        let result = sqlx::query!(
            "INSERT OR IGNORE INTO selected_outpoints (txid, vout) VALUES (?, ?)",
            txid,
            outpoint.vout,
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to insert outpoint");

        tx.commit()
            .await
            .expect("should be able to commit outpoint");

        result.rows_affected() > 0
    }

    async fn selected_outpoints(&self) -> HashSet<OutPoint> {
        let results = sqlx::query!("SELECT txid, vout FROM selected_outpoints")
            .fetch_all(&self.pool)
            .await
            .expect("Failed to fetch selected outpoints");

        results
            .into_iter()
            .map(|record| OutPoint {
                txid: consensus::encode::deserialize_hex(&record.txid)
                    .expect("should be able to deserialize outpoint txid"),
                vout: record.vout as u32,
            })
            .collect()
    }

    async fn add_kickoff_info(&self, deposit_txid: Txid, kickoff_info: KickoffInfo) {
        let deposit_txid = consensus::encode::serialize_hex(&deposit_txid);
        let change_address = kickoff_info.change_address.address().to_string();
        let change_address_network = kickoff_info.change_address.network().to_string();
        let change_amount = kickoff_info.change_amt.to_sat() as i64;

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");

        sqlx::query!(
            "INSERT OR REPLACE INTO kickoff_info (txid, change_address, change_address_network, change_amount) VALUES (?, ?, ?, ?)",
            deposit_txid,
            change_address,
            change_address_network,
            change_amount,
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to insert kickoff info");

        for input in kickoff_info.funding_inputs {
            let input_txid = consensus::encode::serialize_hex(&input.txid);
            sqlx::query!(
                "INSERT INTO funding_inputs (kickoff_txid, input_txid, vout) VALUES (?, ?, ?)",
                deposit_txid,
                input_txid,
                input.vout
            )
            .execute(&mut *tx)
            .await
            .expect("should be able to insert funding input");
        }

        for utxo in kickoff_info.funding_utxos {
            let utxo_value = utxo.value.to_sat() as i64;
            let utxo_script_pubkey = consensus::encode::serialize_hex(&utxo.script_pubkey);

            sqlx::query!(
                "INSERT INTO funding_utxos (kickoff_txid, value, script_pubkey) VALUES (?, ?, ?)",
                deposit_txid,
                utxo_value,
                utxo_script_pubkey,
            )
            .execute(&mut *tx)
            .await
            .expect("should be able to insert funding utxo");
        }

        tx.commit()
            .await
            .expect("should be able to commit kickoff info");
    }

    async fn get_kickoff_info(&self, deposit_txid: Txid) -> Option<KickoffInfo> {
        // Convert Txid to string format
        let txid_str = consensus::encode::serialize_hex(&deposit_txid);

        // Query to retrieve KickoffInfo, funding inputs, and funding UTXOs in a single query
        let rows = sqlx::query!(
            r#"
        SELECT
            ki.txid AS "ki_txid!",
            ki.change_address AS "ki_change_address!",
            ki.change_address_network AS "ki_change_address_network!",
            ki.change_amount AS "ki_change_amount!",
            fi.input_txid AS "fi_input_txid?",
            fi.vout AS "fi_vout?",
            fu.value AS "fu_value?",
            fu.script_pubkey AS "fu_script_pubkey?"
        FROM kickoff_info ki
        LEFT JOIN funding_inputs fi ON fi.kickoff_txid = ki.txid
        LEFT JOIN funding_utxos fu ON fu.kickoff_txid = ki.txid
        WHERE ki.txid = ?
        "#,
            txid_str
        )
        .fetch_all(&self.pool)
        .await
        .expect("Failed to fetch kickoff_info with joins");

        if rows.is_empty() {
            return None;
        }

        // Initialize `KickoffInfo` fields from the first row
        let first_row = &rows[0];
        let change_network = Network::from_str(&first_row.ki_change_address_network)
            .expect("network should be valid");
        let change_address = BitcoinAddress::parse(&first_row.ki_change_address, change_network)
            .expect("address and network must be compatible");
        let change_amt = Amount::from_sat(first_row.ki_change_amount as u64);

        let mut funding_inputs = Vec::new();
        let mut funding_utxos = Vec::new();

        // Iterate through all rows to populate funding_inputs and funding_utxos
        for row in rows {
            // Process funding input
            if let (Some(input_txid), Some(vout)) = (&row.fi_input_txid, row.fi_vout) {
                funding_inputs.push(OutPoint {
                    txid: consensus::encode::deserialize_hex(input_txid)
                        .expect("should be able to deserialize input txid"),
                    vout: vout as u32,
                });
            }

            // Process funding UTXO
            if let (Some(value), Some(script_pubkey)) = (row.fu_value, &row.fu_script_pubkey) {
                let script_pubkey = consensus::encode::deserialize_hex(script_pubkey)
                    .expect("should be able to deserialize script pubkey in db");

                let value = Amount::from_sat(value as u64);

                funding_utxos.push(TxOut {
                    value,
                    script_pubkey,
                });
            }
        }

        Some(KickoffInfo {
            change_address,
            change_amt,
            funding_inputs,
            funding_utxos,
        })
    }
}

#[async_trait]
impl DutyTrackerDb for SqliteDb {
    async fn get_last_fetched_duty_index(&self) -> u64 {
        // Retrieve last fetched duty index from duty_index_tracker table
        let row =
            sqlx::query!("SELECT last_fetched_duty_index FROM duty_index_tracker WHERE id = 1")
                .fetch_optional(&self.pool)
                .await
                .expect("Failed to fetch last fetched duty index");

        row.map(|r| r.last_fetched_duty_index as u64).unwrap_or(0) // Default to 0 if no record
    }

    async fn set_last_fetched_duty_index(&self, duty_index: u64) {
        let duty_index = duty_index as i64;

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");

        sqlx::query!(
            "INSERT OR REPLACE INTO duty_index_tracker (id, last_fetched_duty_index) VALUES (1, ?)",
            duty_index
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to set the last fetched duty index");

        tx.commit()
            .await
            .expect("should be able to commit last fetch duty index");
    }

    async fn fetch_duty_status(&self, duty_id: Txid) -> Option<BridgeDutyStatus> {
        let duty_id = consensus::encode::serialize_hex(&duty_id);
        let row = sqlx::query!("SELECT status FROM duty_tracker WHERE duty_id = ?", duty_id)
            .fetch_optional(&self.pool)
            .await
            .expect("Failed to fetch duty status");

        row.map(|r| serde_json::from_str(&r.status).expect("Failed to parse duty status JSON"))
    }

    async fn update_duty_status(&self, duty_id: Txid, status: BridgeDutyStatus) {
        let duty_id = consensus::encode::serialize_hex(&duty_id);
        let status_json =
            serde_json::to_string(&status).expect("Failed to serialize duty status to JSON");

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");

        sqlx::query!(
            "INSERT OR REPLACE INTO duty_tracker (duty_id, status) VALUES (?, ?)",
            duty_id,
            status_json
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to update duty status");

        tx.commit()
            .await
            .expect("should be able to commit duty status");
    }
}

#[async_trait]
impl BitcoinBlockTrackerDb for SqliteDb {
    async fn get_last_scanned_block_height(&self) -> u64 {
        let row = sqlx::query!("SELECT block_height FROM bitcoin_block_index_tracker WHERE id = 1")
            .fetch_optional(&self.pool)
            .await
            .expect("Failed to fetch last scanned block height");

        row.map(|r| r.block_height as u64).unwrap_or(0) // Default to 0 if no record
    }

    async fn set_last_scanned_block_height(&self, block_height: u64) {
        let block_height = block_height as i64;

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");

        sqlx::query!(
            "INSERT OR REPLACE INTO bitcoin_block_index_tracker (id, block_height) VALUES (1, ?)",
            block_height
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to insert last scanned block height");

        tx.commit()
            .await
            .expect("should be able to commit last scanned block height");
    }

    async fn get_relevant_tx(&self, txid: &Txid) -> Option<Transaction> {
        let txid = consensus::encode::serialize_hex(txid);

        let row = sqlx::query!("SELECT tx FROM bitcoin_tx_index WHERE txid = ?", txid)
            .fetch_optional(&self.pool)
            .await
            .expect("should be able to fetch tx from db");

        row.map(|btc_tx| {
            consensus::encode::deserialize_hex(&btc_tx.tx)
                .expect("should be able to deserialize transaction")
        })
    }

    async fn add_relevant_tx(&self, tx: Transaction) {
        let txid = tx.compute_txid();
        let txid = consensus::encode::serialize_hex(&txid);
        let tx = consensus::encode::serialize_hex(&tx);

        let mut sqlx_tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");
        sqlx::query!(
            "INSERT OR REPLACE INTO bitcoin_tx_index (txid, tx) VALUES (?, ?)",
            txid,
            tx
        )
        .execute(&mut *sqlx_tx)
        .await
        .expect("should be able to insert relevant tx to db");

        sqlx_tx
            .commit()
            .await
            .expect("should be able to commit relevant tx to db");
    }
}
