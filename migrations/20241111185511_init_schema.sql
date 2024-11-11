-- Table for musig_pubkey_table
CREATE TABLE IF NOT EXISTS musig_pubkey_table (
    operator_id INTEGER PRIMARY KEY,
    public_key TEXT NOT NULL  -- Store as hex string
);

-- Table for wots_public_keys with a compound index on (operator_id, deposit_txid)
CREATE TABLE IF NOT EXISTS wots_public_keys (
    operator_id INTEGER NOT NULL,
    deposit_txid TEXT NOT NULL,  -- Store as hex string
    public_keys BLOB NOT NULL,   -- Serialized with bincode
    PRIMARY KEY (operator_id, deposit_txid)  -- Compound primary key
);

-- Table for wots_signatures with a compound index on (operator_id, deposit_txid)
CREATE TABLE IF NOT EXISTS wots_signatures (
    operator_id INTEGER NOT NULL,
    deposit_txid TEXT NOT NULL,  -- Store as hex string
    signatures BLOB NOT NULL,    -- Serialized with bincode
    PRIMARY KEY (operator_id, deposit_txid)  -- Compound primary key
);

-- Table for signatures with a compound index on (operator_id, txid, input_index)
CREATE TABLE IF NOT EXISTS signatures (
    operator_id INTEGER NOT NULL,
    txid TEXT NOT NULL,          -- Store as hex string
    input_index INTEGER NOT NULL,
    signature TEXT NOT NULL,     -- Store as hex string
    PRIMARY KEY (operator_id, txid, input_index)  -- Compound primary key
);

-- Table for claim_txid_to_operator_index_and_deposit_txid
CREATE TABLE IF NOT EXISTS claim_txid_to_operator_index_and_deposit_txid (
    claim_txid TEXT PRIMARY KEY,           -- Store as hex string
    operator_id INTEGER NOT NULL,
    deposit_txid TEXT NOT NULL             -- Store as hex string
);

-- Table for post_assert_txid_to_operator_index_and_deposit_txid
CREATE TABLE IF NOT EXISTS post_assert_txid_to_operator_index_and_deposit_txid (
    post_assert_txid TEXT PRIMARY KEY,     -- Store as hex string
    operator_id INTEGER NOT NULL,
    deposit_txid TEXT NOT NULL             -- Store as hex string
);

-- Table for assert_data_txid_to_operator_and_deposit with a primary key on assert_data_txid
CREATE TABLE IF NOT EXISTS assert_data_txid_to_operator_and_deposit (
    assert_data_txid TEXT PRIMARY KEY,     -- Store as hex string
    operator_id INTEGER NOT NULL,
    deposit_txid TEXT NOT NULL             -- Store as hex string
);

-- Table for pre_assert_txid_to_operator_and_deposit with a primary key on pre_assert_data_txid
CREATE TABLE IF NOT EXISTS pre_assert_txid_to_operator_and_deposit (
    pre_assert_data_txid TEXT PRIMARY KEY, -- Store as hex string
    operator_id INTEGER NOT NULL,
    deposit_txid TEXT NOT NULL             -- Store as hex string

);
-- Table to store collected public nonces for each operator
CREATE TABLE collected_pubnonces (
    txid TEXT NOT NULL,
    input_index INTEGER NOT NULL,
    operator_id INTEGER NOT NULL,
    pubnonce TEXT NOT NULL,
    PRIMARY KEY (txid, input_index, operator_id)
);

-- Table to store secp256k1::SecNonce data
CREATE TABLE sec_nonces (
    txid TEXT NOT NULL,
    input_index INTEGER NOT NULL,
    sec_nonce BLOB NOT NULL,
    PRIMARY KEY (txid, input_index)
);

-- Table to store collected signatures (message hash and operator ID to partial signature)
CREATE TABLE collected_signatures (
    txid TEXT NOT NULL,
    input_index INTEGER NOT NULL,
    msg_hash BLOB NOT NULL,
    operator_id INTEGER NOT NULL,
    partial_signature TEXT NOT NULL, -- Signature is stored as hex string
    PRIMARY KEY (txid, input_index, operator_id)
);

-- Table to store selected outpoints that have been used for KickoffTx
CREATE TABLE selected_outpoints (
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL,
    PRIMARY KEY (txid, vout)
);

-- Table to store main KickoffInfo details for each Deposit Txid
CREATE TABLE kickoff_info (
    txid TEXT PRIMARY KEY,                -- Unique [deposit] identifier for KickoffInfo
    change_address TEXT NOT NULL,         -- Change address as a string
    change_address_network TEXT NOT NULL, -- Network associated with the address (e.g., "bitcoin", "testnet")
    change_amount INTEGER NOT NULL        -- Change amount in smallest denomination (i.e., satoshis)
);

-- Table to store funding inputs for each KickoffInfo
CREATE TABLE funding_inputs (
    kickoff_txid TEXT NOT NULL,           -- Foreign key to kickoff_info.txid
    input_txid TEXT NOT NULL,             -- Txid of the funding input
    vout INTEGER NOT NULL,                -- Output index in the funding input
    FOREIGN KEY (kickoff_txid) REFERENCES kickoff_info(txid) ON DELETE CASCADE,
    PRIMARY KEY (kickoff_txid, input_txid, vout)
);

-- Table to store funding UTXOs for each KickoffInfo, storing TxOut fields directly
CREATE TABLE funding_utxos (
    kickoff_txid TEXT NOT NULL,           -- Foreign key to kickoff_info.txid
    value INTEGER NOT NULL,               -- Value of the TxOut in smallest denomination (e.g., satoshis)
    script_pubkey TEXT NOT NULL,          -- Serialized ScriptPubKey in hex format
    FOREIGN KEY (kickoff_txid) REFERENCES kickoff_info(txid) ON DELETE CASCADE
);