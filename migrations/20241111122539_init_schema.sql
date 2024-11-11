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
