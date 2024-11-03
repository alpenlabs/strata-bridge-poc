use bitvm::signatures::wots::{wots160, wots256};

use crate::common::db::BridgeDb;

pub struct Verifier {
    db: BridgeDb,
}

impl Verifier {
    pub fn new(db: BridgeDb) -> Self {
        Self { db }
    }

    pub fn run() {}
}
