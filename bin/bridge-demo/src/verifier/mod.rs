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
