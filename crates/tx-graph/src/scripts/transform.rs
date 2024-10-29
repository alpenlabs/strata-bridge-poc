use bitcoin_script::{script, Script};
use bitvm::pseudo::NMUL;

pub fn ts_from_nibbles() -> Script {
    script! {
        for _ in 1..8 { OP_TOALTSTACK }
        for _ in 1..8 {
            { NMUL(1 << 4) } OP_FROMALTSTACK OP_ADD
        }
    }
}
