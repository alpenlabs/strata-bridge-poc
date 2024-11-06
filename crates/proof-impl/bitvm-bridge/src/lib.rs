mod primitives;
mod process;
mod treepp;

use bitcoin_script::Script;
pub use primitives::{BridgeProofInput, BridgeProofPublicParams};
pub use process::process_bridge_proof;
use treepp::execute_script;

#[cfg(test)]
mod test {
    use crate::treepp;

    #[test]
    fn test_once() {
        // let a = treepp::ExecuteInfo;
    }
}

pub fn parse_claim_witness(script: Script) -> ([([u8; 20], u8); 10], [([u8; 20], u8); 67]) {
    let res = execute_script(script);
    (
        std::array::from_fn(|j| {
            let k = 2 * j;
            let preimage = res.final_stack.get(k);
            let digit = res.final_stack.get(k + 1);
            let digit = if digit.is_empty() { 0u8 } else { digit[0] };
            (preimage.try_into().unwrap(), digit)
        }),
        std::array::from_fn(|j| {
            let k = 2 * 10 as usize + 2 * j;
            let preimage = res.final_stack.get(k);
            let digit = res.final_stack.get(k + 1);
            let digit = if digit.is_empty() { 0u8 } else { digit[0] };
            (preimage.try_into().unwrap(), digit)
        }),
    )
}
