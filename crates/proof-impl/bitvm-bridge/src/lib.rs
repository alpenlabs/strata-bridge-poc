mod primitives;
mod process;
mod treepp;

pub use primitives::{BridgeProofInput, BridgeProofPublicParams};
pub use process::process_bridge_proof;

#[cfg(test)]
mod test {
    use crate::treepp;

    #[test]
    fn test_once() {
        // let a = treepp::ExecuteInfo;
    }
}
