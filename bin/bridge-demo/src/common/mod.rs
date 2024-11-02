pub mod db;

use bitvm::{
    groth16::g16::{self, N_TAPLEAVES},
    treepp::*,
};

// pub const BRIDGE_POC_VERIFICATION_KEY: g16::VerificationKey = g16::VerificationKey {};

pub fn compile_verifier_scripts() -> [Script; N_TAPLEAVES] {
    // g16::Verifier::compile(BRIDGE_POC_VERIFICATION_KEY)
    todo!()
}
