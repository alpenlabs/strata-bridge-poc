use std::fs;

use bitcoin::ScriptBuf;
use bitcoin_script::{script, Script};
use bitvm::groth16::g16::{self, N_TAPLEAVES};
use lazy_static::lazy_static;
use tracing::info;

use crate::scripts::wots::bridge_poc_verification_key;

const VK_SCRIPTS_FILE: &str = "strata-bridge-poc-vk.scripts";

lazy_static! {
    pub static ref PARTIAL_VERIFIER_SCRIPTS: [Script; 579] = load_or_create_verifier_scripts();
}

pub fn load_or_create_verifier_scripts() -> [Script; 579] {
    let verifier_scripts: [Script; N_TAPLEAVES] = if fs::exists(VK_SCRIPTS_FILE)
        .expect("should be able to check for existence of verifier scripts file")
    {
        info!(
            action = "loading verifier script from file cache...this will take some time",
            estimated_time = "3 mins"
        );

        let contents: Vec<u8> =
            fs::read(VK_SCRIPTS_FILE).expect("should be able to read verifier scripts from file");
        let deserialized: Vec<Vec<u8>> = bincode::deserialize(&contents)
            .expect("should be able to deserialize verifier scripts from file");

        let verifier_scripts = deserialized
            .iter()
            .map(|de| script!().push_script(ScriptBuf::from_bytes(de.to_vec())))
            .collect::<Vec<Script>>();

        let num_scripts = verifier_scripts.len();
        info!(event = "loaded verifier scripts", %num_scripts);

        verifier_scripts.try_into().unwrap_or_else(|_| {
            panic!("number of scripts should be: {N_TAPLEAVES} not {num_scripts}",)
        })
    } else {
        info!(
            action = "compiling verifier scripts, this will take time...",
            estimated_time = "3 mins"
        );

        let verifier_scripts = g16::compile_verifier(bridge_poc_verification_key());

        let serialized: Vec<Vec<u8>> = verifier_scripts
            .clone()
            .into_iter()
            .map(|s| s.compile().to_bytes())
            .collect();

        let serialized: Vec<u8> =
            bincode::serialize(&serialized).expect("should be able to serialize verifier scripts");

        info!(action = "caching verifier scripts for later", cache_file=%VK_SCRIPTS_FILE);
        fs::write(VK_SCRIPTS_FILE, serialized)
            .expect("should be able to write verifier scripts to file");

        verifier_scripts
    };

    verifier_scripts
}

pub fn get_verifier_scripts() -> &'static [Script; 579] {
    &PARTIAL_VERIFIER_SCRIPTS
}
