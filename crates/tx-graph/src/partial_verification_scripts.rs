use std::fs;

use bitcoin::ScriptBuf;
use bitvm::{groth16::g16, treepp::*};
use lazy_static::lazy_static;
use strata_bridge_proof_snark::bridge_poc;
use tracing::{info, warn};

const PARTIAL_VERIFIER_SCRIPTS_PATH: &str = "strata-bridge-poc-vk.scripts";

lazy_static! {
    pub static ref PARTIAL_VERIFIER_SCRIPTS: [Script; 579] = load_or_create_verifier_scripts();
}

pub fn load_or_create_verifier_scripts() -> [Script; 579] {
    let verifier_scripts: [Script; g16::N_TAPLEAVES] = if fs::exists(PARTIAL_VERIFIER_SCRIPTS_PATH)
        .expect("should be able to check for existence of verifier scripts file")
    {
        warn!(
            action = "loading verifier script from file cache...this will take some time",
            estimated_time = "1 min"
        );

        let contents: Vec<u8> = fs::read(PARTIAL_VERIFIER_SCRIPTS_PATH)
            .expect("should be able to read verifier scripts from file");
        let deserialized: Vec<Vec<u8>> = bincode::deserialize(&contents)
            .expect("should be able to deserialize verifier scripts from file");

        let verifier_scripts = deserialized
            .iter()
            .map(|de| script!().push_script(ScriptBuf::from_bytes(de.to_vec())))
            .collect::<Vec<Script>>();

        let num_scripts = verifier_scripts.len();
        info!(event = "loaded verifier scripts", %num_scripts);

        verifier_scripts.try_into().unwrap_or_else(|_| {
            panic!(
                "number of scripts should be: {} not {num_scripts}",
                g16::N_TAPLEAVES
            )
        })
    } else {
        warn!(
            action = "compiling verifier scripts, this will take time...",
            estimated_time = "3 mins"
        );

        let verifier_scripts = g16::compile_verifier(bridge_poc::GROTH16_VERIFICATION_KEY.clone());

        let serialized: Vec<Vec<u8>> = verifier_scripts
            .clone()
            .into_iter()
            .map(|s| s.compile().to_bytes())
            .collect();

        let serialized: Vec<u8> =
            bincode::serialize(&serialized).expect("should be able to serialize verifier scripts");

        warn!(action = "caching verifier scripts for later", cache_file=%PARTIAL_VERIFIER_SCRIPTS_PATH);
        fs::write(PARTIAL_VERIFIER_SCRIPTS_PATH, serialized)
            .expect("should be able to write verifier scripts to file");

        verifier_scripts
    };

    verifier_scripts
}

pub fn get_verifier_scripts() -> &'static [Script; 579] {
    &PARTIAL_VERIFIER_SCRIPTS
}
