use bitvm::{
    groth16::g16,
    signatures::wots::{wots160, wots256, wots32},
    treepp::*,
};

use crate::params::prelude::{
    NUM_CONNECTOR_A160, NUM_CONNECTOR_A256, NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A160_RESIDUAL,
    NUM_PKS_A256_PER_CONNECTOR, NUM_PKS_A256_RESIDUAL,
};

fn parse_wots160_signatures<const N_SIGS: usize>(script: Script) -> [wots160::Signature; N_SIGS] {
    let res = execute_script(script.clone());
    std::array::from_fn(|i| {
        std::array::from_fn(|j| {
            let k = 2 * j + i * 2 * wots160::N_DIGITS as usize;
            let preimage = res.final_stack.get(k);
            let digit = res.final_stack.get(k + 1);
            let digit = if digit.is_empty() { 0u8 } else { digit[0] };
            (preimage.try_into().unwrap(), digit)
        })
    })
}

fn parse_wots256_signatures<const N_SIGS: usize>(script: Script) -> [wots256::Signature; N_SIGS] {
    let res = execute_script(script.clone());
    std::array::from_fn(|i| {
        std::array::from_fn(|j| {
            let k = 2 * j + i * 2 * wots256::N_DIGITS as usize;
            let preimage = res.final_stack.get(k);
            let digit = res.final_stack.get(k + 1);
            let digit = if digit.is_empty() { 0u8 } else { digit[0] };
            (preimage.try_into().unwrap(), digit)
        })
    })
}

pub fn parse_claim_witness(script: Script) -> (wots32::Signature, wots256::Signature) {
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
            let k = 2 * wots32::N_DIGITS as usize + 2 * j;
            let preimage = res.final_stack.get(k);
            let digit = res.final_stack.get(k + 1);
            let digit = if digit.is_empty() { 0u8 } else { digit[0] };
            (preimage.try_into().unwrap(), digit)
        }),
    )
}

pub fn parse_assertion_witnesses(
    witness256: [Script; NUM_CONNECTOR_A256],
    witness256_residual: Option<Script>,
    witness160: [Script; NUM_CONNECTOR_A160],
    witness160_residual: Option<Script>,
) -> (wots256::Signature, g16::Signatures) {
    let mut w256 = witness256
        .map(parse_wots256_signatures::<NUM_PKS_A256_PER_CONNECTOR>)
        .as_flattened()
        .to_vec();
    if let Some(witness) = witness256_residual {
        w256.extend(parse_wots256_signatures::<NUM_PKS_A256_RESIDUAL>(witness));
    }

    let mut w160 = witness160
        .map(parse_wots160_signatures::<NUM_PKS_A160_PER_CONNECTOR>)
        .as_flattened()
        .to_vec();
    if let Some(witness) = witness160_residual {
        w160.extend(parse_wots160_signatures::<NUM_PKS_A160_RESIDUAL>(witness));
    }

    (
        w256[0], // superblock_hash
        (
            [w256[1]], // proof public input
            w256[2..].try_into().unwrap(),
            w160.try_into().unwrap(),
        ),
    )
}

#[cfg(test)]
mod tests {
    use bitvm::{
        signatures::wots::{wots160, wots256, wots32},
        treepp::*,
    };

    use super::*;

    fn create_message<const N_BYTES: usize>(i: usize) -> [u8; N_BYTES] {
        [i as u8; N_BYTES]
    }

    #[test]
    fn test_wots256_signatures_from_witness() {
        const N_SIGS: usize = 5;

        let secrets: [String; N_SIGS] = std::array::from_fn(|i| format!("{:04x}", i));

        let signatures: [_; N_SIGS] =
            std::array::from_fn(|i| wots256::get_signature(&secrets[i], &create_message::<32>(i)));

        let signatures_script = script! {
            for i in 0..N_SIGS {
                { wots256::sign(&secrets[i], &create_message::<32>(i)) }
            }
        };
        let parsed_signatures = parse_wots256_signatures::<N_SIGS>(signatures_script);

        assert_eq!(signatures, parsed_signatures);
    }

    #[test]
    fn test_wots160_signatures_from_witness() {
        const N_SIGS: usize = 11;

        let secrets: [String; N_SIGS] = std::array::from_fn(|i| format!("{:04x}", i));

        let signatures: [_; N_SIGS] =
            std::array::from_fn(|i| wots160::get_signature(&secrets[i], &create_message::<20>(i)));

        let signatures_script = script! {
            for i in 0..N_SIGS {
                { wots160::sign(&secrets[i], &create_message::<20>(i)) }
            }
        };
        let parsed_signatures = parse_wots160_signatures::<N_SIGS>(signatures_script);

        assert_eq!(signatures, parsed_signatures);
    }

    #[test]
    fn test_parse_claim_witness() {
        let msk = "00";

        let message: (_, [_; 32]) = (0x12345678u32, std::array::from_fn(|i| i as u8));

        let signatures = (
            wots32::get_signature(msk, &message.0.to_le_bytes()),
            wots256::get_signature(msk, &message.1),
        );

        let witness_script = script! {
            { wots32::sign(msk, &message.0.to_le_bytes()) }
            { wots256::sign(msk, &message.1) }
        };

        let witness_bytes = witness_script.compile().to_bytes();

        let parsed_signatures: Vec<([u8; 20], u8)> = witness_bytes
            .chunks_exact(1 + 20 + 1)
            .map(|chunk| {
                assert!(chunk[0] == 20);
                (
                    chunk[1..=20].try_into().unwrap(),
                    if chunk[21] == 0 { 0 } else { chunk[21] - 0x50 },
                )
            })
            .collect();

        let (w32, w256) = parsed_signatures.split_at(10);
        let parsed_signatures: (wots32::Signature, wots256::Signature) =
            (w32.try_into().unwrap(), w256.try_into().unwrap());

        assert_eq!(signatures, parsed_signatures);
    }
}
