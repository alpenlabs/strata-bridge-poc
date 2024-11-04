use bitvm::{
    groth16::g16,
    signatures::wots::{wots160, wots256},
    treepp::*,
};

use crate::connectors::constants::{
    NUM_CONNECTOR_A256, NUM_PKS_A256_PER_CONNECTOR, NUM_PKS_A256_RESIDUAL,
};

pub struct AssertDataWitnesses {
    c7s256: [Script; 5],
    c6s256: [Script; 1],
    c11s160: [Script; 5 * 10],
    c2s160: [Script; 1],
}

fn get_wots256_signatures_from_witness<const N_SIG_DIGITS: usize, const N_SIGS: usize>(
    script: Script,
) -> [wots256::Signature; N_SIGS] {
    let res = execute_script(script.clone());

    let stack = (0..res.final_stack.len())
        .rev()
        .map(|i| res.final_stack.get(i))
        .collect::<Vec<_>>();

    std::array::from_fn(|i| {
        std::array::from_fn(|j| {
            let k = 2 * j + i * 2 * N_SIG_DIGITS as usize;
            (stack[k].clone().try_into().unwrap(), stack[k + 1][0])
        })
    })
}

fn get_wots_signatures_from_witnesses(
    claim_witness: Script,
    assert_witnesses: AssertDataWitnesses,
) -> g16::WotsSignatures {
    // let mut sig256s = assert_witnesses
    //     .c7s256
    //     .map(|script| {
    //         get_wots256_signatures_from_witness::<7, { wots256::N_DIGITS as usize
    // }>(script.clone())     })
    //     .iter()
    //     .flatten()
    //     .collect::<Vec<_>>();

    // sig256s.extend(
    //     assert_witnesses
    //         .c6s256
    //         .map(|script| {
    //             get_wots256_signatures_from_witness::<6, { wots256::N_DIGITS as usize }>(
    //                 script.clone(),
    //             )
    //         })
    //         .iter()
    //         .flatten()
    //         .collect::<Vec<_>>(),
    // );

    // let c11s160 = assert_witnesses
    //     .c11s160
    //     .map(|script| {
    //         get_wots256_signatures_from_witness::<11, { wots160::N_DIGITS as usize }>(
    //             script.clone(),
    //         )
    //     })
    //     .iter()
    //     .flatten()
    //     .collect::<Vec<_>>();

    // let c2s160 = assert_witnesses
    //     .c2s160
    //     .map(|script| {
    //         get_wots256_signatures_from_witness::<2, { wots160::N_DIGITS as usize
    // }>(script.clone())     })
    //     .iter()
    //     .flatten()
    //     .collect::<Vec<_>>();

    // sig256s.extend(iter);

    // let public_input_3 = sig256s.remove(0)

    (
        [[([0u8; 20], 0u8); { wots256::N_DIGITS as usize }]; 3].into(),
        [[([0u8; 20], 0u8); { wots256::N_DIGITS as usize }]; 40],
        [[([0u8; 20], 0u8); { wots160::N_DIGITS as usize }]; 574],
    )
}

#[cfg(test)]
mod tests {
    // #[test]
    // fn test_
}
