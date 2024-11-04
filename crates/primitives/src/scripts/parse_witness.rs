use bitvm::{
    groth16::g16,
    signatures::wots::{wots160, wots256},
    treepp::*,
};

fn parse_wots160_signatures<const N_SIGS: usize>(script: Script) -> [wots160::Signature; N_SIGS] {
    let res = execute_script(script.clone());

    let stack = (0..res.final_stack.len())
        .rev()
        .map(|i| res.final_stack.get(i))
        .collect::<Vec<_>>();

    println!("stack: {:?}", stack);

    std::array::from_fn(|i| {
        std::array::from_fn(|j| {
            let k = 2 * j + i * 2 * wots160::N_DIGITS as usize;
            (stack[k].clone().try_into().unwrap(), stack[k + 1][0])
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

#[cfg(test)]
mod tests {
    use bitvm::{signatures::wots::wots256, treepp::*};

    use crate::scripts::parse_witness::parse_wots256_signatures;

    #[test]
    fn test_wots256_signatures_from_witness() {
        const N_SIGS: usize = 5;

        let secrets: [String; N_SIGS] = std::array::from_fn(|i| format!("{:04x}", i));

        let signatures: [_; N_SIGS] =
            std::array::from_fn(|i| wots256::get_signature(&secrets[i], &[i as u8; 32]));

        let signatures_script = script! {
            for i in 0..N_SIGS {
                { wots256::sign(&secrets[i], &[i as u8; 32]) }
            }
        };
        let parsed_signatures = parse_wots256_signatures::<N_SIGS>(signatures_script);

        assert_eq!(signatures, parsed_signatures);
    }
}
