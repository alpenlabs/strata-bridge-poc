use bitcoin::block::Header;
use strata_state::l1::{BtcParams, HeaderVerificationState};

pub fn verify_l1_chain(
    initial_header_state: &HeaderVerificationState,
    headers: &[Header],
    params: &BtcParams,
) -> HeaderVerificationState {
    let mut state = initial_header_state.clone();

    for header in headers {
        state = state.check_and_update_continuity_new(header, params);
    }

    state
}

#[cfg(test)]
mod test {
    use prover_test_utils::get_header_verification_data;
    use strata_state::l1::get_btc_params;

    use crate::bitcoin::header_chain::verify_l1_chain;

    #[tokio::test]
    async fn test_bitcoin_headers() {
        let geneis_block = 0;
        let start_block = 501;
        let end_block = 510;

        let (block_hvs, headers) =
            get_header_verification_data(start_block, end_block, geneis_block).await;

        let params = get_btc_params();
        let res = verify_l1_chain(&block_hvs, &headers, &params);
        println!("got the res {:?} ", res.compute_final_snapshot())
    }
}
