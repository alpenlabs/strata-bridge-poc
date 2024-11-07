use bitcoin::block::Header;
use strata_primitives::buf::Buf32;
use strata_state::l1::{BtcParams, HeaderVerificationState};

pub fn verify_l1_chain(
    initial_header_state: &HeaderVerificationState,
    headers: &[Header],
    params: &BtcParams,
    ts_block_hash: Buf32,
    header_inclusions: Vec<Buf32>,
) -> Buf32 {
    let mut state = initial_header_state.clone();
    let mut inclusions = header_inclusions.clone();

    // let mut super_block = None;
    let mut ts_block_found = false;
    let mut super_block = Buf32([u8::MAX; 32].into());

    for header in headers {
        state = state.check_and_update_continuity_new(header, params);

        // Assert the inclusion of the `header_inclusions` lists
        if !inclusions.is_empty()
            && inclusions.first().unwrap().as_ref() == state.last_verified_block_hash.as_ref()
        {
            inclusions.remove(0);
        }

        // Enable super block search after ts block is observed
        if !ts_block_found && state.last_verified_block_hash.as_ref() == ts_block_hash.as_ref() {
            ts_block_found = true;
        }

        // Search for the super block
        if ts_block_found && super_block.as_ref() > state.last_verified_block_hash.as_ref() {
            super_block = Buf32(state.last_verified_block_hash.as_ref().into());

            // TODO: After super block is found assert `N=2016` blocks are there
        }
    }

    assert!(inclusions.is_empty());
    assert!(ts_block_found);

    super_block
}

#[cfg(test)]
mod test {
    use prover_test_utils::{get_bitcoin_client, get_header_verification_data};
    use strata_btcio::rpc::traits::Reader;
    use strata_state::l1::{compute_block_hash, get_btc_params};

    use crate::bitcoin::header_chain::verify_l1_chain;

    #[tokio::test]
    async fn test_bitcoin_headers() {
        let geneis_block = 0;
        let start_block = 501;
        let end_block = 508;
        let btc_client = get_bitcoin_client();

        let (block_hvs, headers) =
            get_header_verification_data(start_block, end_block, geneis_block).await;

        let params = get_btc_params();

        let headers_inclusions = vec![
            compute_block_hash(
                &btc_client
                    .get_block_at(start_block + 1)
                    .await
                    .unwrap()
                    .header,
            ),
            compute_block_hash(
                &btc_client
                    .get_block_at(start_block + 3)
                    .await
                    .unwrap()
                    .header,
            ),
            compute_block_hash(
                &btc_client
                    .get_block_at(start_block + 6)
                    .await
                    .unwrap()
                    .header,
            ),
        ];

        let ts_block_hash = compute_block_hash(
            &btc_client
                .get_block_at(start_block + 2)
                .await
                .unwrap()
                .header,
        );

        let super_block_hash = verify_l1_chain(
            &block_hvs,
            &headers,
            &params,
            ts_block_hash,
            headers_inclusions,
        );
        println!("got the super_block_hash {:?} ", super_block_hash)
    }
}
