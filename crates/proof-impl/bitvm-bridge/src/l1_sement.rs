#![allow(unused)]
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
    use strata_btcio::rpc::{traits::Reader, BitcoinClient};

    #[tokio::test]
    async fn test_bitcoin() {
        let btc_client = BitcoinClient::new(
            "http://127.0.0.1:12423".to_string(),
            "alpen".to_string(),
            "alpen".to_string(),
        )
        .expect("failed to connect to the btc client");

        let block = btc_client.get_block_at(403).await.unwrap();
        println!("got the block {:?}", block)
    }
}
