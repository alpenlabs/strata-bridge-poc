/// Defines helpers for some common functionalities that don't fit anywhere neatly.
use bitcoin::Network;

pub fn num_blocks_per_network(network: Network, mainnet_num_blocks: u32) -> u32 {
    if network == Network::Bitcoin {
        mainnet_num_blocks
    } else {
        1
    }
}
